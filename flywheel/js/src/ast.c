/* flywheel/src/ast.c
 * Arena + node constructors + printer.
 *
 * Philosophy: this file never crashes.
 *  - all allocations go through ast_alloc, which returns NULL on OOM
 *  - callers check for NULL
 *  - ast_print tolerates NULL by printing "(null)"
 *  - ast_free_arena() releases everything at once
 */

#include "../include/ast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================ */
/* Arena                                                         */
/* ============================================================ */
typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t used;
    size_t cap;
    char   data[];
} ArenaBlock;

static ArenaBlock *g_head = NULL;
static int g_cache_owns_head = 0;   /* 1 when the current head belongs to the cache */

/* Adaptive arena block sizing. Small scripts use tiny memory, large
 * scripts grow. Never hardcoded to one size.
 *   - Start at 1 KB — a "1 + 2" parse uses one 1 KB block.
 *   - Double each time we need a new block, up to 64 KB.
 *   - Individual objects larger than the current target get their own block.
 * Peak RSS for typical scripts stays under 32 KB. */
#define AST_BLOCK_MIN (1u * 1024)
#define AST_BLOCK_MAX (64u * 1024)
static size_t g_next_block_size = AST_BLOCK_MIN;

void *ast_alloc(size_t size) {
    if (size == 0) size = 1;
    size = (size + 15u) & ~((size_t)15u);

    if (!g_head || g_head->used + size > g_head->cap) {
        size_t cap = size > g_next_block_size ? size : g_next_block_size;
        ArenaBlock *b = (ArenaBlock*)malloc(sizeof(ArenaBlock) + cap);
        if (!b) return NULL;               /* caller checks NULL */
        b->next = g_head;
        b->used = 0;
        b->cap  = cap;
        g_head  = b;
        /* double for next time, capped at max */
        if (g_next_block_size < AST_BLOCK_MAX) {
            g_next_block_size *= 2;
            if (g_next_block_size > AST_BLOCK_MAX) g_next_block_size = AST_BLOCK_MAX;
        }
    }
    void *p = g_head->data + g_head->used;
    g_head->used += size;
    memset(p, 0, size);
    return p;
}

void ast_free_arena(void) {
    if (g_cache_owns_head) {
        /* Current arena belongs to the parse cache. Freeing it would
         * corrupt the cache. Callers of cached parses must NOT free.
         * Use parser_cache_clear() to release cache-owned arenas. */
        return;
    }
    ArenaBlock *b = g_head;
    while (b) {
        ArenaBlock *n = b->next;
        free(b);
        b = n;
    }
    g_head = NULL;
    g_next_block_size = AST_BLOCK_MIN;
}

/* Cache integration — see src/cache.c */
void ast_mark_cache_owned(int flag) { g_cache_owns_head = flag ? 1 : 0; }
int  ast_is_cache_owned(void)       { return g_cache_owns_head; }

void ast_free(Node *n) { (void)n; }    /* arena releases everything */

Node *ast_new_sized(NodeKind k, size_t size,
                     int line, int col, int end_line, int end_col) {
    if (size < sizeof(Node)) size = sizeof(Node);
    Node *n = (Node*)ast_alloc(size);
    if (!n) return NULL;
    /* SPEED: ast_alloc already zeroed this block. We only need to write
     * the base fields. Hot path — kept branchless and inline-friendly. */
    n->kind = k;
    n->line = line;
    n->column = col;
    n->end_line = end_line;
    n->end_column = end_col;
    return n;
}

Node *ast_new(NodeKind k, int line, int col, int end_line, int end_col) {
    return ast_new_sized(k, sizeof(Node), line, col, end_line, end_col);
}

/* ============================================================ */
/* Kind names                                                    */
/* ============================================================ */
const char *ast_kind_name(NodeKind k) {
    static const char *names[NODE_MAX] = {
        /* top */
        "PROGRAM","EMPTY_STMT","BLOCK","EXPR_STMT",
        /* decls */
        "VAR_DECL","VAR_DECLARATOR","FUNC_DECL","FUNC_EXPR","ARROW_FUNC",
        "CLASS_DECL","CLASS_EXPR","CLASS_BODY","METHOD_DEF","PROP_DEF","STATIC_BLOCK",
        /* statements */
        "IF","FOR","FOR_IN","FOR_OF","WHILE","DO_WHILE",
        "SWITCH","SWITCH_CASE","RETURN","BREAK","CONTINUE",
        "THROW","TRY","CATCH","FINALLY",
        "LABELED","WITH","DEBUGGER",
        /* expressions */
        "IDENT","LITERAL","TEMPLATE","TEMPLATE_ELEMENT","TAGGED_TEMPLATE",
        "ARRAY","OBJECT","PROPERTY","MEMBER","CALL","NEW",
        "UNARY","UPDATE","BINARY","LOGICAL","ASSIGN","CONDITIONAL","SEQUENCE",
        "YIELD","AWAIT","SPREAD","NEW_TARGET","IMPORT_META","SUPER","THIS","PAREN",
        /* patterns */
        "ARRAY_PATTERN","OBJECT_PATTERN","ASSIGN_PATTERN","REST_ELEMENT",
        /* functions */
        "PARAM","PARAM_LIST",
        /* modules */
        "IMPORT_DECL","IMPORT_SPEC","EXPORT_DECL","EXPORT_SPEC","EXPORT_DEFAULT",
        "IMPORT_CALL"
    };
    if ((int)k < 0 || k >= NODE_MAX) return "?";
    return names[k];
}

/* ============================================================ */
/* Printer — S-expr. Never crashes; prints "(null)" for NULL.    */
/* ============================================================ */
static void ind(int n) { for (int i = 0; i < n; i++) fputs("  ", stdout); }

static const char *binop_name(BinaryOp op) {
    switch (op) {
        case BINOP_ADD: return "+";
        case BINOP_SUB: return "-";
        case BINOP_MUL: return "*";
        case BINOP_DIV: return "/";
        case BINOP_MOD: return "%";
        case BINOP_POW: return "**";
        case BINOP_LT: return "<";
        case BINOP_GT: return ">";
        case BINOP_LE: return "<=";
        case BINOP_GE: return ">=";
        case BINOP_EQ: return "==";
        case BINOP_NEQ: return "!=";
        case BINOP_SEQ: return "===";
        case BINOP_SNEQ: return "!==";
        case BINOP_BITAND: return "&";
        case BINOP_BITOR: return "|";
        case BINOP_BITXOR: return "^";
        case BINOP_LSHIFT: return "<<";
        case BINOP_RSHIFT: return ">>";
        case BINOP_URSHIFT: return ">>>";
        case BINOP_IN: return "in";
        case BINOP_INSTANCEOF: return "instanceof";
    }
    return "?";
}

static const char *unop_name(UnaryOp op) {
    switch (op) {
        case UNOP_PLUS: return "+";
        case UNOP_MINUS: return "-";
        case UNOP_NOT: return "!";
        case UNOP_BITNOT: return "~";
        case UNOP_TYPEOF: return "typeof";
        case UNOP_VOID: return "void";
        case UNOP_DELETE: return "delete";
    }
    return "?";
}

static const char *assignop_name(AssignOp op) {
    switch (op) {
        case ASSIGN_EQ: return "=";
        case ASSIGN_ADD: return "+=";
        case ASSIGN_SUB: return "-=";
        case ASSIGN_MUL: return "*=";
        case ASSIGN_DIV: return "/=";
        case ASSIGN_MOD: return "%=";
        case ASSIGN_POW: return "**=";
        case ASSIGN_BITAND: return "&=";
        case ASSIGN_BITOR: return "|=";
        case ASSIGN_BITXOR: return "^=";
        case ASSIGN_LSHIFT: return "<<=";
        case ASSIGN_RSHIFT: return ">>=";
        case ASSIGN_URSHIFT: return ">>>=";
        case ASSIGN_AND: return "&&=";
        case ASSIGN_OR: return "||=";
        case ASSIGN_NULLISH: return "?\?=";
    }
    return "?=";
}

void ast_print(Node *n, int indent) {
    if (!n) { ind(indent); fputs("(null)\n", stdout); return; }
    ind(indent);
    printf("(%s", ast_kind_name(n->kind));

    switch (n->kind) {
    case NODE_PROGRAM:
    case NODE_BLOCK: {
        Block *s = (Block*)n;
        printf(" n=%d", s->n);
        for (int i = 0; i < s->n; i++) { putchar('\n'); ast_print(s->stmts[i], indent+1); }
        break;
    }
    case NODE_EXPR_STMT:
        putchar('\n');
        ast_print(((ExprStmt*)n)->expr, indent+1);
        break;

    case NODE_IDENT: {
        Ident *i = (Ident*)n;
        printf(" %s", i->name ? i->name : "?");
        break;
    }
    case NODE_LITERAL: {
        Literal *l = (Literal*)n;
        switch (l->lit_kind) {
        case LIT_NUMBER:    printf(" num=%g", l->number); break;
        case LIT_STRING:    printf(" str=%s", l->string ? l->string : ""); break;
        case LIT_BOOL:      printf(" bool=%s", l->boolean ? "true" : "false"); break;
        case LIT_NULL:      fputs(" null", stdout); break;
        case LIT_UNDEFINED: fputs(" undefined", stdout); break;
        case LIT_REGEX:     printf(" /%s/%s",
                                    l->regex_pattern ? l->regex_pattern : "",
                                    l->regex_flags   ? l->regex_flags   : ""); break;
        case LIT_BIGINT:    printf(" %sn", l->bigint_text ? l->bigint_text : ""); break;
        }
        break;
    }
    case NODE_THIS:  fputs(" this", stdout); break;
    case NODE_SUPER: fputs(" super", stdout); break;

    case NODE_BINARY: {
        BinaryExpr *b = (BinaryExpr*)n;
        printf(" %s\n", binop_name(b->op));
        ast_print(b->left, indent+1); putchar('\n');
        ast_print(b->right, indent+1);
        break;
    }
    case NODE_LOGICAL: {
        LogicalExpr *l = (LogicalExpr*)n;
        printf(" %s\n", l->op==LOGOP_AND ? "&&" : l->op==LOGOP_OR ? "||" : "??");
        ast_print(l->left, indent+1); putchar('\n');
        ast_print(l->right, indent+1);
        break;
    }
    case NODE_UNARY: {
        UnaryExpr *u = (UnaryExpr*)n;
        printf(" %s\n", unop_name(u->op));
        ast_print(u->arg, indent+1);
        break;
    }
    case NODE_UPDATE: {
        UpdateExpr *u = (UpdateExpr*)n;
        printf(" %s %s\n", u->prefix ? "prefix" : "postfix",
                           u->op == UPDOP_INC ? "++" : "--");
        ast_print(u->arg, indent+1);
        break;
    }
    case NODE_ASSIGN: {
        AssignExpr *a = (AssignExpr*)n;
        printf(" %s\n", assignop_name(a->op));
        ast_print(a->target, indent+1); putchar('\n');
        ast_print(a->value, indent+1);
        break;
    }
    case NODE_CONDITIONAL: {
        ConditionalExpr *c = (ConditionalExpr*)n;
        putchar('\n');
        ast_print(c->test, indent+1); putchar('\n');
        ast_print(c->cons, indent+1); putchar('\n');
        ast_print(c->alt,  indent+1);
        break;
    }
    case NODE_SEQUENCE: {
        SequenceExpr *s = (SequenceExpr*)n;
        printf(" n=%d", s->n);
        for (int i = 0; i < s->n; i++) { putchar('\n'); ast_print(s->exprs[i], indent+1); }
        break;
    }
    case NODE_MEMBER: {
        MemberExpr *m = (MemberExpr*)n;
        printf(" %s%s\n", m->computed ? "[]" : ".",
                          m->optional ? " optional" : "");
        ast_print(m->object, indent+1); putchar('\n');
        ast_print(m->property, indent+1);
        break;
    }
    case NODE_CALL: {
        CallExpr *c = (CallExpr*)n;
        printf(" argc=%d%s\n", c->n, c->optional ? " optional" : "");
        ast_print(c->callee, indent+1);
        for (int i = 0; i < c->n; i++) { putchar('\n'); ast_print(c->args[i], indent+1); }
        break;
    }
    case NODE_NEW: {
        NewExpr *c = (NewExpr*)n;
        printf(" argc=%d\n", c->n);
        ast_print(c->callee, indent+1);
        for (int i = 0; i < c->n; i++) { putchar('\n'); ast_print(c->args[i], indent+1); }
        break;
    }
    case NODE_ARRAY: {
        ArrayExpr *a = (ArrayExpr*)n;
        printf(" n=%d", a->n);
        for (int i = 0; i < a->n; i++) { putchar('\n'); ast_print(a->elems[i], indent+1); }
        break;
    }
    case NODE_OBJECT: {
        ObjectExpr *o = (ObjectExpr*)n;
        printf(" n=%d", o->n);
        for (int i = 0; i < o->n; i++) { putchar('\n'); ast_print(o->props[i], indent+1); }
        break;
    }
    case NODE_PROPERTY: {
        Property *p = (Property*)n;
        printf("%s%s\n", p->computed ? " computed" : "",
                          p->shorthand ? " shorthand" : "");
        ast_print(p->key, indent+1);
        if (p->value) { putchar('\n'); ast_print(p->value, indent+1); }
        break;
    }
    case NODE_SPREAD: {
        SpreadExpr *s = (SpreadExpr*)n;
        putchar('\n');
        ast_print(s->arg, indent+1);
        break;
    }
    case NODE_PAREN: {
        ParenExpr *p = (ParenExpr*)n;
        fputs(" (paren)\n", stdout);
        ast_print(p->inner, indent+1);
        break;
    }
    case NODE_VAR_DECL: {
        VarDecl *v = (VarDecl*)n;
        printf(" %s n=%d", v->kind==VARDECL_VAR?"var":
                           v->kind==VARDECL_LET?"let":"const", v->n);
        for (int i = 0; i < v->n; i++) { putchar('\n'); ast_print((Node*)v->decls[i], indent+1); }
        break;
    }
    case NODE_VAR_DECLARATOR: {
        VarDeclarator *d = (VarDeclarator*)n;
        putchar('\n');
        ast_print(d->id, indent+1);
        if (d->init) { putchar('\n'); ast_print(d->init, indent+1); }
        break;
    }
    case NODE_IF: {
        IfStmt *s = (IfStmt*)n;
        putchar('\n');
        ast_print(s->test, indent+1); putchar('\n');
        ast_print(s->cons, indent+1);
        if (s->alt) { putchar('\n'); ast_print(s->alt, indent+1); }
        break;
    }
    case NODE_RETURN: {
        ReturnStmt *s = (ReturnStmt*)n;
        if (s->arg) { putchar('\n'); ast_print(s->arg, indent+1); }
        break;
    }
    case NODE_FUNC_DECL:
    case NODE_FUNC_EXPR: {
        FuncNode *f = (FuncNode*)n;
        printf(" name=%s%s%s nparams=%d\n",
               f->name ? f->name : "<anon>",
               f->is_async ? " async" : "",
               f->is_generator ? " gen" : "",
               f->nparams);
        for (int i = 0; i < f->nparams; i++) { ast_print(f->params[i], indent+1); putchar('\n'); }
        if (f->body) ast_print(f->body, indent+1);
        break;
    }
    case NODE_ARROW_FUNC: {
        FuncNode *f = (FuncNode*)n;
        printf(" nparams=%d\n", f->nparams);
        for (int i = 0; i < f->nparams; i++) { ast_print(f->params[i], indent+1); putchar('\n'); }
        if (f->body)      ast_print(f->body, indent+1);
        else if (f->expr_body) ast_print(f->expr_body, indent+1);
        break;
    }
    case NODE_PARAM: {
        Param *p = (Param*)n;
        fputs(p->rest ? " rest" : "", stdout);
        putchar('\n');
        ast_print(p->pattern, indent+1);
        if (p->default_value) { putchar('\n'); ast_print(p->default_value, indent+1); }
        break;
    }
    default:
        /* unknown-to-printer kinds: just close the paren */
        break;
    }
    putchar(')');
}

/* ============================================================ */
/* Arena head accessors — used by src/cache.c to swap arenas    */
/* ============================================================ */
void *ast_arena_head(void) {
    return (void *)g_head;
}

void ast_arena_set_head(void *h) {
    g_head = (ArenaBlock *)h;
}

void ast_arena_release_head(void *h) {
    ArenaBlock *b = (ArenaBlock *)h;
    while (b) {
        ArenaBlock *n = b->next;
        free(b);
        b = n;
    }
}
