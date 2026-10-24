/** scope.c — post-parse local slot assignment.
 * Walks a function body, collects local names, assigns slots,
 * writes slot numbers into matching Ident nodes. */

#include "../include/ast.h"
#include <string.h>
#include <stdlib.h>

#define SCOPE_MAX_LOCALS 256

typedef struct {
    char    *names[SCOPE_MAX_LOCALS];
    int      count;
} scope_t;

static int scope_find(const scope_t *s, const char *name) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->names[i], name) == 0) return i;
    }
    return -1;
}

static int scope_add(scope_t *s, const char *name) {
    if (s->count >= SCOPE_MAX_LOCALS) return -1;
    int existing = scope_find(s, name);
    if (existing >= 0) return existing;
    s->names[s->count] = (char *)name;
    return s->count++;
}

/* Forward decl */
static void walk_assign(Node *n, scope_t *s);

/* Param patterns: extract ident names into scope. */
static void collect_param(Node *pnode, scope_t *s) {
    if (!pnode) return;
    if (pnode->kind == NODE_PARAM) {
        Param *pm = (Param *)pnode;
        if (pm->pattern && pm->pattern->kind == NODE_IDENT) {
            Ident *id = (Ident *)pm->pattern;
            if (id->name) scope_add(s, id->name);
        }
        /* TODO: destructuring params */
    }
}

/* NODE_VAR_DECL — add every simple declarator name to scope. */
static void collect_var_decl(Node *n, scope_t *s) {
    if (!n || n->kind != NODE_VAR_DECL) return;
    VarDecl *v = (VarDecl *)n;
    for (int i = 0; i < v->n; i++) {
        VarDeclarator *d = v->decls[i];
        if (!d) continue;
        if (d->id && d->id->kind == NODE_IDENT) {
            Ident *id = (Ident *)d->id;
            if (id->name) scope_add(s, id->name);
        }
        /* TODO: destructuring */
    }
}

/* Resolve an Ident node: if its name is in scope, assign slot. Else -1. */
static void resolve_ident(Node *n, scope_t *s) {
    if (!n || n->kind != NODE_IDENT) return;
    Ident *id = (Ident *)n;
    if (!id->name) { id->slot = -1; return; }
    int idx = scope_find(s, id->name);
    id->slot = idx;
}

/* Walk all children of a node, calling walk_assign. Does NOT recurse into
 * nested functions — those get their own scope in the parent pass. */
static void walk_assign(Node *n, scope_t *s) {
    if (!n) return;

    switch (n->kind) {
        case NODE_IDENT:
            resolve_ident(n, s);
            return;

        /* Recurse into expressions */
        case NODE_BINARY: {
            BinaryExpr *b = (BinaryExpr *)n;
            walk_assign(b->left, s);
            walk_assign(b->right, s);
            return;
        }
        case NODE_UNARY: {
            UnaryExpr *u = (UnaryExpr *)n;
            walk_assign(u->arg, s);
            return;
        }
        case NODE_LOGICAL: {
            LogicalExpr *l = (LogicalExpr *)n;
            walk_assign(l->left, s);
            walk_assign(l->right, s);
            return;
        }
        case NODE_CONDITIONAL: {
            ConditionalExpr *c = (ConditionalExpr *)n;
            walk_assign(c->test, s);
            walk_assign(c->cons, s);
            walk_assign(c->alt, s);
            return;
        }
        case NODE_PAREN: {
            ParenExpr *p = (ParenExpr *)n;
            walk_assign(p->inner, s);
            return;
        }
        case NODE_SEQUENCE: {
            SequenceExpr *sq = (SequenceExpr *)n;
            for (int i = 0; i < sq->n; i++) walk_assign(sq->exprs[i], s);
            return;
        }
        case NODE_CALL: {
            CallExpr *c = (CallExpr *)n;
            walk_assign(c->callee, s);
            for (int i = 0; i < c->n; i++) walk_assign(c->args[i], s);
            return;
        }
        case NODE_MEMBER: {
            MemberExpr *m = (MemberExpr *)n;
            walk_assign(m->object, s);
            if (m->computed) walk_assign(m->property, s);
            return;
        }
        case NODE_ASSIGN: {
            AssignExpr *a = (AssignExpr *)n;
            walk_assign(a->target, s);
            walk_assign(a->value, s);
            return;
        }
        case NODE_EXPR_STMT: {
            ExprStmt *e = (ExprStmt *)n;
            walk_assign(e->expr, s);
            return;
        }
        case NODE_VAR_DECL: {
            VarDecl *v = (VarDecl *)n;
            for (int i = 0; i < v->n; i++) {
                VarDeclarator *d = v->decls[i];
                if (!d) continue;
                walk_assign(d->id, s);
                if (d->init) walk_assign(d->init, s);
            }
            return;
        }
        case NODE_BLOCK: {
            Block *b = (Block *)n;
            for (int i = 0; i < b->n; i++) walk_assign(b->stmts[i], s);
            return;
        }
        case NODE_IF: {
            IfStmt *ifn = (IfStmt *)n;
            walk_assign(ifn->test, s);
            walk_assign(ifn->cons, s);
            walk_assign(ifn->alt, s);
            return;
        }
        case NODE_WHILE: {
            WhileStmt *w = (WhileStmt *)n;
            walk_assign(w->test, s);
            walk_assign(w->body, s);
            return;
        }
        case NODE_FOR: {
            ForStmt *f = (ForStmt *)n;
            walk_assign(f->init, s);
            walk_assign(f->test, s);
            walk_assign(f->update, s);
            walk_assign(f->body, s);
            return;
        }
        case NODE_RETURN: {
            ReturnStmt *r = (ReturnStmt *)n;
            walk_assign(r->arg, s);
            return;
        }
        case NODE_UPDATE: {
            /* update expressions like x++ */
            UpdateExpr *up = (UpdateExpr *)n;
            walk_assign(up->arg, s);
            return;
        }

        /* Nested functions get their own scope pass — do not descend here. */
        case NODE_FUNC_DECL:
        case NODE_FUNC_EXPR:
        case NODE_ARROW_FUNC:
            return;

        default:
            return;
    }
}

/* Public entry: assign slots to a function body. */
void scope_assign(Node *func_node) {
    if (!func_node) return;
    if (func_node->kind != NODE_FUNC_DECL &&
        func_node->kind != NODE_FUNC_EXPR &&
        func_node->kind != NODE_ARROW_FUNC) return;

    FuncNode *f = (FuncNode *)func_node;
    scope_t s = {0};

    /* 1. Params first — they get slots 0..n-1 */
    for (int i = 0; i < f->nparams; i++) {
        collect_param(f->params[i], &s);
    }

    /* 2. Top-level var/let/const in the function body */
    if (f->body && f->body->kind == NODE_BLOCK) {
        Block *b = (Block *)f->body;
        for (int i = 0; i < b->n; i++) {
            collect_var_decl(b->stmts[i], &s);
        }
    }

    /* 3. Walk and resolve. */
    if (f->body) walk_assign(f->body, &s);
    if (f->expr_body) walk_assign(f->expr_body, &s);
}
