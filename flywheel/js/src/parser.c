/* flywheel/src/parser.c — piece 1: foundation
 *
 * Parser state, error recording, token access, recovery.
 * Grammar functions (expressions, statements, etc) live in later pieces.
 *
 * PHILOSOPHY: this file never crashes.
 *  - Every error is recorded in a ParseError with code + message + line + col
 *  - Parser NEVER calls exit(), abort(), or prints to stdout
 *  - NULL is always checked
 *  - On allocation failure, sets p->fatal and returns a sensible default
 *  - On syntax error, records + synchronizes + continues (unless fatal)
 */

#include "../include/parser.h"
#include "../include/ast.h"
extern void scope_assign(Node *func_node);
#include "../include/cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================ */
/* Error messages — one per code                              */
/* ============================================================ */
static const char *ERR_MSG[] = {
    [PARSE_OK]                       = "ok",
    [PARSE_ERR_LEXER]                = "lexer error",
    [PARSE_ERR_UNEXPECTED_TOKEN]     = "unexpected token",
    [PARSE_ERR_EXPECTED_TOKEN]       = "expected token",
    [PARSE_ERR_UNEXPECTED_EOF]       = "unexpected end of input",
    [PARSE_ERR_INVALID_ASSIGNMENT]   = "invalid assignment target",
    [PARSE_ERR_INVALID_ARROW]        = "invalid arrow function",
    [PARSE_ERR_INVALID_SPREAD]       = "invalid spread operator use",
    [PARSE_ERR_INVALID_TERNARY]      = "invalid conditional expression",
    [PARSE_ERR_INVALID_TAGGED_TEMPLATE] = "invalid tagged template",
    [PARSE_ERR_INVALID_DECLARATION]  = "invalid declaration",
    [PARSE_ERR_INVALID_STATEMENT]    = "invalid statement",
    [PARSE_ERR_INVALID_FOR]          = "invalid for statement",
    [PARSE_ERR_INVALID_RETURN]       = "return outside of function",
    [PARSE_ERR_INVALID_BREAK]        = "break outside of loop or switch",
    [PARSE_ERR_INVALID_CONTINUE]     = "continue outside of loop",
    [PARSE_ERR_INVALID_THROW]        = "invalid throw",
    [PARSE_ERR_INVALID_TRY]          = "invalid try statement",
    [PARSE_ERR_INVALID_PARAMS]       = "invalid parameter list",
    [PARSE_ERR_DUPLICATE_PARAM]      = "duplicate parameter name in strict mode",
    [PARSE_ERR_DUPLICATE_PROTO]      = "duplicate __proto__ in object literal",
    [PARSE_ERR_INVALID_CLASS]        = "invalid class",
    [PARSE_ERR_INVALID_METHOD]       = "invalid method definition",
    [PARSE_ERR_CTOR_CANNOT_BE_ASYNC]= "constructor cannot be async",
    [PARSE_ERR_CTOR_CANNOT_BE_GEN]   = "constructor cannot be a generator",
    [PARSE_ERR_INVALID_DESTRUCTURING]= "invalid destructuring pattern",
    [PARSE_ERR_REST_MUST_BE_LAST]    = "rest element must be last",
    [PARSE_ERR_REST_CANNOT_HAVE_DEFAULT] = "rest element cannot have a default",
    [PARSE_ERR_INVALID_PATTERN]      = "invalid pattern",
    [PARSE_ERR_INVALID_MODULE]       = "invalid module syntax",
    [PARSE_ERR_IMPORT_IN_SCRIPT]     = "import/export only allowed in modules",
    [PARSE_ERR_RESERVED_WORD]        = "reserved word used as identifier",
    [PARSE_ERR_STRICT_VIOLATION]     = "strict mode violation",
    [PARSE_ERR_TOO_MANY_ERRORS]      = "too many errors, stopping",
    [PARSE_ERR_INTERNAL]             = "internal parser error",
};

const char *parser_error_code_name(ParseErrorCode c) {
    if ((int)c < 0 || c > PARSE_ERR_INTERNAL) return "?";
    const char *m = ERR_MSG[c];
    return m ? m : "?";
}

/* ============================================================ */
/* Parser state                                                */
/* ============================================================ */
#define MAX_ERRORS_DEFAULT 64
#define MAX_ERRORS_HARD    4096
#define MAX_RECURSION_DEPTH 10000  /* ~2000 parens deep — generous but bounded */

/* depth guard — enter/leave pairs, safe to call from any recursive fn.
 * On exceeding depth, we emit a NON-fatal error and return NULL from the
 * current parse function. The recursion naturally unwinds; the parser
 * continues with whatever it produced so far. */
#define DEPTH_ENTER(p) \
    do { \
        if (++(p)->depth > (p)->max_depth) { \
            parser_error_at_current((p), PARSE_ERR_INTERNAL, \
                "maximum recursion depth exceeded"); \
            (p)->depth--; \
            return NULL; \
        } \
    } while (0)

#define DEPTH_LEAVE(p) do { if ((p)->depth > 0) (p)->depth--; } while (0)

typedef struct {
    Lexer       lx;
    Token       current;
    Token       lookahead;
    int         has_lookahead;

    const char *source;
    const char *filename;

    ParseError *errors;
    int         nerrors;
    int         errcap;
    int         fatal;

    /* context */
    int         in_function;
    int         in_loop;
    int         in_async;
    int         in_generator;
    int         in_class;
    int         strict;
    int         is_module;

    /* recursion guard — prevents stack overflow on deeply nested input */
    int         depth;
    int         max_depth;
} Parser;

/* ============================================================ */
/* Error recording — never crashes                             */
/* ============================================================ */
static void parser_error(Parser *p, ParseErrorCode code, const char *msg,
                         int line, int col) {
    if (!p) return;
    if (p->fatal) return;
    if (p->nerrors >= MAX_ERRORS_HARD) {
        /* hard cap: mark fatal, stop accumulating */
        p->fatal = 1;
        return;
    }
    if (p->nerrors >= p->errcap) {
        int newcap = p->errcap ? p->errcap * 2 : MAX_ERRORS_DEFAULT;
        ParseError *big = (ParseError*)realloc(p->errors,
                                               newcap * sizeof(ParseError));
        if (!big) {
            /* can't grow — mark fatal, but still keep what we have */
            p->fatal = 1;
            return;
        }
        p->errors = big;
        p->errcap = newcap;
    }
    /* Copy the message text into arena memory. The caller's buffer
     * (like p->lx.error_msg, or parser_expect's stack buf) is dead once
     * that stack frame returns, so storing the raw pointer would leave
     * dangling references. One copy per error, first error wins. */
    const char *raw = msg ? msg : (ERR_MSG[code] ? ERR_MSG[code] : "error");
    char *stored = NULL;
    if (raw) {
        size_t _len = strlen(raw);
        stored = (char*)ast_alloc(_len + 1);
        if (stored) {
            memcpy(stored, raw, _len + 1);
        }
    }
    if (!stored) {
        /* arena allocation failed — fall back to a static string */
        stored = (char *)(ERR_MSG[code] ? ERR_MSG[code] : "error");
    }

    ParseError *e = &p->errors[p->nerrors++];
    e->code     = code;
    e->msg      = stored;
    e->line     = line;
    e->column   = col;
    e->filename = p->filename;
}

/* convenience — use current token's position */
static void parser_error_at_current(Parser *p, ParseErrorCode code,
                                    const char *msg) {
    parser_error(p, code, msg,
                 p->current.line, p->current.column);
}

/* ============================================================ */
/* Token access                                                */
/* ============================================================ */
static void parser_load_next(Parser *p) {
    if (!p || p->fatal) return;
    Token t = lexer_next(&p->lx);
    if (t.kind == TOK_ERROR) {
        parser_error(p, PARSE_ERR_LEXER,
                     p->lx.error_msg[0] ? p->lx.error_msg : "lex error",
                     p->lx.error_line, p->lx.error_column);
        /* recover: pretend we got a "nothing" token */
        Token dummy = {0};
        dummy.kind = TOK_EOF;
        dummy.start = t.start;
        dummy.line = t.line;
        dummy.column = t.column;
        p->lookahead = dummy;
        p->has_lookahead = 1;
        return;
    }
    p->lookahead = t;
    p->has_lookahead = 1;
}

static void parser_advance(Parser *p) {
    if (!p) return;
    if (p->has_lookahead) {
        p->current = p->lookahead;
        p->has_lookahead = 0;
    } else {
        Token t = lexer_next(&p->lx);
        if (t.kind == TOK_ERROR) {
            parser_error(p, PARSE_ERR_LEXER,
                         p->lx.error_msg[0] ? p->lx.error_msg : "lex error",
                         p->lx.error_line, p->lx.error_column);
            Token dummy = {0};
            dummy.kind = TOK_EOF;
            dummy.start = t.start;
            dummy.line = t.line;
            dummy.column = t.column;
            p->current = dummy;
            return;
        }
        p->current = t;
    }
    if (p->current.kind == TOK_EOF) {
        /* freeze at EOF forever — further advances are no-ops */
    }
}

static __attribute__((unused)) Token parser_peek_next(Parser *p) {
    if (!p) return (Token){0};
    if (!p->has_lookahead) parser_load_next(p);
    return p->lookahead;
}

static int parser_check(Parser *p, TokKind kind) {
    if (!p || p->fatal) return 0;
    return p->current.kind == kind;
}

static int parser_check_kw(Parser *p, KeywordKind kw) {
    if (!p || p->fatal) return 0;
    return p->current.kind == TOK_KEYWORD && p->current.keyword == kw;
}

static __attribute__((unused)) int parser_match(Parser *p, TokKind kind) {
    if (parser_check(p, kind)) {
        parser_advance(p);
        return 1;
    }
    return 0;
}

static __attribute__((unused)) int parser_match_kw(Parser *p, KeywordKind kw) {
    if (parser_check_kw(p, kw)) {
        parser_advance(p);
        return 1;
    }
    return 0;
}

static __attribute__((unused)) int parser_expect(Parser *p, TokKind kind, const char *what) {
    if (parser_check(p, kind)) {
        parser_advance(p);
        return 1;
    }
    char buf[128];
    const char *want = what ? what : token_kind_name(kind);
    snprintf(buf, sizeof(buf), "expected %s", want);
    parser_error_at_current(p,
        p->current.kind == TOK_EOF ? PARSE_ERR_UNEXPECTED_EOF
                                   : PARSE_ERR_EXPECTED_TOKEN,
        buf);
    return 0;
}

/* ============================================================ */
/* Recovery: skip to a plausible statement boundary            */
/* ============================================================ */
static __attribute__((unused)) void parser_synchronize(Parser *p) {
    if (!p || p->fatal) return;
    parser_advance(p);
    while (p->current.kind != TOK_EOF) {
        /* skip past statement terminators */
        if (p->current.kind == TOK_SEMICOLON) {
            parser_advance(p);
            return;
        }
        switch (p->current.kind) {
        case TOK_RBRACE:
        case TOK_KEYWORD: /* if/for/while/var/let/const/function/class/return/... */
            return;
        default:
            parser_advance(p);
        }
    }
}

/* ---- forward declarations (module scope) ---- */
static Node *parse_program(Parser *p);
static Node *parse_if_stmt(Parser *p, int line, int col);
static Node *parse_while_stmt(Parser *p, int line, int col);
static Node *parse_do_stmt(Parser *p, int line, int col);
static Node *parse_for_stmt(Parser *p, int line, int col);
static Node *parse_return_stmt(Parser *p, int line, int col);
static Node *parse_break_continue_stmt(Parser *p, int line, int col);
static Node *parse_throw_stmt(Parser *p, int line, int col);
static Node *parse_try_stmt(Parser *p, int line, int col);
static Node *parse_switch_stmt(Parser *p, int line, int col);
static Node *parse_statement(Parser *p);
static Node *parse_expression(Parser *p, int no_in);
static Node *parse_assignment(Parser *p, int no_in);
static Node *parse_conditional(Parser *p, int no_in);
static Node *parse_binary(Parser *p, int min_prec, int no_in);
static Node *parse_unary(Parser *p);
static Node *parse_postfix(Parser *p);
static Node *parse_lhs_expr(Parser *p);
static Node *parse_primary(Parser *p);
static Node *parse_array_literal(Parser *p);
static Node *parse_object_literal(Parser *p);
static Node *parse_template(Parser *p, Node *tag);
static Node *parse_function(Parser *p, int is_decl, int is_async);
static Node *parse_class(Parser *p, int is_decl);
static Node *parse_params(Parser *p, int *out_n);
static Node *parse_block(Parser *p);
static Node *parse_var_decl(Parser *p, int kind);
static char *dup_string(const char *s);
static char *dup_range(const char *s, int n);
static ParseResult parser_do_uncached(const char *source, const char *filename,
                             int as_module) {
    ParseResult r;
    memset(&r, 0, sizeof(r));

    if (!source) {
        r.program = NULL;
        r.errors = NULL;
        r.nerrors = 1;
        r.capacity = 0;
        r.fatal = 1;
        /* caller must not dereference errors when capacity==0 */
        return r;
    }

    Parser p;
    memset(&p, 0, sizeof(p));
    p.source = source;
    p.filename = filename;
    p.is_module = as_module ? 1 : 0;
    p.errcap = MAX_ERRORS_DEFAULT;
    p.max_depth = MAX_RECURSION_DEPTH;
    p.errors = (ParseError*)malloc(p.errcap * sizeof(ParseError));
    if (!p.errors) {
        r.program = NULL;
        r.errors = NULL;
        r.nerrors = 1;
        r.capacity = 0;
        r.fatal = 1;
        return r;
    }

    lexer_init(&p.lx, source);
    parser_advance(&p);   /* prime current token */

    Node *prog = parse_program(&p);

    /* if the parser made zero errors but returned no program, that's a bug */
    if (!prog && p.nerrors == 0) {
        parser_error(&p, PARSE_ERR_INTERNAL, "parser returned no program",
                     p.current.line, p.current.column);
    }

    r.program    = prog;
    r.errors     = p.errors;
    r.nerrors    = p.nerrors;
    r.capacity   = p.errcap;
    r.fatal      = p.fatal;
    return r;
}

ParseResult parser_parse(const char *source, const char *filename) {
    return parser_parse_cached(source, filename);
}

ParseResult parser_parse_nocache(const char *source, const char *filename) {
    /* Isolate: install a NULL arena so the parse does not append to
     * any existing (possibly cache-owned) arena chain. Leave the fresh
     * arena installed so the caller can free it normally. */
    ast_mark_cache_owned(0);
    ast_arena_set_head(NULL);
    ParseResult r = parser_do_uncached(source, filename, 0);
    r.owns_arena = 1;
    return r;
}

ParseResult parser_parse_module(const char *source, const char *filename) {
    return parser_parse_module_cached(source, filename);
}

/* Non-static uncached entry points used by src/cache.c */
/* Internal — no arena swap. Used by src/cache.c which does its own
 * swap management. Do not call these from normal code. */
ParseResult parser_parse_no_swap(const char *source, const char *filename) {
    return parser_do_uncached(source, filename, 0);
}
ParseResult parser_parse_module_no_swap(const char *source, const char *filename) {
    return parser_do_uncached(source, filename, 1);
}

ParseResult parser_parse_uncached(const char *source, const char *filename) {
    ast_mark_cache_owned(0);
    ast_arena_set_head(NULL);
    ParseResult r = parser_do_uncached(source, filename, 0);
    r.owns_arena = 1;
    return r;
}

ParseResult parser_parse_module_uncached(const char *source, const char *filename) {
    ast_mark_cache_owned(0);
    ast_arena_set_head(NULL);
    ParseResult r = parser_do_uncached(source, filename, 1);
    r.owns_arena = 1;
    return r;
}

void parser_free_result(ParseResult *r) {
    if (!r) return;
    if (r->errors) {
        free(r->errors);
        r->errors = NULL;
    }
    r->program = NULL;
    r->nerrors = 0;
    r->capacity = 0;
    r->fatal = 0;
    /* note: AST nodes are arena-allocated; call ast_free_arena() separately */
}

int parser_error_count(const ParseResult *r) {
    return r ? r->nerrors : 0;
}

void parser_print_errors(const ParseResult *r) {
    if (!r || !r->errors || r->nerrors <= 0) return;
    for (int i = 0; i < r->nerrors; i++) {
        const ParseError *e = &r->errors[i];
        printf("%s:%d:%d: %s: %s\n",
               e->filename ? e->filename : "<input>",
               e->line, e->column,
               parser_error_code_name(e->code),
               e->msg ? e->msg : "");
    }
    if (r->fatal) {
        printf("(fatal: too many errors)\n");
    }
}

/* ============================================================ */
/* Test main — only when built with -DPARSER_TEST              */
/* ============================================================ */
#ifdef PARSER_TEST
int main(int argc, char **argv) {
    const char *src = (argc >= 2) ? argv[1] : "1 + 2 * 3 - 4 / 5";
    ParseResult r = parser_parse(src, "<test>");
    printf("=== source ===\n%s\n\n", src);
    if (r.program) {
        printf("=== ast ===\n");
        ast_print(r.program, 0);
        printf("\n");
    } else {
        printf("=== ast === (null)\n");
    }
    printf("\n=== errors: %d ===\n", r.nerrors);
    if (r.nerrors) parser_print_errors(&r);
    int had_errors = r.nerrors;
    parser_free_result(&r);
    ast_free_arena();
    return (had_errors > 0) ? 1 : 0;
}
#endif
/* ==================================================================
 *  piece 2 — expressions + statements (full grammar)
 *  ================================================================== */

/* ---- forward decls ---- */
static Node *parse_statement(Parser *p);
static Node *parse_expression(Parser *p, int no_in);
static Node *parse_assignment(Parser *p, int no_in);
static Node *parse_conditional(Parser *p, int no_in);
static Node *parse_binary(Parser *p, int min_prec, int no_in);
static Node *parse_unary(Parser *p);
static Node *parse_postfix(Parser *p);
static Node *parse_lhs_expr(Parser *p);
static Node *parse_primary(Parser *p);
static Node *parse_array_literal(Parser *p);
static Node *parse_object_literal(Parser *p);
static Node *parse_template(Parser *p, Node *tag);
static Node *parse_function(Parser *p, int is_decl, int is_async);
static Node *parse_class(Parser *p, int is_decl);
static Node *parse_params(Parser *p, int *out_n);
static Node *parse_block(Parser *p);
static Node *parse_var_decl(Parser *p, int kind);

/* ---- precedence table ---- */
typedef struct { TokKind tk; int prec; int right; BinaryOp op; } BinOpEntry;
static const BinOpEntry BIN_OPS[] = {
    { TOK_NULLISH,     1, 0, BINOP_ADD /*unused*/ },
    { TOK_OR_OR,       2, 0, BINOP_ADD },
    { TOK_AND_AND,     3, 0, BINOP_ADD },
    { TOK_PIPE,        4, 0, BINOP_BITOR },
    { TOK_CARET,       5, 0, BINOP_BITXOR },
    { TOK_AMP,         6, 0, BINOP_BITAND },
    { TOK_EQEQ,        7, 0, BINOP_EQ },
    { TOK_NEQ,         7, 0, BINOP_NEQ },
    { TOK_STRICT_EQ,   7, 0, BINOP_SEQ },
    { TOK_STRICT_NEQ,  7, 0, BINOP_SNEQ },
    { TOK_LT,          8, 0, BINOP_LT },
    { TOK_GT,          8, 0, BINOP_GT },
    { TOK_LE,          8, 0, BINOP_LE },
    { TOK_GE,          8, 0, BINOP_GE },
    { TOK_LSHIFT,      9, 0, BINOP_LSHIFT },
    { TOK_RSHIFT,      9, 0, BINOP_RSHIFT },
    { TOK_URSHIFT,     9, 0, BINOP_URSHIFT },
    { TOK_PLUS,       10, 0, BINOP_ADD },
    { TOK_MINUS,      10, 0, BINOP_SUB },
    { TOK_STAR,       11, 0, BINOP_MUL },
    { TOK_SLASH,      11, 0, BINOP_DIV },
    { TOK_PERCENT,    11, 0, BINOP_MOD },
    { TOK_POW,        12, 1, BINOP_POW },
};
static const int N_BIN_OPS = sizeof(BIN_OPS)/sizeof(BIN_OPS[0]);

/* ---- helpers ---- */

static char *dup_string(const char *s);
static char *dup_range(const char *s, int n);
static char *dup_range(const char *s, int n) {
    if (!s || n <= 0) { char *e = (char*)ast_alloc(1); if (e) e[0]=0; return e; }
    char *out = (char*)ast_alloc((size_t)n + 1);
    if (!out) return NULL;
    memcpy(out, s, (size_t)n);
    out[n] = 0;
    return out;
}

static int is_assign_op(TokKind k) {
    switch (k) {
    case TOK_EQ: case TOK_PLUS_EQ: case TOK_MINUS_EQ:
    case TOK_STAR_EQ: case TOK_SLASH_EQ: case TOK_PERCENT_EQ:
    case TOK_POW_EQ: case TOK_AMP_EQ: case TOK_PIPE_EQ:
    case TOK_CARET_EQ: case TOK_LSHIFT_EQ: case TOK_RSHIFT_EQ:
    case TOK_URSHIFT_EQ: case TOK_AND_AND_EQ: case TOK_OR_OR_EQ:
    case TOK_NULLISH_EQ:
        return 1;
    default: return 0;
    }
}
static AssignOp assign_op_from(TokKind k) {
    switch (k) {
    case TOK_EQ: return ASSIGN_EQ;
    case TOK_PLUS_EQ: return ASSIGN_ADD;
    case TOK_MINUS_EQ: return ASSIGN_SUB;
    case TOK_STAR_EQ: return ASSIGN_MUL;
    case TOK_SLASH_EQ: return ASSIGN_DIV;
    case TOK_PERCENT_EQ: return ASSIGN_MOD;
    case TOK_POW_EQ: return ASSIGN_POW;
    case TOK_AMP_EQ: return ASSIGN_BITAND;
    case TOK_PIPE_EQ: return ASSIGN_BITOR;
    case TOK_CARET_EQ: return ASSIGN_BITXOR;
    case TOK_LSHIFT_EQ: return ASSIGN_LSHIFT;
    case TOK_RSHIFT_EQ: return ASSIGN_RSHIFT;
    case TOK_URSHIFT_EQ: return ASSIGN_URSHIFT;
    case TOK_AND_AND_EQ: return ASSIGN_AND;
    case TOK_OR_OR_EQ: return ASSIGN_OR;
    case TOK_NULLISH_EQ: return ASSIGN_NULLISH;
    default: return ASSIGN_EQ;
    }
}

/* ---- expressions ---- */
static Node *parse_expression(Parser *p, int no_in) {
    DEPTH_ENTER(p);
    Node *first = parse_assignment(p, no_in);
    if (!parser_check(p, TOK_COMMA)) return first;

    SequenceExpr *s = (SequenceExpr*)MK(NODE_SEQUENCE, SequenceExpr, p->current.line, p->current.column, p->current.line, p->current.column);
    if (!s) return first;
    s->exprs = (Node**)ast_alloc(sizeof(Node*) * 4);
    s->n = 0;
    int cap = 4;
    s->exprs[s->n++] = first;
    while (parser_match(p, TOK_COMMA)) {
        if (s->n >= cap) {
            cap *= 2;
            Node **big = (Node**)ast_alloc(sizeof(Node*) * (size_t)cap);
            if (!big) break;
            memcpy(big, s->exprs, sizeof(Node*) * (size_t)s->n);
            s->exprs = big;
        }
        s->exprs[s->n++] = parse_assignment(p, no_in);
    }
    return (Node*)s;
}

static Node *parse_assignment(Parser *p, int no_in) {
    DEPTH_ENTER(p);
    Node *left = parse_conditional(p, no_in);
    if (!left) return NULL;

    if (is_assign_op(p->current.kind)) {
        AssignOp op = assign_op_from(p->current.kind);
        parser_advance(p);
        Node *value = parse_assignment(p, no_in);
        AssignExpr *a = (AssignExpr*)MK(NODE_ASSIGN, AssignExpr, left->line, left->column,
            value ? value->end_line : left->end_line,
            value ? value->end_column : left->end_column);
        if (!a) return left;
        a->op = op;
        a->target = left;
        a->value = value;
        return (Node*)a;
    }
    return left;
}

static Node *parse_conditional(Parser *p, int no_in) {
    DEPTH_ENTER(p);
    Node *test = parse_binary(p, 1, no_in);
    if (!parser_match(p, TOK_QUESTION)) return test;

    Node *cons = parse_assignment(p, 0);
    parser_expect(p, TOK_COLON, ":");
    Node *alt = parse_assignment(p, no_in);
    ConditionalExpr *c = (ConditionalExpr*)MK(NODE_CONDITIONAL, ConditionalExpr, p->current.line, p->current.column, p->current.line, p->current.column);
    if (!c) return test;
    c->test = test;
    c->cons = cons;
    c->alt  = alt;
    return (Node*)c;
}

static int peek_binop(Parser *p, int *out_prec, int *out_right,
                      BinaryOp *out_op, TokKind *out_tok) {
    TokKind k = p->current.kind;
    /* special: in / instanceof as keywords */
    if (p->current.kind == TOK_KEYWORD) {
        if (p->current.keyword == KW_IN) {
            *out_prec = 8; *out_right = 0; *out_op = BINOP_IN; *out_tok = k;
            return 1;
        }
        if (p->current.keyword == KW_INSTANCEOF) {
            *out_prec = 8; *out_right = 0; *out_op = BINOP_INSTANCEOF; *out_tok = k;
            return 1;
        }
        return 0;
    }
    for (int i = 0; i < N_BIN_OPS; i++) {
        if (BIN_OPS[i].tk == k) {
            *out_prec = BIN_OPS[i].prec;
            *out_right = BIN_OPS[i].right;
            *out_op = BIN_OPS[i].op;
            *out_tok = k;
            return 1;
        }
    }
    return 0;
}

static Node *parse_binary(Parser *p, int min_prec, int no_in) {
    DEPTH_ENTER(p);
    Node *left = parse_unary(p);
    if (!left) return NULL;

    for (;;) {
        int prec, right;
        BinaryOp op;
        TokKind tk;
        if (!peek_binop(p, &prec, &right, &op, &tk)) break;
        if (prec < min_prec) break;
        /* `in` disallowed in for-init when no_in */
        if (no_in && p->current.kind == TOK_KEYWORD &&
            p->current.keyword == KW_IN) break;
        /* logical ops get their own node kind */
        int is_logic = (p->current.kind == TOK_AND_AND ||
                        p->current.kind == TOK_OR_OR ||
                        p->current.kind == TOK_NULLISH);
        parser_advance(p);
        int next_min = right ? prec : prec + 1;
        Node *right_node = parse_binary(p, next_min, no_in);
        if (is_logic) {
            LogicalExpr *l = (LogicalExpr*)MK(NODE_LOGICAL, LogicalExpr, left->line, left->column,
                right_node ? right_node->end_line : left->end_line,
                right_node ? right_node->end_column : left->end_column);
            if (!l) return left;
            l->op = (p->current.kind == TOK_AND_AND ||
                     (left && left->kind == NODE_LOGICAL &&
                      ((LogicalExpr*)left)->op == LOGOP_AND)) ? LOGOP_AND :
                    (left && left->kind == NODE_LOGICAL &&
                     ((LogicalExpr*)left)->op == LOGOP_OR) ? LOGOP_OR :
                    LOGOP_NULLISH;
            /* simpler: infer from token we consumed */
            if (tk == TOK_AND_AND) l->op = LOGOP_AND;
            else if (tk == TOK_OR_OR) l->op = LOGOP_OR;
            else l->op = LOGOP_NULLISH;
            l->left = left;
            l->right = right_node;
            left = (Node*)l;
        } else {
            BinaryExpr *b = (BinaryExpr*)MK(NODE_BINARY, BinaryExpr, left->line, left->column,
                right_node ? right_node->end_line : left->end_line,
                right_node ? right_node->end_column : left->end_column);
            if (!b) return left;
            b->op = op;
            b->left = left;
            b->right = right_node;
            left = (Node*)b;
        }
    }
    return left;
}

static Node *parse_unary(Parser *p) {
    DEPTH_ENTER(p);
    UnaryOp uop;
    int have_unary = 0;
    switch (p->current.kind) {
    case TOK_PLUS:  uop = UNOP_PLUS;  have_unary = 1; break;
    case TOK_MINUS: uop = UNOP_MINUS; have_unary = 1; break;
    case TOK_BANG:  uop = UNOP_NOT;   have_unary = 1; break;
    case TOK_TILDE: uop = UNOP_BITNOT;have_unary = 1; break;
    case TOK_PLUS_PLUS:
    case TOK_MINUS_MINUS: {
        UpdateOp op = (p->current.kind == TOK_PLUS_PLUS) ? UPDOP_INC : UPDOP_DEC;
        int line = p->current.line, col = p->current.column;
        parser_advance(p);
        Node *arg = parse_unary(p);
        UpdateExpr *u = (UpdateExpr*)MK(NODE_UPDATE, UpdateExpr, line, col,
                                             arg ? arg->end_line : line,
                                             arg ? arg->end_column : col);
        if (!u) return arg;
        u->op = op; u->arg = arg; u->prefix = 1;
        return (Node*)u;
    }
    default:
        if (p->current.kind == TOK_KEYWORD) {
            switch (p->current.keyword) {
            case KW_TYPEOF: uop = UNOP_TYPEOF; have_unary = 1; break;
            case KW_VOID:   uop = UNOP_VOID;   have_unary = 1; break;
            case KW_DELETE: uop = UNOP_DELETE; have_unary = 1; break;
            case KW_AWAIT: {
                int line = p->current.line, col = p->current.column;
                parser_advance(p);
                Node *arg = parse_unary(p);
                struct AwaitNode { Node base; Node *arg; };
                struct AwaitNode *aw = (struct AwaitNode*)ast_new_sized(
                    NODE_AWAIT, sizeof(struct AwaitNode),
                    line, col,
                    arg ? arg->end_line : line,
                    arg ? arg->end_column : col);
                if (aw) aw->arg = arg;
                return aw ? (Node*)aw : arg;
            }
            case KW_NEW: {
                int line = p->current.line, col = p->current.column;
                parser_advance(p);
                if (parser_check(p, TOK_DOT)) {
                    parser_advance(p);
                    if (parser_check_kw(p, KW_NONE) == 0 &&
                        (parser_check(p, TOK_IDENT))) {
                        /* new.target */
                        parser_advance(p);
                        return ast_new(NODE_NEW_TARGET, line, col, line, col);
                    }
                }
                Node *callee;
                if (parser_check_kw(p, KW_NEW)) {
                    /* chained new: recursively parse the inner new */
                    callee = parse_unary(p);
                } else {
                    callee = parse_lhs_expr(p);
                }
                Node **args = NULL; int n = 0;
                if (parser_match(p, TOK_LPAREN)) {
                    args = (Node**)ast_alloc(sizeof(Node*) * 8);
                    int cap = 8;
                    while (!parser_check(p, TOK_RPAREN) &&
                           !parser_check(p, TOK_EOF)) {
                        if (n >= cap) {
                            cap *= 2;
                            Node **big = (Node**)ast_alloc(sizeof(Node*)*cap);
                            if (!big) break;
                            memcpy(big, args, sizeof(Node*)*(size_t)n);
                            args = big;
                        }
                        if (parser_match(p, TOK_ELLIPSIS)) {
                            SpreadExpr *s = (SpreadExpr*)MK(NODE_SPREAD, SpreadExpr, p->current.line, p->current.column, p->current.line, p->current.column);
                            if (s) s->arg = parse_assignment(p, 0);
                            args[n++] = (Node*)s;
                        } else {
                            args[n++] = parse_assignment(p, 0);
                        }
                        if (!parser_match(p, TOK_COMMA)) break;
                    }
                    parser_expect(p, TOK_RPAREN, ")");
                }
                NewExpr *ne = (NewExpr*)MK(NODE_NEW, NewExpr, line, col,
                    p->current.line, p->current.column);
                if (!ne) return callee;
                ne->callee = callee;
                ne->args = args;
                ne->n = n;
                return (Node*)ne;
            }
            default: break;
            }
        }
        break;
    }
    if (have_unary) {
        int line = p->current.line, col = p->current.column;
        parser_advance(p);
        Node *arg = parse_unary(p);
        UnaryExpr *u = (UnaryExpr*)MK(NODE_UNARY, UnaryExpr, line, col,
                                           arg ? arg->end_line : line,
                                           arg ? arg->end_column : col);
        if (!u) return arg;
        u->op = uop;
        u->arg = arg;
        return (Node*)u;
    }
    return parse_postfix(p);
}

static Node *parse_postfix(Parser *p) {
    DEPTH_ENTER(p);
    Node *expr = parse_lhs_expr(p);
    if (parser_check(p, TOK_PLUS_PLUS) || parser_check(p, TOK_MINUS_MINUS)) {
        UpdateOp op = (p->current.kind == TOK_PLUS_PLUS) ? UPDOP_INC : UPDOP_DEC;
        int line = p->current.line, col = p->current.column;
        parser_advance(p);
        UpdateExpr *u = (UpdateExpr*)MK(NODE_UPDATE, UpdateExpr, expr?expr->line:line,
                                             expr?expr->column:col, line, col);
        if (!u) return expr;
        u->op = op; u->arg = expr; u->prefix = 0;
        return (Node*)u;
    }
    return expr;
}

static Node *parse_arguments(Parser *p, int *out_n) {
    parser_expect(p, TOK_LPAREN, "(");
    Node **args = (Node**)ast_alloc(sizeof(Node*) * 8);
    int n = 0, cap = 8;
    while (!parser_check(p, TOK_RPAREN) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) {
            cap *= 2;
            Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap);
            if (!big) break;
            memcpy(big, args, sizeof(Node*)*(size_t)n);
            args = big;
        }
        if (parser_match(p, TOK_ELLIPSIS)) {
            SpreadExpr *s = (SpreadExpr*)MK(NODE_SPREAD, SpreadExpr, p->current.line, p->current.column, p->current.line, p->current.column);
            if (s) s->arg = parse_assignment(p, 0);
            args[n++] = (Node*)s;
        } else {
            args[n++] = parse_assignment(p, 0);
        }
        if (!parser_match(p, TOK_COMMA)) break;
    }
    parser_expect(p, TOK_RPAREN, ")");
    *out_n = n;
    return (Node*)args;
}

static Node *parse_lhs_expr(Parser *p) {
    DEPTH_ENTER(p);
    Node *expr = parse_primary(p);
    if (!expr) return NULL;

    for (;;) {
        if (parser_match(p, TOK_DOT)) {
            if (parser_check(p, TOK_IDENT) || parser_check(p, TOK_KEYWORD)) {
                Ident *id = (Ident*)MK(NODE_IDENT, Ident, p->current.line, p->current.column,
                    p->current.line, p->current.column + p->current.length);
    id->slot = -1;
                if (id) id->name = dup_range(p->current.start, p->current.length);
                parser_advance(p);
                MemberExpr *m = (MemberExpr*)MK(NODE_MEMBER, MemberExpr, expr->line, expr->column,
                    id?id->base.end_line:expr->end_line,
                    id?id->base.end_column:expr->end_column);
                if (!m) return expr;
                m->object = expr;
                m->property = (Node*)id;
                m->computed = 0;
                m->optional = 0;
                expr = (Node*)m;
            } else {
                parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
                                        "expected property name after '.'");
                return expr;
            }
        } else if (parser_match(p, TOK_OPTIONAL_CHAIN)) {
            /* ?. */
            if (parser_check(p, TOK_LPAREN)) {
                int argc = 0;
                Node **args = (Node**)parse_arguments(p, &argc);
                CallExpr *c = (CallExpr*)MK(NODE_CALL, CallExpr, expr->line, expr->column,
                    p->current.line, p->current.column);
                if (!c) return expr;
                c->callee = expr; c->args = args; c->n = argc; c->optional = 1;
                expr = (Node*)c;
            } else if (parser_match(p, TOK_LBRACKET)) {
                Node *prop = parse_expression(p, 0);
                parser_expect(p, TOK_RBRACKET, "]");
                MemberExpr *m = (MemberExpr*)MK(NODE_MEMBER, MemberExpr, expr->line, expr->column,
                    p->current.line, p->current.column);
                if (!m) return expr;
                m->object = expr; m->property = prop;
                m->computed = 1; m->optional = 1;
                expr = (Node*)m;
            } else if (parser_check(p, TOK_IDENT) || parser_check(p, TOK_KEYWORD)) {
                Ident *id = (Ident*)MK(NODE_IDENT, Ident, p->current.line, p->current.column,
                    p->current.line, p->current.column + p->current.length);
    id->slot = -1;
                if (id) id->name = dup_range(p->current.start, p->current.length);
                parser_advance(p);
                MemberExpr *m = (MemberExpr*)MK(NODE_MEMBER, MemberExpr, expr->line, expr->column,
                    id?id->base.end_line:expr->end_line,
                    id?id->base.end_column:expr->end_column);
                if (!m) return expr;
                m->object = expr; m->property = (Node*)id;
                m->computed = 0; m->optional = 1;
                expr = (Node*)m;
            } else {
                parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
                    "expected .name, [expr], or (args) after ?.");
                return expr;
            }
        } else if (parser_check(p, TOK_LPAREN)) {
            int argc = 0;
            Node **args = (Node**)parse_arguments(p, &argc);
            CallExpr *c = (CallExpr*)MK(NODE_CALL, CallExpr, expr->line, expr->column,
                p->current.line, p->current.column);
            if (!c) return expr;
            c->callee = expr; c->args = args; c->n = argc; c->optional = 0;
            expr = (Node*)c;
        } else if (parser_match(p, TOK_LBRACKET)) {
            Node *prop = parse_expression(p, 0);
            parser_expect(p, TOK_RBRACKET, "]");
            MemberExpr *m = (MemberExpr*)MK(NODE_MEMBER, MemberExpr, expr->line, expr->column,
                p->current.line, p->current.column);
            if (!m) return expr;
            m->object = expr; m->property = prop;
            m->computed = 1; m->optional = 0;
            expr = (Node*)m;
        } else if (parser_check(p, TOK_TEMPLATE_HEAD) ||
                   parser_check(p, TOK_TEMPLATE_NO_SUB)) {
            expr = parse_template(p, expr);
        } else {
            break;
        }
    }
    return expr;
}

static Node *parse_primary(Parser *p) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;

    /* ============================================================
     * FAST DISPATCH — one switch on the current token kind.
     * Handles the 9 most common kinds directly (number, string,
     * ident, paren, bracket, brace, template, regex, bigint).
     * Only falls through to the keyword chain if the token is
     * actually a keyword. Same code below, but the compiler emits
     * a jump table for the switch.
     * ============================================================ */
    switch (p->current.kind) {
        case TOK_NUMBER:
        case TOK_BIGINT:
        case TOK_STRING:
        case TOK_REGEX:
        case TOK_TEMPLATE_HEAD:
        case TOK_TEMPLATE_NO_SUB:
        case TOK_IDENT:
        case TOK_LPAREN:
        case TOK_LBRACKET:
        case TOK_LBRACE:
            break;   /* fall through to the sequential chain below */
        case TOK_KEYWORD:
            break;   /* handled by keyword chain below */
        default:
            /* Unknown token → fast-fail with specific error */
            if (p->current.kind == TOK_EOF) {
                parser_error_at_current(p, PARSE_ERR_UNEXPECTED_EOF,
                    "unexpected end of input in expression");
            } else {
                parser_error_at_current(p, PARSE_ERR_UNEXPECTED_TOKEN,
                    "unexpected token in expression");
            }
            return NULL;
    }

    /* literals */
    if (parser_check(p, TOK_NUMBER)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col,
            line, col + p->current.length);
        if (l) {
            l->lit_kind = LIT_NUMBER;
            l->number = p->current.number;
        }
        parser_advance(p);
        return (Node*)l;
    }
    if (parser_check(p, TOK_BIGINT)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col,
            line, col + p->current.length);
        if (l) {
            l->lit_kind = LIT_BIGINT;
            l->bigint_text = dup_range(p->current.start, p->current.length);
        }
        parser_advance(p);
        return (Node*)l;
    }
    if (parser_check(p, TOK_STRING)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col,
            line, col + p->current.length);
        if (l) {
            l->lit_kind = LIT_STRING;
            /* strip quotes, no escape processing yet */
            const char *s = p->current.start;
            int len = p->current.length;
            if (len >= 2) {
                l->string = dup_range(s + 1, len - 2);
            } else {
                l->string = dup_range("", 0);
            }
        }
        parser_advance(p);
        return (Node*)l;
    }
    if (parser_check(p, TOK_REGEX)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col,
            line, col + p->current.length);
        if (l) {
            l->lit_kind = LIT_REGEX;
            l->regex_pattern = dup_range(p->current.start, p->current.length);
            l->regex_flags = dup_range("", 0);
        }
        parser_advance(p);
        return (Node*)l;
    }
    if (parser_check(p, TOK_TEMPLATE_HEAD) ||
        parser_check(p, TOK_TEMPLATE_NO_SUB)) {
        return parse_template(p, NULL);
    }

    /* this */
    if (parser_check_kw(p, KW_THIS)) {
        parser_advance(p);
        return ast_new(NODE_THIS, line, col, line, col);
    }
    if (parser_check_kw(p, KW_IMPORT)) {
        parser_advance(p);
        if (parser_check(p, TOK_DOT)) {
            parser_advance(p);
            if (parser_check(p, TOK_IDENT)) {
                parser_advance(p);
                return ast_new(NODE_IMPORT_META, line, col, line, col);
            }
        }
        /* dynamic import(...) */
        if (parser_check(p, TOK_LPAREN)) {
            parser_advance(p);
            Node *arg = parse_assignment(p, 0);
            parser_expect(p, TOK_RPAREN, ")");
            ImportCall *ic = (ImportCall*)ast_new_sized(NODE_IMPORT_CALL,
                sizeof(ImportCall), line, col, p->current.line, p->current.column);
            if (ic) ic->source = arg;
            return (Node*)ic;
        }
        parser_error_at_current(p, PARSE_ERR_INVALID_MODULE,
            "expected '.' or '(' after import");
        return NULL;
    }
    if (parser_check_kw(p, KW_SUPER)) {
        parser_advance(p);
        return ast_new(NODE_SUPER, line, col, line, col);
    }

    /* true / false / null / undefined */
    if (parser_check_kw(p, KW_TRUE) || parser_check_kw(p, KW_FALSE)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col, line, col);
        if (l) {
            l->lit_kind = LIT_BOOL;
            l->boolean = parser_check_kw(p, KW_TRUE) ? 1 : 0;
        }
        parser_advance(p);
        return (Node*)l;
    }
    if (parser_check_kw(p, KW_UNDEFINED)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col, line, col);
        if (l) l->lit_kind = LIT_UNDEFINED;
        parser_advance(p);
        return (Node*)l;
    }

    if (parser_check_kw(p, KW_NULL)) {
        Literal *l = (Literal*)MK(NODE_LITERAL, Literal, line, col, line, col);
        if (l) l->lit_kind = LIT_NULL;
        parser_advance(p);
        return (Node*)l;
    }

    /* function / class expressions */
    if (parser_check_kw(p, KW_FUNCTION)) {
        return parse_function(p, 0, 0);
    }
    if (parser_check_kw(p, KW_ASYNC)) {
        Token nxt = parser_peek_next(p);
        if (nxt.kind == TOK_KEYWORD && nxt.keyword == KW_FUNCTION) {
            parser_advance(p);
            return parse_function(p, 0, 1);
        }
        if (nxt.kind == TOK_IDENT || nxt.kind == TOK_LPAREN) {
            parser_advance(p);
            if (parser_check(p, TOK_IDENT)) {
                int xl = p->current.line, xc = p->current.column;
                Ident *aid = (Ident*)ast_new_sized(NODE_IDENT, sizeof(Ident),
                    xl, xc, xl, xc + p->current.length);
    aid->slot = -1;
                if (aid) aid->name = dup_range(p->current.start, p->current.length);
                parser_advance(p);
                if (parser_check(p, TOK_ARROW)) {
                    parser_advance(p);
                    FuncNode *f = (FuncNode*)ast_new_sized(NODE_ARROW_FUNC,
                        sizeof(FuncNode), line, col, p->current.line, p->current.column);
                    if (f) {
                        f->is_arrow = 1; f->is_async = 1;
                        Param *pm = (Param*)ast_new_sized(NODE_PARAM, sizeof(Param), xl, xc, xl, xc);
                        if (pm) pm->pattern = (Node*)aid;
                        f->params = (Node**)ast_alloc(sizeof(Node*));
                        f->params[0] = (Node*)pm;
                        f->nparams = 1;
                        if (parser_check(p, TOK_LBRACE)) f->body = parse_block(p);
                        else f->expr_body = parse_assignment(p, 0);
                    }
                    return (Node*)f;
                }
                parser_error_at_current(p, PARSE_ERR_INVALID_ARROW,
                    "expected '=>' after async identifier");
                return (Node*)aid;
            }
            if (parser_check(p, TOK_LPAREN)) {
                parser_advance(p);
                Node **params = (Node**)ast_alloc(sizeof(Node*) * 4);
                int n = 0, cap = 4;
                while (!parser_check(p, TOK_RPAREN) && !parser_check(p, TOK_EOF)) {
                    if (parser_check(p, TOK_COMMA)) break;
                    if (n >= cap) { cap *= 2; Node **b2 = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!b2) break; memcpy(b2, params, sizeof(Node*)*(size_t)n); params = b2; }
                    int pl = p->current.line, pc = p->current.column;
                    Param *pm = (Param*)ast_new_sized(NODE_PARAM, sizeof(Param), pl, pc, pl, pc);
                    if (parser_check(p, TOK_ELLIPSIS)) { parser_advance(p); if (pm) pm->rest = 1; }
                    if (pm) pm->pattern = parse_primary(p);
                    if (parser_match(p, TOK_EQ)) {
                        if (pm) pm->default_value = parse_assignment(p, 0);
                    }
                    params[n++] = (Node*)pm;
                    if (!parser_match(p, TOK_COMMA)) break;
                }
                parser_expect(p, TOK_RPAREN, ")");
                if (parser_check(p, TOK_ARROW)) {
                    parser_advance(p);
                    FuncNode *f = (FuncNode*)ast_new_sized(NODE_ARROW_FUNC,
                        sizeof(FuncNode), line, col,
                        p->current.line, p->current.column);
                    if (f) {
                        f->is_arrow = 1; f->is_async = 1;
                        f->params = params; f->nparams = n;
                        if (parser_check(p, TOK_LBRACE)) f->body = parse_block(p);
                        else f->expr_body = parse_assignment(p, 0);
                    }
                    return (Node*)f;
                }
                parser_error_at_current(p, PARSE_ERR_INVALID_ARROW,
                    "expected '=>' after async (...)");
                return NULL;
            }
        }
        /* bare async identifier */
        Ident *id2 = (Ident*)ast_new_sized(NODE_IDENT, sizeof(Ident),
            line, col, line, col + 5);
    id2->slot = -1;
        if (id2) id2->name = dup_string("async");
        return (Node*)id2;
    }
    if (parser_check_kw(p, KW_CLASS)) {
        return parse_class(p, 0);
    }

    /* identifiers */
    if (parser_check(p, TOK_IDENT)) {
        Ident *id = (Ident*)MK(NODE_IDENT, Ident, line, col,
            line, col + p->current.length);
    id->slot = -1;
        if (id) id->name = dup_range(p->current.start, p->current.length);
        parser_advance(p);

        /* arrow function: IDENT => ... */
        if (parser_check(p, TOK_ARROW)) {
            parser_advance(p);
            FuncNode *f = (FuncNode*)MK(NODE_ARROW_FUNC, FuncNode, line, col, p->current.line, p->current.column);
            if (!f) return (Node*)id;
            f->is_arrow = 1;
            Param *param = (Param*)MK(NODE_PARAM, Param, line, col, line, col + p->current.length);
            if (param) param->pattern = (Node*)id;
            f->params = (Node**)ast_alloc(sizeof(Node*));
            f->params[0] = (Node*)param;
            f->nparams = 1;
            if (parser_check(p, TOK_LBRACE)) {
                f->body = parse_block(p);
            } else {
                f->expr_body = parse_assignment(p, 0);
            }
            return (Node*)f;
        }
        return (Node*)id;
    }

    /* grouping or arrow-params: ( ... ) */
    if (parser_check(p, TOK_LPAREN)) {
        parser_advance(p);
        /* empty parens: () => ... */
        if (parser_check(p, TOK_RPAREN)) {
            parser_advance(p);
            if (parser_check(p, TOK_ARROW)) {
                parser_advance(p);
                FuncNode *f = (FuncNode*)MK(NODE_ARROW_FUNC, FuncNode, line, col, p->current.line, p->current.column);
                if (!f) return NULL;
                f->is_arrow = 1;
                f->params = NULL; f->nparams = 0;
                if (parser_check(p, TOK_LBRACE)) {
                    f->body = parse_block(p);
                } else {
                    f->expr_body = parse_assignment(p, 0);
                }
                return (Node*)f;
            }
            /* empty grouping is an error */
            parser_error_at_current(p, PARSE_ERR_UNEXPECTED_TOKEN,
                "empty parentheses");
            return NULL;
        }

        /* rest param at start: (...args) => ... */
        if (parser_check(p, TOK_ELLIPSIS)) {
            parser_advance(p);
            Node *rest_pat = parse_primary(p);
            Param *rest_pm = (Param*)ast_new_sized(
                NODE_PARAM, sizeof(Param), line, col, line, col);
            if (rest_pm) { rest_pm->pattern = rest_pat; rest_pm->rest = 1; }
            parser_expect(p, TOK_RPAREN, ")");
            if (parser_check(p, TOK_ARROW)) {
                parser_advance(p);
                FuncNode *f = (FuncNode*)ast_new_sized(
                    NODE_ARROW_FUNC, sizeof(FuncNode),
                    line, col, p->current.line, p->current.column);
                if (f) {
                    f->is_arrow = 1;
                    f->params = (Node**)ast_alloc(sizeof(Node*));
                    f->params[0] = (Node*)rest_pm;
                    f->nparams = 1;
                    if (parser_check(p, TOK_LBRACE)) f->body = parse_block(p);
                    else f->expr_body = parse_assignment(p, 0);
                }
                return (Node*)f;
            }
            /* not an arrow -> invalid syntax in this form */
            ParenExpr *pe = (ParenExpr*)ast_new_sized(
                NODE_PAREN, sizeof(ParenExpr), line, col, line, col);
            if (pe) pe->inner = (Node*)rest_pm;
            return (Node*)pe;
        }

        Node *first = parse_assignment(p, 0);
        if (parser_check(p, TOK_COMMA)) {
            /* definitely param list or sequence */
            /* collect as arrow params */
            parser_advance(p);
            Node **items = (Node**)ast_alloc(sizeof(Node*) * 4);
            int n = 0, cap = 4;
            items[n++] = first;
            do {
                if (parser_check(p, TOK_RPAREN)) break;   /* trailing comma */
                if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, items, sizeof(Node*)*(size_t)n); items = big; }
                if (parser_check(p, TOK_ELLIPSIS)) {
                    parser_advance(p);
                    Node *rp = parse_primary(p);
                    Param *rpm = (Param*)ast_new_sized(
                        NODE_PARAM, sizeof(Param), line, col, line, col);
                    if (rpm) { rpm->pattern = rp; rpm->rest = 1; }
                    items[n++] = (Node*)rpm;
                } else {
                    items[n++] = parse_assignment(p, 0);
                }
            } while (parser_match(p, TOK_COMMA));
            parser_expect(p, TOK_RPAREN, ")");
            if (parser_check(p, TOK_ARROW)) {
                parser_advance(p);
                FuncNode *f = (FuncNode*)MK(NODE_ARROW_FUNC, FuncNode, line, col, p->current.line, p->current.column);
                if (!f) return first;
                f->is_arrow = 1;
                f->params = (Node**)ast_alloc(sizeof(Node*) * (size_t)n);
                for (int i = 0; i < n; i++) {
                    Param *pm = (Param*)MK(NODE_PARAM, Param, line, col, line, col);
                    if (pm) pm->pattern = items[i];
                    f->params[i] = (Node*)pm;
                }
                f->nparams = n;
                if (parser_check(p, TOK_LBRACE)) {
                    f->body = parse_block(p);
                } else {
                    f->expr_body = parse_assignment(p, 0);
                }
                return (Node*)f;
            }
            /* sequence expr in parens */
            SequenceExpr *s = (SequenceExpr*)MK(NODE_SEQUENCE, SequenceExpr, line, col, p->current.line, p->current.column);
            if (s) { s->exprs = items; s->n = n; }
            ParenExpr *pe = (ParenExpr*)MK(NODE_PAREN, ParenExpr, line, col, p->current.line, p->current.column);
            if (pe) pe->inner = (Node*)s;
            return (Node*)pe;
        }
        parser_expect(p, TOK_RPAREN, ")");
        if (parser_check(p, TOK_ARROW)) {
            parser_advance(p);
            FuncNode *f = (FuncNode*)MK(NODE_ARROW_FUNC, FuncNode, line, col, p->current.line, p->current.column);
            if (!f) return first;
            f->is_arrow = 1;
            Param *pm = (Param*)MK(NODE_PARAM, Param, line, col, line, col);
            if (pm) pm->pattern = first;
            f->params = (Node**)ast_alloc(sizeof(Node*));
            f->params[0] = (Node*)pm;
            f->nparams = 1;
            if (parser_check(p, TOK_LBRACE)) {
                f->body = parse_block(p);
            } else {
                f->expr_body = parse_assignment(p, 0);
            }
            return (Node*)f;
        }
        ParenExpr *pe = (ParenExpr*)MK(NODE_PAREN, ParenExpr, line, col, p->current.line, p->current.column);
        if (pe) pe->inner = first;
        return (Node*)pe;
    }

    /* array literal */
    if (parser_check(p, TOK_LBRACKET)) {
        return parse_array_literal(p);
    }
    /* object literal */
    if (parser_check(p, TOK_LBRACE)) {
        return parse_object_literal(p);
    }

    /* nothing matched */
    if (parser_check(p, TOK_EOF)) {
        parser_error_at_current(p, PARSE_ERR_UNEXPECTED_EOF,
            "unexpected end of input in expression");
    } else {
        parser_error_at_current(p, PARSE_ERR_UNEXPECTED_TOKEN,
            "unexpected token in expression");
    }
    return NULL;
}

static Node *parse_array_literal(Parser *p) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;
    parser_expect(p, TOK_LBRACKET, "[");
    Node **elems = (Node**)ast_alloc(sizeof(Node*) * 8);
    int n = 0, cap = 8;
    while (!parser_check(p, TOK_RBRACKET) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, elems, sizeof(Node*)*(size_t)n); elems = big; }
        if (parser_check(p, TOK_COMMA)) {
            /* sparse: hole */
            elems[n++] = NULL;
            parser_advance(p);
            continue;
        }
        if (parser_match(p, TOK_ELLIPSIS)) {
            SpreadExpr *s = (SpreadExpr*)MK(NODE_SPREAD, SpreadExpr, p->current.line, p->current.column, p->current.line, p->current.column);
            if (s) s->arg = parse_assignment(p, 0);
            elems[n++] = (Node*)s;
        } else {
            elems[n++] = parse_assignment(p, 0);
        }
        if (!parser_match(p, TOK_COMMA)) break;
    }
    parser_expect(p, TOK_RBRACKET, "]");
    ArrayExpr *a = (ArrayExpr*)MK(NODE_ARRAY, ArrayExpr, line, col,
        p->current.line, p->current.column);
    if (!a) return NULL;
    a->elems = elems; a->n = n;
    return (Node*)a;
}

static Node *parse_object_literal(Parser *p) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;
    parser_expect(p, TOK_LBRACE, "{");
    Node **props = (Node**)ast_alloc(sizeof(Node*) * 8);
    int n = 0, cap = 8;
    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, props, sizeof(Node*)*(size_t)n); props = big; }

        int is_async = 0, is_gen = 0, is_getter = 0, is_setter = 0;
        if (parser_check_kw(p, KW_ASYNC) && parser_peek_next(p).kind == TOK_IDENT) {
            /* async method */
            is_async = 1;
            parser_advance(p);
        } else if (parser_check_kw(p, KW_GET) && parser_peek_next(p).kind == TOK_IDENT) {
            is_getter = 1;
            parser_advance(p);
        } else if (parser_check_kw(p, KW_SET) && parser_peek_next(p).kind == TOK_IDENT) {
            is_setter = 1;
            parser_advance(p);
        }
        if (parser_check(p, TOK_STAR)) {
            is_gen = 1;
            parser_advance(p);
        }
        Property *prop = (Property*)MK(NODE_PROPERTY, Property, p->current.line, p->current.column, p->current.line, p->current.column);
        if (!prop) { parser_advance(p); continue; }

        /* spread */
        if (parser_match(p, TOK_ELLIPSIS)) {
            SpreadExpr *s = (SpreadExpr*)MK(NODE_SPREAD, SpreadExpr, p->current.line, p->current.column, p->current.line, p->current.column);
            if (s) s->arg = parse_assignment(p, 0);
            props[n++] = (Node*)s;
            if (!parser_match(p, TOK_COMMA)) break;
            continue;
        }

        prop->kind = PROP_INIT;

        /* key: ident, keyword-as-ident, string, number, or [computed] */
        if (parser_match(p, TOK_LBRACKET)) {
            prop->computed = 1;
            prop->key = parse_assignment(p, 0);
            parser_expect(p, TOK_RBRACKET, "]");
        } else if (parser_check(p, TOK_STRING)) {
            Literal *l = (Literal*)MK(NODE_LITERAL, Literal, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
            if (l) { l->lit_kind = LIT_STRING; l->string = dup_range(p->current.start+1, p->current.length-2); }
            prop->key = (Node*)l;
            parser_advance(p);
        } else if (parser_check(p, TOK_NUMBER)) {
            Literal *l = (Literal*)MK(NODE_LITERAL, Literal, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
            if (l) { l->lit_kind = LIT_NUMBER; l->number = p->current.number; }
            prop->key = (Node*)l;
            parser_advance(p);
        } else if (parser_check(p, TOK_IDENT) || parser_check(p, TOK_KEYWORD)) {
            Ident *id = (Ident*)MK(NODE_IDENT, Ident, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
    id->slot = -1;
            if (id) id->name = dup_range(p->current.start, p->current.length);
            prop->key = (Node*)id;
            parser_advance(p);
        } else {
            parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN, "expected property key");
            parser_synchronize(p);
            break;
        }

        if (parser_match(p, TOK_COLON)) {
            prop->value = parse_assignment(p, 0);
        } else if (parser_match(p, TOK_EQ)) {
            /* destructuring default: { a = 1 } */
            Node *def = parse_assignment(p, 0);
            AssignPattern *ap = (AssignPattern*)ast_new_sized(
                NODE_ASSIGN_PATTERN, sizeof(AssignPattern),
                prop->base.line, prop->base.column,
                p->current.line, p->current.column);
            if (ap) { ap->target = prop->key; ap->default_value = def; }
            prop->value = (Node*)ap;
            prop->shorthand = 1;
        } else if (parser_check(p, TOK_LPAREN)) {
            /* method shorthand */
            prop->kind = is_getter ? PROP_GET : is_setter ? PROP_SET : PROP_METHOD;
            if (is_async) prop->is_async = 1;
            if (is_gen) prop->is_generator = 1;
            int pn = 0;
            Node *param_list = parse_params(p, &pn);
            FuncNode *f = (FuncNode*)MK(NODE_FUNC_EXPR, FuncNode, prop->base.line, prop->base.column, p->current.line, p->current.column);
            if (f) {
                f->params = ((ParamList*)param_list)->params;
                f->nparams = ((ParamList*)param_list)->n;
                f->is_async = is_async;
                f->is_generator = is_gen;
                if (parser_check(p, TOK_LBRACE)) f->body = parse_block(p);
            }
            prop->value = (Node*)f;
        } else if (parser_check(p, TOK_COMMA) || parser_check(p, TOK_RBRACE)) {
            /* shorthand { x } */
            prop->shorthand = 1;
            prop->value = prop->key;
        } else {
            parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
                "expected ':', '(', ',', or '}'");
            parser_synchronize(p);
            break;
        }

        props[n++] = (Node*)prop;
        if (!parser_match(p, TOK_COMMA)) break;
    }
    parser_expect(p, TOK_RBRACE, "}");
    ObjectExpr *o = (ObjectExpr*)MK(NODE_OBJECT, ObjectExpr, line, col,
        p->current.line, p->current.column);
    if (!o) return NULL;
    o->props = props; o->n = n;
    return (Node*)o;
}

static Node *parse_template(Parser *p, Node *tag) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;
    TemplateNode *t = (TemplateNode*)MK(NODE_TEMPLATE, TemplateNode, line, col, line, col);
    if (!t) return tag;
    t->quasis = (Node**)ast_alloc(sizeof(Node*) * 4);
    t->exprs  = (Node**)ast_alloc(sizeof(Node*) * 4);
    t->nq = 0; t->ne = 0;
    int capq = 4, cape = 4;

    if (parser_check(p, TOK_TEMPLATE_NO_SUB)) {
        TemplateElement *e = (TemplateElement*)MK(NODE_TEMPLATE_ELEMENT, TemplateElement, line, col, line, col);
        if (e) { e->cooked = dup_range(p->current.start+1, p->current.length-2); e->raw = dup_range(p->current.start, p->current.length); }
        t->quasis[t->nq++] = (Node*)e;
        parser_advance(p);
        t->is_tagged = tag ? 1 : 0;
        t->tag = tag;
        return (Node*)t;
    }

    /* TOK_TEMPLATE_HEAD - strip leading backtick and trailing dollar-brace */
    {
        const char *s = p->current.start;
        int len = p->current.length;
        int skip_lead = 1;
        int skip_tail = 2;
        if (len < skip_lead + skip_tail) { skip_lead = 0; skip_tail = 0; }
        TemplateElement *e = (TemplateElement*)MK(NODE_TEMPLATE_ELEMENT, TemplateElement, line, col, line, col);
        if (e) {
            e->cooked = dup_range(s + skip_lead, len - skip_lead - skip_tail);
            e->raw    = dup_range(s, len);
        }
        t->quasis[t->nq++] = (Node*)e;
        parser_advance(p);
    }

    for (;;) {
        if (t->ne >= cape) { cape *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cape); if (big) { memcpy(big, t->exprs, sizeof(Node*)*(size_t)t->ne); t->exprs = big; } }
        t->exprs[t->ne++] = parse_expression(p, 0);
        /* The lexer consumes `}` that closes `${...}` and immediately
         * resumes the template. So current token should be TEMPLATE_MIDDLE
         * or TEMPLATE_TAIL. But if the expression parser consumed the
         * RBRACE (some inner parser state), handle it as a fallback. */
        if (parser_check(p, TOK_RBRACE)) {
            parser_advance(p);
        }
        if (parser_check(p, TOK_TEMPLATE_MIDDLE) ||
            parser_check(p, TOK_TEMPLATE_TAIL)) {
            int is_tail = (p->current.kind == TOK_TEMPLATE_TAIL);
            const char *s = p->current.start;
            int len = p->current.length;
            int skip_lead = 0;   /* lexer already consumed the } */
            int skip_tail = is_tail ? 1 : 2;
            if (len < skip_lead + skip_tail) { skip_lead = 0; skip_tail = 0; }
            TemplateElement *e = (TemplateElement*)MK(NODE_TEMPLATE_ELEMENT, TemplateElement, p->current.line, p->current.column, p->current.line, p->current.column + len);
            if (e) {
                e->cooked = dup_range(s + skip_lead, len - skip_lead - skip_tail);
                e->raw    = dup_range(s, len);
            }
            if (t->nq >= capq) { capq *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)capq); if (big) { memcpy(big, t->quasis, sizeof(Node*)*(size_t)t->nq); t->quasis = big; } }
            t->quasis[t->nq++] = (Node*)e;
            parser_advance(p);
            if (is_tail) break;
        } else {
            parser_error_at_current(p, PARSE_ERR_UNEXPECTED_TOKEN,
                "expected template segment");
            break;
        }
    }
    t->is_tagged = tag ? 1 : 0;
    t->tag = tag;
    return (Node*)t;
}

static char *dup_string(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *out = (char*)ast_alloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n + 1);
    return out;
}

/* ---- statements ---- */
static Node *parse_block(Parser *p) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;
    parser_expect(p, TOK_LBRACE, "{");
    Node **stmts = (Node**)ast_alloc(sizeof(Node*) * 8);
    int n = 0, cap = 8;
    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, stmts, sizeof(Node*)*(size_t)n); stmts = big; }
        Node *s = parse_statement(p);
        if (s) stmts[n++] = s;
        else {
            if (p->fatal) break;
            parser_synchronize(p);
        }
    }
    parser_expect(p, TOK_RBRACE, "}");
    Block *b = (Block*)MK(NODE_BLOCK, Block, line, col,
        p->current.line, p->current.column);
    if (!b) return NULL;
    b->stmts = stmts; b->n = n;
    return (Node*)b;
}

static Node *parse_var_decl(Parser *p, int kind) {
    int line = p->current.line, col = p->current.column;
    parser_advance(p);   /* var / let / const */
    Node **decls = (Node**)ast_alloc(sizeof(Node*) * 4);
    int n = 0, cap = 4;
    for (;;) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, decls, sizeof(Node*)*(size_t)n); decls = big; }
        int dline = p->current.line, dcol = p->current.column;
        /* Parse the declaration target.
         *  - Identifier:      let x
         *  - Object pattern:  let { a, b }      (defaults handled inside)
         *  - Array pattern:   let [ a, b ]
         * Then an optional '= init'. */
        Node *id = NULL;
        if (parser_check(p, TOK_LBRACE)) {
            id = parse_object_literal(p);
        } else if (parser_check(p, TOK_LBRACKET)) {
            id = parse_array_literal(p);
        } else {
            id = parse_primary(p);
        }

        Node *init = NULL;
        if (parser_match(p, TOK_EQ)) {
            init = parse_assignment(p, 0);
        }
        VarDeclarator *d = (VarDeclarator*)MK(NODE_VAR_DECLARATOR, VarDeclarator, dline, dcol, p->current.line, p->current.column);
        if (d) { d->id = id; d->init = init; }
        decls[n++] = (Node*)d;
        if (!parser_match(p, TOK_COMMA)) break;
    }
    VarDecl *v = (VarDecl*)MK(NODE_VAR_DECL, VarDecl, line, col,
        p->current.line, p->current.column);
    if (!v) return NULL;
    v->kind = (VarDeclKind)kind;
    v->decls = (VarDeclarator**)decls; v->n = n;
    return (Node*)v;
}

static Node *parse_params(Parser *p, int *out_n) {
    parser_expect(p, TOK_LPAREN, "(");
    Node **params = (Node**)ast_alloc(sizeof(Node*) * 4);
    int n = 0, cap = 4;
    while (!parser_check(p, TOK_RPAREN) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, params, sizeof(Node*)*(size_t)n); params = big; }
        int pl = p->current.line, pc = p->current.column;
        Param *pm = (Param*)MK(NODE_PARAM, Param, pl, pc, pl, pc);
        if (!pm) { parser_advance(p); continue; }
        if (parser_match(p, TOK_ELLIPSIS)) pm->rest = 1;
        pm->pattern = parse_primary(p);
        if (parser_match(p, TOK_EQ)) {
            pm->default_value = parse_assignment(p, 0);
        }
        params[n++] = (Node*)pm;
        if (!parser_match(p, TOK_COMMA)) break;
    }
    parser_expect(p, TOK_RPAREN, ")");
    ParamList *pl = (ParamList*)MK(NODE_PARAM_LIST, ParamList, p->current.line, p->current.column,
        p->current.line, p->current.column);
    if (!pl) { *out_n = 0; return NULL; }
    pl->params = params; pl->n = n;
    *out_n = n;
    return (Node*)pl;
}

static Node *parse_function(Parser *p, int is_decl, int is_async) {
    int line = p->current.line, col = p->current.column;
    parser_advance(p);   /* function */
    int is_gen = 0;
    if (parser_match(p, TOK_STAR)) is_gen = 1;

    char *name = NULL;
    if (parser_check(p, TOK_IDENT)) {
        name = dup_range(p->current.start, p->current.length);
        parser_advance(p);
    } else if (is_decl) {
        parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
            "function declaration requires a name");
    }

    int pn = 0;
    Node *param_list = parse_params(p, &pn);
    FuncNode *f = (FuncNode*)ast_new_sized(
        is_decl ? NODE_FUNC_DECL : NODE_FUNC_EXPR,
        sizeof(FuncNode),
        line, col, p->current.line, p->current.column);
    if (!f) return NULL;
    f->name = name;
    f->is_async = is_async;
    f->is_generator = is_gen;
    f->nparams = pn;
    f->params = param_list ? ((ParamList*)param_list)->params : NULL;
    if (parser_check(p, TOK_LBRACE)) {
        f->body = parse_block(p);
    }
    /* Post-parse pass: assign local slot numbers to every Ident inside
     * this function body whose name matches a param or a top-level var/let/const. */
    scope_assign((Node *)f);
    return (Node*)f;
}

static Node *parse_class(Parser *p, int is_decl) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;
    parser_advance(p);   /* class */
    char *name = NULL;
    if (parser_check(p, TOK_IDENT)) {
        name = dup_range(p->current.start, p->current.length);
        parser_advance(p);
    } else if (is_decl) {
        parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
            "class declaration requires a name");
    }
    Node *super_class = NULL;
    if (parser_match_kw(p, KW_EXTENDS)) {
        super_class = parse_lhs_expr(p);
    }
    parser_expect(p, TOK_LBRACE, "{");

    Node **body = (Node**)ast_alloc(sizeof(Node*) * 4);
    int n = 0, cap = 4;
    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, body, sizeof(Node*)*(size_t)n); body = big; }
        if (parser_match(p, TOK_SEMICOLON)) continue;

        int mline = p->current.line, mcol = p->current.column;
        int is_static = 0, is_async = 0, is_gen = 0, computed = 0;
        if (parser_check_kw(p, KW_STATIC) &&
            !parser_check(p, TOK_LPAREN)) {
            parser_advance(p);
            is_static = 1;
        }
        if (parser_check_kw(p, KW_ASYNC) && !parser_check(p, TOK_LPAREN)) {
            parser_advance(p);
            is_async = 1;
        }
        if (parser_match(p, TOK_STAR)) is_gen = 1;

        Node *key = NULL;
        if (parser_match(p, TOK_LBRACKET)) {
            computed = 1;
            key = parse_assignment(p, 0);
            parser_expect(p, TOK_RBRACKET, "]");
        } else if (parser_check(p, TOK_STRING)) {
            Literal *l = (Literal*)MK(NODE_LITERAL, Literal, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
            if (l) { l->lit_kind = LIT_STRING; l->string = dup_range(p->current.start+1, p->current.length-2); }
            key = (Node*)l;
            parser_advance(p);
        } else if (parser_check(p, TOK_NUMBER)) {
            Literal *l = (Literal*)MK(NODE_LITERAL, Literal, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
            if (l) { l->lit_kind = LIT_NUMBER; l->number = p->current.number; }
            key = (Node*)l;
            parser_advance(p);
        } else if (parser_check(p, TOK_IDENT) || parser_check(p, TOK_KEYWORD)) {
            Ident *id = (Ident*)MK(NODE_IDENT, Ident, p->current.line, p->current.column, p->current.line, p->current.column + p->current.length);
    id->slot = -1;
            if (id) id->name = dup_range(p->current.start, p->current.length);
            key = (Node*)id;
            parser_advance(p);
        } else if (parser_check(p, TOK_LPAREN)) {
            /* constructor or method without name? */
            Ident *id = (Ident*)MK(NODE_IDENT, Ident, mline, mcol, mline, mcol);
    id->slot = -1;
            if (id) id->name = dup_string("constructor");
            key = (Node*)id;
        } else {
            parser_error_at_current(p, PARSE_ERR_INVALID_METHOD,
                "invalid class member");
            parser_synchronize(p);
            continue;
        }

        if (parser_check(p, TOK_LPAREN)) {
            int pn = 0;
            Node *pl = parse_params(p, &pn);
            FuncNode *fn = (FuncNode*)MK(NODE_FUNC_EXPR, FuncNode, mline, mcol, p->current.line, p->current.column);
            if (fn) {
                fn->is_async = is_async;
                fn->is_generator = is_gen;
                fn->params = pl ? ((ParamList*)pl)->params : NULL;
                fn->nparams = pn;
                if (parser_check(p, TOK_LBRACE)) fn->body = parse_block(p);
            }
            MethodDef *md = (MethodDef*)MK(NODE_METHOD_DEF, MethodDef, mline, mcol, p->current.line, p->current.column);
            if (md) {
                md->kind = PROP_METHOD;
                md->is_static = is_static;
                md->is_async = is_async;
                md->is_generator = is_gen;
                md->key = key;
                md->computed = computed;
                md->value = fn;
            }
            body[n++] = (Node*)md;
        } else {
            /* property */
            Node *init = NULL;
            if (parser_match(p, TOK_EQ)) init = parse_assignment(p, 0);
            if (!parser_match(p, TOK_SEMICOLON)) {
                /* ASI */
            }
            MethodDef *pd = (MethodDef*)MK(NODE_PROP_DEF, MethodDef, mline, mcol, p->current.line, p->current.column);
            if (pd) {
                pd->kind = PROP_INIT;
                pd->is_static = is_static;
                pd->key = key;
                pd->computed = computed;
                pd->init = init;
            }
            body[n++] = (Node*)pd;
        }
    }
    parser_expect(p, TOK_RBRACE, "}");

    ClassNode *cl = (ClassNode*)ast_new_sized(
        is_decl ? NODE_CLASS_DECL : NODE_CLASS_EXPR,
        sizeof(ClassNode),
        line, col, p->current.line, p->current.column);
    if (!cl) return NULL;
    cl->name = name;
    cl->super_class = super_class;
    cl->body = body;
    cl->nbody = n;
    return (Node*)cl;
}

/* ---- ASI: consume a semicolon, or accept if a newline came before the next token */
static int consume_semicolon(Parser *p) {
    if (parser_match(p, TOK_SEMICOLON)) return 1;
    /* ASI: next token is } or EOF -> ok */
    if (parser_check(p, TOK_RBRACE) || parser_check(p, TOK_EOF)) return 1;
    /* newline before next token? — we don't track that in Token; accept anyway to be lenient */
    return 0;
}

/* === Statement handlers (extracted from parse_statement) === */

static Node *parse_if_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    parser_expect(p, TOK_LPAREN, "(");
    Node *test = parse_expression(p, 0);
    parser_expect(p, TOK_RPAREN, ")");
    Node *cons = parse_statement(p);
    Node *alt = NULL;
    if (parser_match_kw(p, KW_ELSE)) alt = parse_statement(p);
    IfStmt *s = (IfStmt*)MK(NODE_IF, IfStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->test = test; s->cons = cons; s->alt = alt;
    return (Node*)s;
}

static Node *parse_while_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    parser_expect(p, TOK_LPAREN, "(");
    Node *test = parse_expression(p, 0);
    parser_expect(p, TOK_RPAREN, ")");
    int saved = p->in_loop; p->in_loop = 1;
    Node *body = parse_statement(p);
    p->in_loop = saved;
    WhileStmt *s = (WhileStmt*)MK(NODE_WHILE, WhileStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->test = test; s->body = body;
    return (Node*)s;
}

static Node *parse_do_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    int saved = p->in_loop; p->in_loop = 1;
    Node *body = parse_statement(p);
    p->in_loop = saved;
    parser_match_kw(p, KW_WHILE);
    parser_expect(p, TOK_LPAREN, "(");
    Node *test = parse_expression(p, 0);
    parser_expect(p, TOK_RPAREN, ")");
    consume_semicolon(p);
    DoWhileStmt *s = (DoWhileStmt*)MK(NODE_DO_WHILE, DoWhileStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->body = body; s->test = test;
    return (Node*)s;
}

static Node *parse_for_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    int for_await = 0;
    if (parser_check_kw(p, KW_AWAIT)) {
        for_await = 1;
        parser_advance(p);
    }
    parser_expect(p, TOK_LPAREN, "(");
    Node *init = NULL;
    if (!parser_check(p, TOK_SEMICOLON)) {
        if (parser_check_kw(p, KW_VAR) || parser_check_kw(p, KW_LET) || parser_check_kw(p, KW_CONST)) {
            int kind = parser_check_kw(p, KW_VAR) ? VARDECL_VAR :
                       parser_check_kw(p, KW_LET) ? VARDECL_LET : VARDECL_CONST;
            init = parse_var_decl(p, kind);
        } else {
            init = parse_expression(p, 1);
        }
    }
    if (parser_check_kw(p, KW_IN) || parser_check_kw(p, KW_OF)) {
        int is_of = parser_check_kw(p, KW_OF);
        parser_advance(p);
        Node *right = is_of ? parse_assignment(p, 0) : parse_expression(p, 0);
        parser_expect(p, TOK_RPAREN, ")");
        int saved = p->in_loop; p->in_loop = 1;
        Node *body = parse_statement(p);
        p->in_loop = saved;
        ForInOfStmt *s = (ForInOfStmt*)ast_new(is_of ? NODE_FOR_OF : NODE_FOR_IN,
            line, col, p->current.line, p->current.column);
        if (!s) return NULL;
        s->left = init;
        s->right = right;
        s->body = body;
        s->is_await = for_await;
        return (Node*)s;
    }
    parser_expect(p, TOK_SEMICOLON, ";");
    Node *test = NULL;
    if (!parser_check(p, TOK_SEMICOLON)) test = parse_expression(p, 0);
    parser_expect(p, TOK_SEMICOLON, ";");
    Node *update = NULL;
    if (!parser_check(p, TOK_RPAREN)) update = parse_expression(p, 0);
    parser_expect(p, TOK_RPAREN, ")");
    int saved = p->in_loop; p->in_loop = 1;
    Node *body = parse_statement(p);
    p->in_loop = saved;
    ForStmt *s = (ForStmt*)MK(NODE_FOR, ForStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->init = init; s->test = test; s->update = update; s->body = body;
    return (Node*)s;
}

static Node *parse_return_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    Node *arg = NULL;
    if (!parser_check(p, TOK_SEMICOLON) && !parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
        arg = parse_expression(p, 0);
    }
    consume_semicolon(p);
    ReturnStmt *s = (ReturnStmt*)MK(NODE_RETURN, ReturnStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->arg = arg;
    return (Node*)s;
}

static Node *parse_break_continue_stmt(Parser *p, int line, int col) {

    int is_brk = parser_check_kw(p, KW_BREAK);
    parser_advance(p);
    char *label = NULL;
    if (parser_check(p, TOK_IDENT)) {
        label = dup_range(p->current.start, p->current.length);
        parser_advance(p);
    }
    consume_semicolon(p);
    Node *s = ast_new(is_brk ? NODE_BREAK : NODE_CONTINUE, line, col, p->current.line, p->current.column);
    if (s && is_brk) ((BreakStmt*)s)->label = label;
    if (s && !is_brk) ((ContinueStmt*)s)->label = label;
    return s;
}

static Node *parse_throw_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    Node *arg = parse_expression(p, 0);
    consume_semicolon(p);
    ThrowStmt *s = (ThrowStmt*)MK(NODE_THROW, ThrowStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->arg = arg;
    return (Node*)s;
}

static Node *parse_try_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    Node *block = parse_block(p);
    Node *handler = NULL;
    Node *finalizer = NULL;
    if (parser_check_kw(p, KW_CATCH)) {
        parser_advance(p);
        Node *param = NULL;
        if (parser_match(p, TOK_LPAREN)) {
            param = parse_primary(p);
            parser_expect(p, TOK_RPAREN, ")");
        }
        Node *cbody = parse_block(p);
        CatchClause *cc = (CatchClause*)MK(NODE_CATCH, CatchClause, p->current.line, p->current.column,
            p->current.line, p->current.column);
        if (cc) { cc->param = param; cc->body = cbody; }
        handler = (Node*)cc;
    }
    if (parser_match_kw(p, KW_FINALLY)) {
        Node *fbody = parse_block(p);
        struct FinallyNode { Node base; Node *block; };
        struct FinallyNode *fin = (struct FinallyNode*)ast_new_sized(
            NODE_FINALLY, sizeof(struct FinallyNode),
            line, col, p->current.line, p->current.column);
        if (fin) fin->block = fbody;
        finalizer = (Node*)fin;
    }
    if (!handler && !finalizer) {
        parser_error_at_current(p, PARSE_ERR_INVALID_TRY,
            "try requires catch or finally");
    }
    TryStmt *s = (TryStmt*)MK(NODE_TRY, TryStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->block = block; s->handler = handler; s->finalizer = finalizer;
    return (Node*)s;
}

static Node *parse_switch_stmt(Parser *p, int line, int col) {

    parser_advance(p);
    parser_expect(p, TOK_LPAREN, "(");
    Node *test = parse_expression(p, 0);
    parser_expect(p, TOK_RPAREN, ")");
    parser_expect(p, TOK_LBRACE, "{");
    Node **cases = (Node**)ast_alloc(sizeof(Node*) * 4);
    int n = 0, cap = 4;
    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) break; memcpy(big, cases, sizeof(Node*)*(size_t)n); cases = big; }
        SwitchCase *sc = (SwitchCase*)MK(NODE_SWITCH_CASE, SwitchCase, p->current.line, p->current.column,
            p->current.line, p->current.column);
        if (!sc) break;
        if (parser_match_kw(p, KW_CASE)) {
            sc->test = parse_expression(p, 0);
            parser_expect(p, TOK_COLON, ":");
        } else if (parser_match_kw(p, KW_DEFAULT)) {
            sc->is_default = 1;
            parser_expect(p, TOK_COLON, ":");
        } else {
            parser_error_at_current(p, PARSE_ERR_EXPECTED_TOKEN,
                "expected case or default");
            break;
        }
        Node **stmts = (Node**)ast_alloc(sizeof(Node*) * 4);
        int sn = 0, scap = 4;
        while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF) &&
               !parser_check_kw(p, KW_CASE) && !parser_check_kw(p, KW_DEFAULT)) {
            if (sn >= scap) { scap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)scap); if (!big) break; memcpy(big, stmts, sizeof(Node*)*(size_t)sn); stmts = big; }
            Node *s = parse_statement(p);
            if (s) stmts[sn++] = s;
            else { if (p->fatal) break; parser_synchronize(p); }
        }
        sc->body = stmts; sc->n = sn;
        cases[n++] = (Node*)sc;
    }
    parser_expect(p, TOK_RBRACE, "}");
    SwitchStmt *s = (SwitchStmt*)MK(NODE_SWITCH, SwitchStmt, line, col,
        p->current.line, p->current.column);
    if (!s) return NULL;
    s->test = test; s->cases = cases; s->n = n;
    return (Node*)s;
}

static Node *parse_statement(Parser *p) {
    DEPTH_ENTER(p);
    int line = p->current.line, col = p->current.column;

    /* FAST PATH: tokens that are not keywords. Covers most minified code. */
    if (p->current.kind != TOK_KEYWORD) {
        if (p->current.kind == TOK_EOF) return NULL;
        if (p->current.kind == TOK_SEMICOLON) {
            parser_advance(p);
            return ast_new(NODE_EMPTY_STMT, line, col, line, col);
        }
        if (p->current.kind == TOK_LBRACE) return parse_block(p);
        if (p->current.kind == TOK_IDENT) {
            Token nxt = parser_peek_next(p);
            if (nxt.kind == TOK_COLON) {
                char *label = dup_range(p->current.start, p->current.length);
                parser_advance(p);
                parser_advance(p);
                Node *body = parse_statement(p);
                LabeledStmt *ls = (LabeledStmt*)ast_new_sized(
                    NODE_LABELED, sizeof(LabeledStmt),
                    line, col,
                    body ? body->end_line : line,
                    body ? body->end_column : col);
                if (ls) { ls->label = label; ls->body = body; }
                return (Node*)ls;
            }
        }
        goto expr_stmt;
    }

    /* KEYWORD DISPATCH: one jump to the handler. */
    switch (p->current.keyword) {
    case KW_VAR:      return parse_var_decl(p, VARDECL_VAR);
    case KW_LET:      return parse_var_decl(p, VARDECL_LET);
    case KW_CONST:    return parse_var_decl(p, VARDECL_CONST);
    case KW_FUNCTION: return parse_function(p, 1, 0);
    case KW_CLASS:    return parse_class(p, 1);
    case KW_IF:       return parse_if_stmt(p, line, col);
    case KW_WHILE:    return parse_while_stmt(p, line, col);
    case KW_DO:       return parse_do_stmt(p, line, col);
    case KW_FOR:      return parse_for_stmt(p, line, col);
    case KW_RETURN:   return parse_return_stmt(p, line, col);
    case KW_BREAK:
    case KW_CONTINUE: return parse_break_continue_stmt(p, line, col);
    case KW_THROW:    return parse_throw_stmt(p, line, col);
    case KW_TRY:      return parse_try_stmt(p, line, col);
    case KW_SWITCH:   return parse_switch_stmt(p, line, col);
    case KW_ASYNC: {
        Token nxt = parser_peek_next(p);
        if (nxt.kind == TOK_KEYWORD && nxt.keyword == KW_FUNCTION) {
            parser_advance(p);
            return parse_function(p, 1, 1);
        }
        /* fall through to expression statement (async identifier) */
        goto expr_stmt;
    }
    default:
        goto expr_stmt;
    }

expr_stmt:
    {
        Node *expr = parse_expression(p, 0);
        if (!expr) return NULL;
        consume_semicolon(p);
        ExprStmt *s = (ExprStmt*)MK(NODE_EXPR_STMT, ExprStmt, expr->line, expr->column,
            p->current.line, p->current.column);
        if (!s) return NULL;
        s->expr = expr;
        return (Node*)s;
    }
}

static Node *parse_program(Parser *p) {
    int line = 1, col = 1;
    Node **stmts = (Node**)ast_alloc(sizeof(Node*) * 8);
    int n = 0, cap = 8;
    while (!parser_check(p, TOK_EOF) && !p->fatal) {
        if (n >= cap) { cap *= 2; Node **big = (Node**)ast_alloc(sizeof(Node*)*(size_t)cap); if (!big) { p->fatal = 1; break; } memcpy(big, stmts, sizeof(Node*)*(size_t)n); stmts = big; }
        Node *s = parse_statement(p);
        if (s) stmts[n++] = s;
        else {
            if (p->fatal) break;
            /* if we didn't advance, force progress */
            if (p->nerrors > 0) parser_synchronize(p);
            else break;   /* nothing happened — bail to avoid infinite loop */
        }
    }
    Program *prog = (Program*)MK(NODE_PROGRAM, Program, line, col,
        p->current.line, p->current.column);
    if (!prog) return NULL;
    prog->stmts = stmts;
    prog->n = n;
    return (Node*)prog;
}
