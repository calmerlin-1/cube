/* flywheel/include/ast.h
 *
 * AST for JavaScript. Every node carries a source span.
 * Design: base struct + per-kind struct. Cast by kind.
 * Full ES2023 node coverage — no placeholders, no "v2 adds X".
 */

#ifndef FLYWHEEL_AST_H
#define FLYWHEEL_AST_H

#include <stddef.h>
#include <stdint.h>

typedef struct Node Node;

typedef enum {
    /* --- top --- */
    NODE_PROGRAM,
    NODE_EMPTY_STMT,
    NODE_BLOCK,
    NODE_EXPR_STMT,

    /* --- declarations --- */
    NODE_VAR_DECL,          /* kind: var/let/const, declarators[] */
    NODE_VAR_DECLARATOR,    /* id (pattern or ident), init */
    NODE_FUNC_DECL,
    NODE_FUNC_EXPR,
    NODE_ARROW_FUNC,
    NODE_CLASS_DECL,
    NODE_CLASS_EXPR,
    NODE_CLASS_BODY,
    NODE_METHOD_DEF,
    NODE_PROP_DEF,
    NODE_STATIC_BLOCK,

    /* --- statements --- */
    NODE_IF, NODE_FOR, NODE_FOR_IN, NODE_FOR_OF,
    NODE_WHILE, NODE_DO_WHILE,
    NODE_SWITCH, NODE_SWITCH_CASE,
    NODE_RETURN, NODE_BREAK, NODE_CONTINUE,
    NODE_THROW, NODE_TRY, NODE_CATCH, NODE_FINALLY,
    NODE_LABELED, NODE_WITH, NODE_DEBUGGER,

    /* --- expressions --- */
    NODE_IDENT,
    NODE_LITERAL,           /* numbers, strings, bool, null, undefined, regex, bigint */
    NODE_TEMPLATE,
    NODE_TEMPLATE_ELEMENT,
    NODE_TAGGED_TEMPLATE,
    NODE_ARRAY,
    NODE_OBJECT,
    NODE_PROPERTY,
    NODE_MEMBER,            /* obj.key or obj[key] or obj?.key */
    NODE_CALL,
    NODE_NEW,
    NODE_UNARY,
    NODE_UPDATE,
    NODE_BINARY,
    NODE_LOGICAL,           /* && || ?? */
    NODE_ASSIGN,
    NODE_CONDITIONAL,
    NODE_SEQUENCE,
    NODE_YIELD,
    NODE_AWAIT,
    NODE_SPREAD,
    NODE_NEW_TARGET,
    NODE_IMPORT_META,
    NODE_SUPER,
    NODE_THIS,
    NODE_PAREN,             /* parenthesized — kept for round-trip fidelity */

    /* --- patterns (destructuring) --- */
    NODE_ARRAY_PATTERN,
    NODE_OBJECT_PATTERN,
    NODE_ASSIGN_PATTERN,    /* { a = 1 } */
    NODE_REST_ELEMENT,      /* ...rest */

    /* --- functions & params --- */
    NODE_PARAM,             /* name, default, rest */
    NODE_PARAM_LIST,

    /* --- modules --- */
    NODE_IMPORT_DECL,
    NODE_IMPORT_SPEC,
    NODE_EXPORT_DECL,
    NODE_EXPORT_SPEC,
    NODE_EXPORT_DEFAULT,
    NODE_IMPORT_CALL,       /* dynamic import() */

    NODE_MAX
} NodeKind;

/* ---------- operators ---------- */
typedef enum {
    BINOP_ADD, BINOP_SUB, BINOP_MUL, BINOP_DIV, BINOP_MOD, BINOP_POW,
    BINOP_LT, BINOP_GT, BINOP_LE, BINOP_GE,
    BINOP_EQ, BINOP_NEQ, BINOP_SEQ, BINOP_SNEQ,
    BINOP_BITAND, BINOP_BITOR, BINOP_BITXOR,
    BINOP_LSHIFT, BINOP_RSHIFT, BINOP_URSHIFT,
    BINOP_IN, BINOP_INSTANCEOF,
} BinaryOp;

typedef enum {
    LOGOP_AND, LOGOP_OR, LOGOP_NULLISH,
} LogicalOp;

typedef enum {
    UNOP_PLUS, UNOP_MINUS, UNOP_NOT, UNOP_BITNOT,
    UNOP_TYPEOF, UNOP_VOID, UNOP_DELETE,
} UnaryOp;

typedef enum {
    UPDOP_INC, UPDOP_DEC,
} UpdateOp;

typedef enum {
    ASSIGN_EQ,
    ASSIGN_ADD, ASSIGN_SUB, ASSIGN_MUL, ASSIGN_DIV, ASSIGN_MOD, ASSIGN_POW,
    ASSIGN_BITAND, ASSIGN_BITOR, ASSIGN_BITXOR,
    ASSIGN_LSHIFT, ASSIGN_RSHIFT, ASSIGN_URSHIFT,
    ASSIGN_AND, ASSIGN_OR, ASSIGN_NULLISH,
} AssignOp;

typedef enum { VARDECL_VAR, VARDECL_LET, VARDECL_CONST } VarDeclKind;

typedef enum {
    LIT_NUMBER, LIT_BIGINT, LIT_STRING, LIT_BOOL, LIT_NULL, LIT_UNDEFINED, LIT_REGEX,
} LiteralKind;

typedef enum { PROP_INIT, PROP_GET, PROP_SET, PROP_METHOD, PROP_SHORTHAND } PropKind;

/* ---------- base ---------- */
struct Node {
    NodeKind kind;
    int line, column;
    int end_line, end_column;
};

/* ---------- generic helpers (arena allocated) ---------- */
#define NODE_BASE(N) ((Node*)(N))

/* ---------- specific nodes ---------- */
typedef struct { Node base; Node **stmts; int n; } Program;
typedef struct { Node base; Node **stmts; int n; } Block;
typedef struct { Node base; Node *expr; } ExprStmt;

typedef struct { Node base; Node *id; Node *init; } VarDeclarator;
typedef struct { Node base; VarDeclKind kind; VarDeclarator **decls; int n; } VarDecl;

typedef struct {
    Node base;
    char *name;
    int is_async, is_generator;
    Node **params; int nparams;
    Node *body;         /* Block or NULL for arrow-expr */
    Node *expr_body;    /* for arrow: () => expr */
    int is_arrow;
} FuncNode;

typedef struct {
    Node base;
    char *name;              /* may be NULL for anonymous */
    Node *super_class;
    Node **body; int nbody;  /* MethodDef / PropDef / StaticBlock */
} ClassNode;

typedef struct {
    Node base;
    PropKind kind;
    int is_static;
    int is_async, is_generator;
    Node *key;               /* Ident, Literal, or computed */
    int computed;
    FuncNode *value;         /* for methods */
    Node *init;              /* for props */
} MethodDef;

typedef struct {
    Node base;
    int is_static;
    Node *block;
} StaticBlock;

typedef struct { Node base; Node *test, *cons, *alt; } IfStmt;
typedef struct { Node base; Node *init, *test, *update, *body; } ForStmt;
typedef struct { Node base; Node *left, *right, *body; int is_await; } ForInOfStmt;
typedef struct { Node base; Node *test, *body; } WhileStmt;
typedef struct { Node base; Node *body, *test; } DoWhileStmt;

typedef struct { Node base; Node *test; Node **cases; int n; } SwitchStmt;
typedef struct { Node base; Node *test; Node **body; int n; int is_default; } SwitchCase;

typedef struct { Node base; Node *arg; } ReturnStmt;
typedef struct { Node base; char *label; } BreakStmt;
typedef struct { Node base; char *label; } ContinueStmt;
typedef struct { Node base; Node *arg; } ThrowStmt;
typedef struct { Node base; Node *block, *handler, *finalizer; } TryStmt;
typedef struct { Node base; Node *param; Node *body; } CatchClause;

typedef struct { Node base; char *label; Node *body; } LabeledStmt;
typedef struct { Node base; Node *object, *body; } WithStmt;

/* expressions */
typedef struct {
    Node base;
    char *name;
    int   slot;      /* >= 0 → local slot in current env; -1 → global (by name) */
} Ident;
typedef struct {
    Node base;
    LiteralKind lit_kind;
    double number;
    char *string;
    int boolean;
    char *regex_pattern;
    char *regex_flags;
    char *bigint_text;
} Literal;

typedef struct {
    Node base;
    Node **quasis; int nq;    /* TemplateElement */
    Node **exprs; int ne;
    int is_tagged;
    Node *tag;
} TemplateNode;

typedef struct {
    Node base;
    char *cooked;   /* processed text */
    char *raw;      /* source text */
} TemplateElement;

typedef struct { Node base; Node **elems; int n; } ArrayExpr;
typedef struct { Node base; Node **props; int n; } ObjectExpr;
typedef struct {
    Node base;
    PropKind kind;
    Node *key;
    int computed;
    int shorthand;
    Node *value;      /* init / function */
    int is_async, is_generator;
} Property;

typedef struct {
    Node base;
    Node *object;
    Node *property;
    int   computed;
    int   optional;
    /* PROPERTY CACHE — populated on first access of a static (non-computed)
     * member against a given object shape. If obj->shape still matches,
     * read cached_slot directly, skipping the string scan. */
    uint32_t cached_shape;
    int      cached_slot;
} MemberExpr;
typedef struct {
    Node base;
    Node *callee;
    Node **args;
    int n;
    int optional;
    /* ADAPTIVE CALL SITE CACHE — populated on first call, used after.
     * Points at the last-resolved function object. If it still matches
     * on the next call, we skip the "is this callable?" checks and the
     * env lookup for the function itself. */
    void *cached_fn;
    int   cached_argc;
    int   cached_hits;
} CallExpr;
typedef struct { Node base; Node *callee; Node **args; int n; } NewExpr;

typedef struct { Node base; UnaryOp op; Node *arg; } UnaryExpr;
typedef struct { Node base; UpdateOp op; Node *arg; int prefix; } UpdateExpr;
typedef struct { Node base; BinaryOp op; Node *left, *right; } BinaryExpr;
typedef struct { Node base; LogicalOp op; Node *left, *right; } LogicalExpr;
typedef struct { Node base; AssignOp op; Node *target, *value; } AssignExpr;
typedef struct { Node base; Node *test, *cons, *alt; } ConditionalExpr;
typedef struct { Node base; Node **exprs; int n; } SequenceExpr;
typedef struct { Node base; Node *arg; int delegate; } YieldExpr;

/* patterns */
typedef struct { Node base; Node **elems; int n; } ArrayPattern;
typedef struct { Node base; Node **props; int n; } ObjectPattern;
typedef struct { Node base; Node *target, *default_value; } AssignPattern;
typedef struct { Node base; Node *arg; } RestElement;

/* params */
typedef struct { Node base; Node *pattern; Node *default_value; int rest; } Param;
typedef struct { Node base; Node **params; int n; } ParamList;

/* modules */
typedef struct { Node base; Node **specs; int n; Node *source; } ImportDecl;
typedef struct { Node base; char *imported, *local; } ImportSpec;
typedef struct { Node base; Node *decl; Node **specs; int n; Node *source; int is_default; } ExportDecl;
typedef struct { Node base; char *local, *exported; } ExportSpec;
typedef struct { Node base; Node *source; } ImportCall;

/* ---------- supplementary ---------- */
typedef struct { Node base; Node *arg; } SpreadExpr;
typedef struct { Node base; Node *inner; } ParenExpr;
typedef struct { Node base; Node *arg; } AwaitNode;
typedef struct { Node base; Node *block; } FinallyNode;

/* ---------- helpers ---------- */
void  *ast_alloc(size_t size);
/* sized allocation — callers MUST use this via the MK() macro or pass
 * sizeof(TheStruct). ast_new alone allocates only sizeof(Node), which is
 * enough for the base fields but NOT for specific node kinds. Writing
 * specific fields past the base is a buffer overrun. */
Node  *ast_new_sized(NodeKind k, size_t size,
                     int line, int col, int end_line, int end_col);

/* helper macro: MK(NODE_BINARY, BinaryExpr, l, c, el, ec) -> BinaryExpr* */
#define MK(kind, ty, l, c, el, ec) \
    ((ty*)ast_new_sized((kind), sizeof(ty), (l), (c), (el), (ec)))

/* legacy: only used by tests. Same as ast_new_sized(sizeof(Node)). */
Node  *ast_new(NodeKind k, int line, int col, int end_line, int end_col);
void   ast_free_arena(void);
void   ast_mark_cache_owned(int flag);
int    ast_is_cache_owned(void);

/* Arena head accessors — used by src/cache.c to swap arenas */
void  *ast_arena_head(void);
void   ast_arena_set_head(void *head);
void   ast_arena_release_head(void *head);
int    ast_is_cache_owned(void);
void   ast_free(Node *n);                 /* no-op if using arena */
void   ast_print(Node *n, int indent);
const char *ast_kind_name(NodeKind k);

#endif /* FLYWHEEL_AST_H */
