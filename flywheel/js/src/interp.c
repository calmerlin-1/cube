/* flywheel/src/interp.c  —  Piece 1: expression evaluation
 *
 * Tree-walking interpreter. Reads the AST produced by the parser,
 * executes it, produces Values.
 *
 * ERROR HANDLING:
 *  - Every eval_* function checks I->has_error at entry.
 *  - On failure, sets the error state and returns val_undefined().
 *  - No crashes, no exit(). Errors carry message + line + column.
 *  - The top-level flywheel_eval clears state, runs, and reports.
 */

#include "../include/interp.h"
#include "../include/parser.h"
#include "../include/ast.h"
#include "../include/object.h"
#include "../include/env.h"
#include "../include/cache.h"
#include "../include/lexcache.h"
#include "category.h"
#include "../src/runtime/platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

/* Error helpers                                                */
Value flywheel_err(Interp *I, const char *msg, Node *where) {
    if (!I->has_error) {
        I->has_error = 1;
        I->last_status = FLY_RUNTIME_ERROR;
        snprintf(I->last_error, sizeof(I->last_error), "%s", msg);
        if (where) {
            I->error_line   = where->line;
            I->error_column = where->column;
        }
    }
    return val_undefined();
}

Value flywheel_errf(Interp *I, Node *where, const char *fmt, ...) {
    if (I->has_error) return val_undefined();
    char buf[480];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return flywheel_err(I, buf, where);
}

/* Forward declarations                                         */
static Value eval_expr(Interp *I, Env *env, Node *n);
static Value eval_expr_impl(Interp *I, Env *env, Node *n);
static Value eval_binary(Interp *I, Env *env, BinaryExpr *b);
static Value eval_unary(Interp *I, Env *env, UnaryExpr *u);
static Value eval_logical(Interp *I, Env *env, LogicalExpr *l);
static Value eval_ident(Interp *I, Env *env, Ident *id);
static Value eval_literal(Interp *I, Literal *lit);
static Value eval_statement(Interp *I, Env *env, Node *s);
static Value eval_statement_impl(Interp *I, Env *env, Node *s);
static Value eval_var_decl(Interp *I, Env *env, VarDecl *v);
static Value eval_assign(Interp *I, Env *env, AssignExpr *a);
static Value eval_block(Interp *I, Env *env, Block *b);
static Value eval_array_lit(Interp *I, Env *env, ArrayExpr *a);
static Value eval_object_lit(Interp *I, Env *env, ObjectExpr *o);
static Value eval_member(Interp *I, Env *env, MemberExpr *m);
static Value eval_member_assign(Interp *I, Env *env, MemberExpr *m, Value v);
static Value eval_new(Interp *I, Env *env, NewExpr *n);
static Value eval_func_decl(Interp *I, Env *env, FuncNode *f);
static Value eval_return(Interp *I, Env *env, ReturnStmt *r);
static Value eval_while(Interp *I, Env *env, WhileStmt *w);
static Value eval_for(Interp *I, Env *env, ForStmt *f);
static Value eval_break(Interp *I);
static Value eval_continue(Interp *I);
static Value call_function(Interp *I, Value fn, Value this_val, Value *args, int argc, Node *where);
static Value eval_template(Interp *I, Env *env, TemplateNode *t);
static Value eval_switch(Interp *I, Env *env, SwitchStmt *sw);
static Value eval_try(Interp *I, Env *env, TryStmt *tr);
static Value eval_throw(Interp *I, Env *env, ThrowStmt *th);

/* Interp lifecycle                                             */
Interp *flywheel_new(void) {
    Interp *I = (Interp *)calloc(1, sizeof(Interp));
    if (!I) return NULL;

    I->globals = env_new(NULL, NULL);
    if (!I->globals) { free(I); return NULL; }

    I->strict         = 0;
    I->call_depth     = 0;
    I->max_call_depth = 2000;  /* C stack safety */
    I->has_error      = 0;
    I->last_status    = FLY_OK;
    I->last_error[0]  = '\0';
    I->error_line     = 0;
    I->error_column   = 0;
    I->ctl            = CTL_NONE;
    I->return_value   = val_undefined();
    I->thrown_value   = val_undefined();
    I->string_proto   = NULL;
    I->array_proto    = NULL;
    I->number_proto   = NULL;
    I->natives_loaded = 0;
    I->env_free_list  = NULL;
    I->console_obj    = NULL;
    I->math_obj       = NULL;
    I->json_obj       = NULL;
    I->parseint_obj   = NULL;

    /* Define the `undefined` global. In JS it's a normal global, not a
     * reserved word. We removed it from the keyword table so the lexer
     * emits it as an identifier; here we give it a value. */
    env_define(I, I->globals, "undefined", val_undefined(), 0);

    return I;
}

void flywheel_free(Interp *I) {
    if (!I) return;
    if (I->globals) env_free_chain(I->globals);

    /* NOTE: I->string_proto, I->array_proto, I->number_proto,
     * I->console_obj, I->math_obj, I->json_obj are process-wide SHARED
     * objects owned by builtins_shared.c. Do NOT free them here.
     * Freeing them would double-free on the next Interp.
     * See src/builtins_shared.c. */

    /* Drain the env recycle free list. */
    while (I->env_free_list) {
        Env *e = I->env_free_list;
        I->env_free_list = (Env *)e->parent;
        env_free(e);
    }

    /* Top-level builtin objects (console, Math, JSON) are SHARED.
     * Do not free — see note above. */

    /* Release AST memory. Order matters:
     *   1. Unmark cache-owned so ast_free_arena will actually free.
     *   2. parser_cache_clear frees any cache-entry arenas that are
     *      NOT the current head (its internal guard skips the head).
     *   3. lexer_cache_clear frees token arrays (separate mallocs).
     *   4. ast_free_arena frees the current head chain.
     * If we skip step 2, the parser cache keeps pointers into memory
     * that step 4 frees — the next Interp crashes on a stale "hit". */
    /* Now the cache and the working arena are truly separate chains:
     *   - parser_cache_clear frees every cache entry's own arena chain
     *   - ast_free_arena frees the working chain (may be NULL if all
     *     evals hit the cache and never allocated a working chain)
     * No overlap, no double-free, no orphan. */
    ast_mark_cache_owned(0);
    parser_cache_clear();
    lexer_cache_clear();
    ast_free_arena();

    free(I);
}

Value flywheel_get_global(Interp *I, const char *name) {
    Value v;
    if (env_lookup(I, I->globals, name, &v)) return v;
    return val_undefined();
}

void flywheel_set_global(Interp *I, const char *name, Value v) {
    env_define(I, I->globals, name, v, 1);
}

/* Literals                                                     */
static Value eval_literal(Interp *I, Literal *lit) {
    switch (lit->lit_kind) {
    case LIT_NUMBER:    return val_number(lit->number);
    case LIT_STRING:    return val_string(lit->string ? lit->string : "");
    case LIT_BOOL:      return val_bool(lit->boolean);
    case LIT_NULL:      return val_null();
    case LIT_UNDEFINED: return val_undefined();
    case LIT_BIGINT:
        /* BigInt as number for now — proper BigInt type later. */
        if (lit->bigint_text) {
            double d = strtod(lit->bigint_text, NULL);
            return val_number(d);
        }
        return val_number(0);
    case LIT_REGEX:
        /* Placeholder until RegExp is implemented. */
        return val_string("(regex)");
    }
    return flywheel_err(I, "eval_literal: unknown literal kind", (Node *)lit);
}

/* Identifier lookup                                            */
static Value eval_ident(Interp *I, Env *env, Ident *id) {
    if (!id->name) return flywheel_err(I, "eval_ident: unnamed identifier", (Node *)id);

    /* FAST PATH: local slot — direct array read, no strcmp. */
    if (id->slot >= 0 && id->slot < env->count) {
        return env->values[id->slot];
    }

    Value v;
    if (env_lookup(I, env, id->name, &v)) return v;

    /* Not found: also check globals (env chains through caller's env into globals
     * usually — but if the caller passed an env whose chain doesn't reach
     * globals, this catches it). */
    if (env != I->globals && env_lookup(I, I->globals, id->name, &v)) {
        return v;
    }

    return flywheel_errf(I, (Node *)id, "%s is not defined", id->name);
}

/* Binary operators                                             */
static Value eval_binary(Interp *I, Env *env, BinaryExpr *b) {
    Value L = eval_expr(I, env, b->left);
    if (I->has_error) return val_undefined();
    Value R = eval_expr(I, env, b->right);
    if (I->has_error) return val_undefined();

    /* FAST PATH: number OP number — the hot case in loops and arithmetic.
     * Skips VAL_TO_NUMBER() calls and the string-coercion branch entirely. */
    if (L.kind == VAL_NUMBER && R.kind == VAL_NUMBER) {
        double a = L.as.number, c = R.as.number;
        switch (b->op) {
            case BINOP_ADD:    return val_number(a + c);
            case BINOP_SUB:    return val_number(a - c);
            case BINOP_MUL:    return val_number(a * c);
            case BINOP_DIV:    return val_number(a / c);
            case BINOP_MOD:    return val_number(fmod(a, c));
            case BINOP_POW:    return val_number(pow(a, c));
            case BINOP_LT:     return val_bool(a < c);
            case BINOP_GT:     return val_bool(a > c);
            case BINOP_LE:     return val_bool(a <= c);
            case BINOP_GE:     return val_bool(a >= c);
            case BINOP_EQ:     return val_bool(a == c);
            case BINOP_NEQ:    return val_bool(a != c);
            case BINOP_SEQ:    return val_bool(a == c);
            case BINOP_SNEQ:   return val_bool(a != c);
            case BINOP_BITAND: return val_number((double)((int32_t)a &  (int32_t)c));
            case BINOP_BITOR:  return val_number((double)((int32_t)a |  (int32_t)c));
            case BINOP_BITXOR: return val_number((double)((int32_t)a ^  (int32_t)c));
            case BINOP_LSHIFT: return val_number((double)((int32_t)a << (int32_t)c));
            case BINOP_RSHIFT: return val_number((double)((int32_t)a >> (int32_t)c));
            case BINOP_URSHIFT:return val_number((double)((uint32_t)a >> (int32_t)c));
            default: break;
        }
    }

    switch (b->op) {
    /* --- arithmetic --- */
    case BINOP_ADD:
        /* JS: + is string concat if either side is string (after primitive coercion).
         * For v0 we do the simple rule: if either operand is a string, concatenate. */
        if (L.kind == VAL_STRING || R.kind == VAL_STRING) {
            const char *ls = val_to_cstr(L);
            const char *rs = val_to_cstr(R);
            size_t n = strlen(ls) + strlen(rs) + 1;
            char *buf = (char *)malloc(n);
            if (!buf) return flywheel_err(I, "eval_binary: OOM in string concat", (Node *)b);
            snprintf(buf, n, "%s%s", ls, rs);
            return val_string_take(buf);
        }
        return val_number(VAL_TO_NUMBER(L) + VAL_TO_NUMBER(R));

    case BINOP_SUB: return val_number(VAL_TO_NUMBER(L) - VAL_TO_NUMBER(R));
    case BINOP_MUL: return val_number(VAL_TO_NUMBER(L) * VAL_TO_NUMBER(R));
    case BINOP_DIV: return val_number(VAL_TO_NUMBER(L) / VAL_TO_NUMBER(R));
    case BINOP_MOD: {
        double a = VAL_TO_NUMBER(L), bb = VAL_TO_NUMBER(R);
        return val_number(fmod(a, bb));
    }
    case BINOP_POW: return val_number(pow(VAL_TO_NUMBER(L), VAL_TO_NUMBER(R)));

    /* --- comparison (numeric for now) --- */
    case BINOP_LT:  return val_bool(VAL_TO_NUMBER(L) <  VAL_TO_NUMBER(R));
    case BINOP_GT:  return val_bool(VAL_TO_NUMBER(L) >  VAL_TO_NUMBER(R));
    case BINOP_LE:  return val_bool(VAL_TO_NUMBER(L) <= VAL_TO_NUMBER(R));
    case BINOP_GE:  return val_bool(VAL_TO_NUMBER(L) >= VAL_TO_NUMBER(R));

    case BINOP_EQ:  return val_bool(val_loose_equals(L, R));
    case BINOP_NEQ: return val_bool(!val_loose_equals(L, R));
    case BINOP_SEQ: return val_bool(val_strict_equals(L, R));
    case BINOP_SNEQ:return val_bool(!val_strict_equals(L, R));

    /* --- bitwise (coerce to int32 like JS) --- */
    case BINOP_BITAND: return val_number((double)((int32_t)VAL_TO_NUMBER(L) & (int32_t)VAL_TO_NUMBER(R)));
    case BINOP_BITOR:  return val_number((double)((int32_t)VAL_TO_NUMBER(L) | (int32_t)VAL_TO_NUMBER(R)));
    case BINOP_BITXOR: return val_number((double)((int32_t)VAL_TO_NUMBER(L) ^ (int32_t)VAL_TO_NUMBER(R)));
    case BINOP_LSHIFT: return val_number((double)((int32_t)VAL_TO_NUMBER(L) << (int32_t)VAL_TO_NUMBER(R)));
    case BINOP_RSHIFT: return val_number((double)((int32_t)VAL_TO_NUMBER(L) >> (int32_t)VAL_TO_NUMBER(R)));
    case BINOP_URSHIFT:return val_number((double)((uint32_t)VAL_TO_NUMBER(L) >> (int32_t)VAL_TO_NUMBER(R)));

    /* --- in / instanceof --- */
    case BINOP_IN:
        /* "key" in obj */
        if (R.kind == VAL_OBJECT && R.as.object) {
            Object *o = (Object *)R.as.object;
            const char *k = val_to_cstr(L);
            return val_bool(object_has(I, o, k));
        }
        return flywheel_err(I, "in: right operand is not an object", (Node *)b);

    case BINOP_INSTANCEOF:
        /* Prototype chain check */
        if (R.kind != VAL_OBJECT && R.kind != VAL_FUNCTION) {
            return flywheel_err(I, "instanceof: right operand is not a function", (Node *)b);
        }
        if (L.kind != VAL_OBJECT && L.kind != VAL_FUNCTION) return val_bool(0);
        {
            Object *proto = ((Object *)R.as.object)->prototype;
            Object *obj   = (Object *)L.as.object;
            while (obj) {
                if (obj == proto) return val_bool(1);
                obj = obj->prototype;
            }
            return val_bool(0);
        }
    }
    return flywheel_err(I, "eval_binary: unknown operator", (Node *)b);
}

/* Unary operators                                              */
static Value eval_unary(Interp *I, Env *env, UnaryExpr *u) {
    if (u->op == UNOP_TYPEOF && u->arg && u->arg->kind == NODE_IDENT) {
        Ident *tid = (Ident *)u->arg;
        Value tv;
        if (!env_lookup(I, env, tid->name, &tv) &&
            !env_lookup(I, I->globals, tid->name, &tv))
            return val_string("undefined");
    }
    Value v = eval_expr(I, env, u->arg);
    if (I->has_error) return val_undefined();

    /* FAST PATH: number operand */
    if (v.kind == VAL_NUMBER) {
        double d = v.as.number;
        switch (u->op) {
            case UNOP_PLUS:   return v;
            case UNOP_MINUS:  return val_number(-d);
            case UNOP_BITNOT: return val_number((double)(~(int32_t)d));
            case UNOP_NOT:    return val_bool(d == 0 || d != d);   /* 0 or NaN */
            default: break;
        }
    }

    switch (u->op) {
    case UNOP_PLUS:   return val_number(+VAL_TO_NUMBER(v));
    case UNOP_MINUS:  return val_number(-VAL_TO_NUMBER(v));
    case UNOP_NOT:    return val_bool(!VAL_IS_TRUTHY(v));
    case UNOP_BITNOT: return val_number((double)(~(int32_t)VAL_TO_NUMBER(v)));
    case UNOP_TYPEOF: {
        const char *t;
        switch (v.kind) {
        case VAL_UNDEFINED: t = "undefined"; break;
        case VAL_NULL:      t = "object";    break;
        case VAL_BOOL:      t = "boolean";   break;
        case VAL_NUMBER:    t = "number";    break;
        case VAL_STRING:    t = "string";    break;
        case VAL_OBJECT:    t = "object";    break;
        case VAL_FUNCTION:  t = "function";  break;
        default:            t = "undefined"; break;
        }
        return val_string(t);
    }
    case UNOP_VOID:   return val_undefined();
    case UNOP_DELETE:
        /* delete obj.key — needs the AST shape, not just the value.
         * Handled specially below before we call eval_expr on the operand. */
        return val_bool(0);   /* v0: always returns false (property not deleted) */
    }
    return flywheel_err(I, "eval_unary: unknown operator", (Node *)u);
}

/* Logical && || ??                                             */
static Value eval_logical(Interp *I, Env *env, LogicalExpr *l) {
    Value L = eval_expr(I, env, l->left);
    if (I->has_error) return val_undefined();

    switch (l->op) {
    case LOGOP_AND:
        if (!VAL_IS_TRUTHY(L)) return L;
        return eval_expr(I, env, l->right);

    case LOGOP_OR:
        if (VAL_IS_TRUTHY(L)) return L;
        return eval_expr(I, env, l->right);

    case LOGOP_NULLISH:
        if (!val_is_nullish(L)) return L;
        return eval_expr(I, env, l->right);
    }
    return flywheel_err(I, "eval_logical: unknown operator", (Node *)l);
}

/* Expression dispatcher                                        */
static Value eval_expr(Interp *I, Env *env, Node *n) {
    if (!g_cat_enabled) return eval_expr_impl(I, env, n);
    if (!n) return val_undefined();

    uint64_t t0 = plat_now_ns();
    Value v = eval_expr_impl(I, env, n);
    uint64_t dt = plat_now_ns() - t0;

    cat_state_t *s = cat_get(n);
    if (s) {
        s->count++;
        s->total_time_ns += dt;
        uint8_t kb = (uint8_t)(v.kind & 0xFF);
        if (kb == s->last_kind_byte) s->same_type_run++;
        else { s->last_kind_byte = kb; s->same_type_run = 1; }
    }
    return v;
}

static Value eval_expr_impl(Interp *I, Env *env, Node *n) {
    if (I->has_error) return val_undefined();
    if (!n) return val_undefined();

    switch (n->kind) {
    case NODE_LITERAL:    return eval_literal(I, (Literal *)n);
    case NODE_IDENT:      return eval_ident(I, env, (Ident *)n);
    case NODE_BINARY:     return eval_binary(I, env, (BinaryExpr *)n);
    case NODE_UNARY:      return eval_unary(I, env, (UnaryExpr *)n);
    case NODE_LOGICAL:    return eval_logical(I, env, (LogicalExpr *)n);
    case NODE_PAREN: {
        ParenExpr *p = (ParenExpr *)n;
        return eval_expr(I, env, p->inner);
    }
    case NODE_CONDITIONAL: {
        ConditionalExpr *c = (ConditionalExpr *)n;
        Value t = eval_expr(I, env, c->test);
        if (I->has_error) return val_undefined();
        if (VAL_IS_TRUTHY(t)) return eval_expr(I, env, c->cons);
        return eval_expr(I, env, c->alt);
    }
    case NODE_SEQUENCE: {
        SequenceExpr *s = (SequenceExpr *)n;
        Value last = val_undefined();
        for (int i = 0; i < s->n; i++) {
            last = eval_expr(I, env, s->exprs[i]);
            if (I->has_error) return val_undefined();
        }
        return last;
    }
    /* Not yet implemented — return a specific error, not a crash. */
    case NODE_CALL: {
        CallExpr *call = (CallExpr *)n;
        Value this_val = val_undefined();

        /* If calling a member method, we need the receiver as `this`.
         * Evaluate the base once, then look up the method WITHOUT
         * binding (saves an allocation per method call). */
        Value callee;
        int callee_from_cache = 0;

        /* ADAPTIVE CALL-SITE CACHE.
         * If we've called this site before and the callee is a slot-
         * resolved local that still holds the same function object,
         * skip the eval_expr walk entirely. */
        if (call->cached_fn
            && call->callee
            && call->callee->kind == NODE_IDENT)
        {
            Ident *cid = (Ident *)call->callee;
            if (cid->slot >= 0 && cid->slot < env->count) {
                Value v = env->values[cid->slot];
                if (v.kind == VAL_FUNCTION && v.as.object == call->cached_fn) {
                    callee = v;
                    callee_from_cache = 1;
                }
            }
        }

        if (!callee_from_cache) {
            if (call->callee && call->callee->kind == NODE_MEMBER) {
                MemberExpr *me = (MemberExpr *)call->callee;
                this_val = eval_expr(I, env, me->object);
                if (I->has_error) return val_undefined();
                callee = eval_expr(I, env, call->callee);
                if (I->has_error) return val_undefined();
            } else {
                callee = eval_expr(I, env, call->callee);
                if (I->has_error) return val_undefined();
            }

            /* Populate the cache on first successful resolution. */
            if (call->callee && call->callee->kind == NODE_IDENT
                && callee.kind == VAL_FUNCTION) {
                call->cached_fn   = callee.as.object;
                call->cached_argc = call->n;
                call->cached_hits++;
            }
        }

        /* Arg storage: stack for common case (argc <= 8), heap for the rest.
         * Declared first so error paths can free correctly. */
        Value stack_args[8];
        int   args_heap = 0;
        Value *args = NULL;
        if (call->n > 0) {
            if (call->n <= 8) {
                args = stack_args;
            } else {
                args = (Value *)malloc(sizeof(Value) * call->n);
                args_heap = 1;
                if (!args) return flywheel_err(I, "OOM in call args", n);
            }
        }

        for (int i = 0; i < call->n; i++) {
            args[i] = eval_expr(I, env, call->args[i]);
            if (I->has_error) {
                if (args_heap) free(args);
                return val_undefined();
            }
        }

        if (callee.kind != VAL_FUNCTION) {
            if (args_heap) free(args);
            return flywheel_err(I, "not a function", n);
        }

        Value r = call_function(I, callee, this_val, args, call->n, n);
        if (args_heap) free(args);
        return r;
    }
    case NODE_ASSIGN:
        return eval_assign(I, env, (AssignExpr *)n);
    case NODE_ARRAY:
        return eval_array_lit(I, env, (ArrayExpr *)n);
    case NODE_OBJECT:
        return eval_object_lit(I, env, (ObjectExpr *)n);
    case NODE_MEMBER:
        return eval_member(I, env, (MemberExpr *)n);
    case NODE_NEW:
        return eval_new(I, env, (NewExpr *)n);
    case NODE_TEMPLATE:
        return eval_template(I, env, (TemplateNode *)n);
    case NODE_FUNC_EXPR:
    case NODE_ARROW_FUNC:
        return eval_func_decl(I, env, (FuncNode *)n);
    default:
        return flywheel_err(I, "eval_expr: unsupported node kind", n);
    }
}

/* Array literals                                               */static Value eval_array_lit(Interp *I, Env *env, ArrayExpr *a) {
    if (I->has_error) return val_undefined();
    Object *arr = array_new(I);
    if (!arr) return val_undefined();

    for (int i = 0; i < a->n; i++) {
        if (a->elems[i] == NULL) {
            /* sparse array slot — set undefined */
            array_push(I, arr, val_undefined());
        } else {
            Value v = eval_expr(I, env, a->elems[i]);
            if (I->has_error) return val_undefined();
            array_push(I, arr, v);
        }
    }

    Value out;
    out.kind = VAL_OBJECT;
    out.as.object = arr;
    return out;
}

/* Object literals                                              */
static Value eval_object_lit(Interp *I, Env *env, ObjectExpr *o) {
    if (I->has_error) return val_undefined();
    Object *obj = object_new(I);
    if (!obj) return val_undefined();

    for (int i = 0; i < o->n; i++) {
        Node *pnode = o->props[i];
        if (!pnode) continue;

        if (pnode->kind == NODE_SPREAD) {
            /* { ...spread } */
            SpreadExpr *s = (SpreadExpr *)pnode;
            Value src = eval_expr(I, env, s->arg);
            if (I->has_error) return val_undefined();
            if (src.kind == VAL_OBJECT && src.as.object) {
                Object *so = (Object *)src.as.object;
                for (int k = 0; k < so->count; k++) {
                    object_set(I, obj, so->keys[k], so->values[k]);
                }
            }
            continue;
        }

        if (pnode->kind != NODE_PROPERTY) continue;
        Property *p = (Property *)pnode;

        /* Compute the key */
        char keybuf[256];
        const char *key = NULL;
        if (p->computed) {
            Value kv = eval_expr(I, env, p->key);
            if (I->has_error) return val_undefined();
            snprintf(keybuf, sizeof(keybuf), "%s", val_to_cstr(kv));
            key = keybuf;
        } else if (p->key) {
            if (p->key->kind == NODE_IDENT) {
                key = ((Ident *)p->key)->name;
            } else if (p->key->kind == NODE_LITERAL) {
                Literal *lit = (Literal *)p->key;
                if (lit->lit_kind == LIT_STRING && lit->string) key = lit->string;
                else { snprintf(keybuf, sizeof(keybuf), "%s", val_to_cstr(eval_literal(I, lit))); key = keybuf; }
            }
        }
        if (!key) continue;

        /* Compute the value */
        Value v = val_undefined();
        if (p->shorthand) {
            /* { x } — same as { x: x } */
            if (p->key && p->key->kind == NODE_IDENT) {
                v = eval_ident(I, env, (Ident *)p->key);
                if (I->has_error) return val_undefined();
            } else if (p->value) {
                v = eval_expr(I, env, p->value);
                if (I->has_error) return val_undefined();
            }
        } else if (p->value) {
            if (p->value->kind == NODE_FUNC_EXPR) {
                /* Method: { f() { return 1; } } */
                v = eval_func_decl(I, env, (FuncNode *)p->value);
                if (I->has_error) return val_undefined();
            } else {
                v = eval_expr(I, env, p->value);
                if (I->has_error) return val_undefined();
            }
        }
        object_set(I, obj, key, v);
    }

    Value out;
    out.kind = VAL_OBJECT;
    out.as.object = obj;
    return out;
}

/* Member access: obj.key, obj[key], arr[i]                     */
static Value eval_member(Interp *I, Env *env, MemberExpr *m) {
    if (I->has_error) return val_undefined();
    Value base = eval_expr(I, env, m->object);
    if (I->has_error) return val_undefined();

    /* Optional chaining: obj?.x — if base is null/undefined, return undefined */
    if (m->optional && val_is_nullish(base)) return val_undefined();

    /* ---- Compute key FIRST (independent of base kind) ---- */
    char keybuf[256];
    const char *key = NULL;
    if (m->computed) {
        Value kv = eval_expr(I, env, m->property);
        if (I->has_error) return val_undefined();
        snprintf(keybuf, sizeof(keybuf), "%s", val_to_cstr(kv));
        key = keybuf;
    } else if (m->property && m->property->kind == NODE_IDENT) {
        key = ((Ident *)m->property)->name;
    }
    if (!key) return val_undefined();

    /* FAST PATH: property shape cache.
     * For a static (non-computed) member access on an object or function
     * whose shape matches the last-seen shape at this MemberExpr site,
     * read the value at the cached slot directly. Skips the string scan
     * inside object_get. */
    if (!m->computed
        && m->property
        && m->property->kind == NODE_IDENT
        && (base.kind == VAL_OBJECT || base.kind == VAL_FUNCTION))
    {
        Object *obj = (Object *)base.as.object;
        if (obj
            && m->cached_shape != 0
            && obj->shape == m->cached_shape
            && m->cached_slot >= 0
            && m->cached_slot < obj->count)
        {
            return obj->values[m->cached_slot];
        }
        /* On miss, resolve once and record the shape+slot for next time. */
        if (obj && obj->count > 0) {
            for (int i = 0; i < obj->count; i++) {
                if (strcmp(obj->keys[i], key) == 0) {
                    m->cached_shape = obj->shape;
                    m->cached_slot  = i;
                    return obj->values[i];
                }
            }
            /* Not found in this object — fall through to object_get for
             * prototype chain walk. Do NOT cache negative results. */
        }
    }

    /* ---- Dispatch on base kind ---- */

    /* String primitive: methods live on I->string_proto */
    if (base.kind == VAL_STRING) {
        const char *s = base.as.string ? base.as.string : "";
        if (strcmp(key, "length") == 0) return val_number((double)strlen(s));
        if (!I->string_proto) return val_undefined();
        Value m2 = object_get(I, I->string_proto, key);
        if (m2.kind == VAL_FUNCTION && m2.as.object) {
            Object *orig = (Object *)m2.as.object;
            Object *bound = object_new(I);
            if (!bound) return val_undefined();
            bound->native     = orig->native;
            bound->fn_node    = orig->fn_node;
            bound->closure    = orig->closure;
            bound->bound_this = base;
            Value bv; bv.kind = VAL_FUNCTION; bv.as.object = bound;
            return bv;
        }
        return val_undefined();
    }

    /* Number primitive */
    if (base.kind == VAL_NUMBER) {
        if (!I->number_proto) return val_undefined();
        Value m2 = object_get(I, I->number_proto, key);
        if (m2.kind == VAL_FUNCTION && m2.as.object) {
            Object *orig = (Object *)m2.as.object;
            Object *bound = object_new(I);
            if (!bound) return val_undefined();
            bound->native     = orig->native;
            bound->fn_node    = orig->fn_node;
            bound->closure    = orig->closure;
            bound->bound_this = base;
            Value bv; bv.kind = VAL_FUNCTION; bv.as.object = bound;
            return bv;
        }
        return val_undefined();
    }

    /* Bool / null / undefined: no methods */
    if (base.kind != VAL_OBJECT && base.kind != VAL_FUNCTION) {
        return flywheel_err(I, "cannot read property of non-object", (Node *)m);
    }

    Object *obj = (Object *)base.as.object;
    if (!obj) return val_undefined();

    /* Array .length */
    if (obj->is_array && strcmp(key, "length") == 0) {
        return val_number(obj->length);
    }

    /* Array with numeric index — skip string scan entirely */
    if (obj->is_array && m->computed) {
        char *end = NULL;
        long n = strtol(key, &end, 10);
        if (end && *end == '\0' && n >= 0) {
            if (n < obj->length) return obj->elements[n];
            return val_undefined();
        }
    }

    /* FAST PATH: arrays only have numeric own keys. A static name like
     * "push" or "join" can never be an own property. Skip the O(N) scan
     * and go straight to the array prototype. Without this, every method
     * call on an N-length array costs N strcmp() calls. */
    if (obj->is_array && !m->computed) {
        if (I->array_proto) {
            Value m2 = object_get(I, I->array_proto, key);
            if (m2.kind == VAL_FUNCTION && m2.as.object) {
                Object *orig = (Object *)m2.as.object;
                Object *bound = object_new(I);
                if (!bound) return val_undefined();
                bound->native     = orig->native;
                bound->fn_node    = orig->fn_node;
                bound->closure    = orig->closure;
                bound->bound_this = base;
                Value bv; bv.kind = VAL_FUNCTION; bv.as.object = bound;
                return bv;
            }
            if (!val_is_undefined(m2)) return m2;
        }
        return val_undefined();
    }

    /* Own property (general objects) */
    Value own = object_get(I, obj, key);
    if (!val_is_undefined(own)) return own;

    /* Non-array prototypes (numbers, strings handled earlier) */
    if (I->array_proto && obj->is_array) {
        Value m2 = object_get(I, I->array_proto, key);
        if (m2.kind == VAL_FUNCTION && m2.as.object) {
            Object *orig = (Object *)m2.as.object;
            Object *bound = object_new(I);
            if (!bound) return val_undefined();
            bound->native     = orig->native;
            bound->fn_node    = orig->fn_node;
            bound->closure    = orig->closure;
            bound->bound_this = base;
            Value bv; bv.kind = VAL_FUNCTION; bv.as.object = bound;
            return bv;
        }
        if (!val_is_undefined(m2)) return m2;
    }

    return own;
}

/* Member assignment: obj.key = v, arr[i] = v                   */
static Value eval_member_assign(Interp *I, Env *env, MemberExpr *m, Value v) {
    if (I->has_error) return val_undefined();
    Value base = eval_expr(I, env, m->object);
    if (I->has_error) return val_undefined();

    if (base.kind != VAL_OBJECT && base.kind != VAL_FUNCTION) {
        return flywheel_err(I, "cannot assign property of non-object", (Node *)m);
    }
    Object *obj = (Object *)base.as.object;
    if (!obj) return flywheel_err(I, "null object in assignment", (Node *)m);

    char keybuf[256];
    const char *key = NULL;
    if (m->computed) {
        Value kv = eval_expr(I, env, m->property);
        if (I->has_error) return val_undefined();
        snprintf(keybuf, sizeof(keybuf), "%s", val_to_cstr(kv));
        key = keybuf;
    } else if (m->property && m->property->kind == NODE_IDENT) {
        key = ((Ident *)m->property)->name;
    }
    if (!key) return flywheel_err(I, "invalid member assignment target", (Node *)m);

    /* FAST PATH: numeric assignment to an array. Skip the O(N) string
     * key scan inside object_set; write directly to the slot. */
    if (obj->is_array && m->computed) {
        char *end = NULL;
        long n = strtol(key, &end, 10);
        if (end && *end == '\0' && n >= 0) {
            array_set(I, obj, (int)n, v);
            return v;
        }
    }

    object_set(I, obj, key, v);
    return v;
}

/* new expression — basic: create object, call constructor      */
static Value eval_new(Interp *I, Env *env, NewExpr *n) {
    if (I->has_error) return val_undefined();

    /* eval callee */
    Value callee = eval_expr(I, env, n->callee);
    if (I->has_error) return val_undefined();

    /* new on non-function is an error */
    if (callee.kind != VAL_FUNCTION) {
        return flywheel_err(I, "new: value is not a constructor", (Node *)n);
    }

    /* Create a fresh object */
    Object *obj = object_new(I);
    if (!obj) return val_undefined();

    /* Set its prototype to the callee's prototype */
    Object *callee_obj = (Object *)callee.as.object;
    if (callee_obj) obj->prototype = callee_obj->prototype;

    Value thisv;
    thisv.kind = VAL_OBJECT;
    thisv.as.object = obj;

    /* Build args */
    Value *args = NULL;
    if (n->n > 0) {
        args = (Value *)malloc(sizeof(Value) * n->n);
        if (!args) return flywheel_err(I, "OOM in new args", (Node *)n);
    }
    for (int i = 0; i < n->n; i++) {
        args[i] = eval_expr(I, env, n->args[i]);
        if (I->has_error) { free(args); return val_undefined(); }
    }

    /* Call the function (native or user) with `this` bound. Our call_function
     * doesn't yet pass `this`; for v0 natives, ignore. */
    Value r = call_function(I, callee, thisv, args, n->n, (Node *)n);
    free(args);
    if (I->has_error) return val_undefined();

    /* If the function returned an object, use it. Otherwise use our new obj. */
    if (r.kind == VAL_OBJECT || r.kind == VAL_FUNCTION) return r;
    return thisv;
}

/* Functions                                                    */
static Value eval_func_decl(Interp *I, Env *env, FuncNode *f) {
    if (I->has_error) return val_undefined();
    if (!f) return flywheel_err(I, "eval_func_decl: null", NULL);

    Object *obj = object_new(I);
    if (!obj) return val_undefined();

    obj->fn_node = (void *)f;
    obj->closure = (void *)env;
    /* The closure now holds a reference to this env. Bump refcount so
     * that when the defining scope returns and env_free is called, the
     * env survives as long as the function does. */
    env_retain(env);

    Value fv;
    fv.kind = VAL_FUNCTION;
    fv.as.object = obj;

    if (f->name) {
        env_define(I, env, f->name, fv, 1);
    }
    return fv;
}

/* Template literals: `hello ${name}` -> "hello world"         */
static Value eval_template(Interp *I, Env *env, TemplateNode *t) {
    if (I->has_error) return val_undefined();
    if (!t) return val_string("");

    /* Result is the concatenation of all quasis and expr values. */
    size_t total = 0;
    size_t cap = 64;
    char *buf = (char *)malloc(cap);
    if (!buf) return flywheel_err(I, "OOM in template", (Node *)t);
    buf[0] = '\0';

    int nseg = t->nq > t->ne ? t->nq : t->ne;
    for (int i = 0; i < nseg; i++) {
        /* quasi text */
        if (i < t->nq) {
            Node *qn = t->quasis[i];
            if (qn && qn->kind == NODE_TEMPLATE_ELEMENT) {
                TemplateElement *te = (TemplateElement *)qn;
                const char *s = te->cooked ? te->cooked : (te->raw ? te->raw : "");
                /* skip leading ` or }${ and trailing ${ or ` from raw segments */
                if (te->cooked) {
                    s = te->cooked;
                } else {
                    /* cooked not set — strip the raw markers */
                    s = te->raw ? te->raw : "";
                }
                size_t sl = strlen(s);
                while (total + sl + 2 > cap) { cap *= 2; char *n = realloc(buf, cap); if (!n) { free(buf); return flywheel_err(I, "OOM", (Node *)t); } buf = n; }
                memcpy(buf + total, s, sl); total += sl; buf[total] = '\0';
            }
        }
        /* expr value */
        if (i < t->ne) {
            Value v = eval_expr(I, env, t->exprs[i]);
            if (I->has_error) { free(buf); return val_undefined(); }
            const char *vs = val_to_cstr(v);
            size_t vl = strlen(vs);
            while (total + vl + 2 > cap) { cap *= 2; char *n = realloc(buf, cap); if (!n) { free(buf); return flywheel_err(I, "OOM", (Node *)t); } buf = n; }
            memcpy(buf + total, vs, vl); total += vl; buf[total] = '\0';
        }
    }
    return val_string_take(buf);
}

/* Switch                                                       */
static Value eval_switch(Interp *I, Env *env, SwitchStmt *sw) {
    if (I->has_error) return val_undefined();
    Value disc = eval_expr(I, env, sw->test);
    if (I->has_error) return val_undefined();

    int matched = -1;
    int default_idx = -1;
    for (int i = 0; i < sw->n; i++) {
        SwitchCase *sc = (SwitchCase *)sw->cases[i];
        if (!sc) continue;
        if (sc->is_default) { default_idx = i; continue; }
        if (matched >= 0) continue;
        Value casev = eval_expr(I, env, sc->test);
        if (I->has_error) return val_undefined();
        if (val_strict_equals(disc, casev)) matched = i;
    }
    if (matched < 0) matched = default_idx;
    if (matched < 0) return val_undefined();

    /* Run from matched case through all following cases (fall-through) */
    Value last = val_undefined();
    for (int i = matched; i < sw->n; i++) {
        SwitchCase *sc = (SwitchCase *)sw->cases[i];
        if (!sc) continue;
        for (int j = 0; j < sc->n; j++) {
            last = eval_statement(I, env, sc->body[j]);
            if (I->has_error) return val_undefined();
            if (I->ctl == CTL_BREAK) { I->ctl = CTL_NONE; return last; }
            if (I->ctl == CTL_RETURN) return last;
            if (I->ctl == CTL_CONTINUE) return last;
        }
    }
    return last;
}

/* Throw                                                        */
static Value eval_throw(Interp *I, Env *env, ThrowStmt *th) {
    if (I->has_error) return val_undefined();
    Value v = val_undefined();
    if (th && th->arg) {
        v = eval_expr(I, env, th->arg);
        if (I->has_error) return val_undefined();
    }
    I->ctl = CTL_THROW;
    I->thrown_value = v;
    return v;
}

/* Try / Catch / Finally                                        */
static Value eval_try(Interp *I, Env *env, TryStmt *tr) {
    if (I->has_error) return val_undefined();
    Value last = val_undefined();

    /* Run the try block */
    if (tr->block) {
        last = eval_statement(I, env, tr->block);
    }

    /* Handle throw */
    if (I->ctl == CTL_THROW) {
        Value thrown = I->thrown_value;
        I->ctl = CTL_NONE;
        I->thrown_value = val_undefined();

        if (tr->handler) {
            CatchClause *cc = (CatchClause *)tr->handler;
            Env *catch_env = env_new(I, env);
            if (cc->param && cc->param->kind == NODE_IDENT) {
                env_define(I, catch_env, ((Ident *)cc->param)->name, thrown, 1);
            }
            last = eval_statement(I, catch_env, cc->body);
            env_free(catch_env);
        } else {
            /* No catch: the throw propagates. If we have a finalizer,
             * run it first; then re-raise. */
            if (tr->finalizer) {
                /* We'll set the throw state again after finally. The
                 * finally block runs on the next line. */
                I->ctl = CTL_THROW;
                I->thrown_value = thrown;
                /* fall through to run finally */
            } else {
                I->ctl = CTL_THROW;
                I->thrown_value = thrown;
            }
        }
    }

    /* Finally always runs */
    if (tr->finalizer) {
        Node *fn = tr->finalizer;
        if (fn && fn->kind == NODE_FINALLY) {
            FinallyNode *fin = (FinallyNode *)fn;
            if (fin->block) eval_statement(I, env, fin->block);
        }
    }
    return last;
}

/* Call a function                                              */
static Value call_function(Interp *I, Value fn, Value this_val, Value *args, int argc, Node *where) {
    if (I->has_error) return val_undefined();
    if (fn.kind != VAL_FUNCTION) {
        return flywheel_err(I, "value is not a function", where);
    }
    Object *obj = (Object *)fn.as.object;
    if (!obj) return flywheel_err(I, "null function object", where);

    /* Native function — prefer bound_this (set by older binding), else
     * use the caller-supplied this_val. */
    if (obj->native) {
        Value recv = obj->bound_this;
        if (val_is_undefined(recv)) recv = this_val;
        return obj->native(I, recv, args, argc);
    }

    /* User function */
    FuncNode *f = (FuncNode *)obj->fn_node;
    if (!f) return flywheel_err(I, "function has no body", where);

    if (I->call_depth >= I->max_call_depth) {
        return flywheel_err(I, "maximum call stack depth exceeded", where);
    }
    I->call_depth++;

    /* New env for the function body, parent = closure (lexical scope) */
    Env *callenv = env_acquire(I, (Env *)obj->closure);
    if (!callenv) { I->call_depth--; return val_undefined(); }

    /* ADAPTIVE PARAM BINDING.
     * If the closure's env is fresh (no bindings yet) we can write
     * directly into slots without lookup. Names are still strdup'd
     * (they must persist) but the find step is skipped. */
    int nbind = f->nparams < argc ? f->nparams : argc;

    if (callenv->count == 0 && callenv->capacity >= f->nparams) {
        /* Fast path: env is pre-sized and empty. Skip env_find. */
        for (int i = 0; i < nbind; i++) {
            Node *pnode = f->params[i];
            if (!pnode || pnode->kind != NODE_PARAM) continue;
            Param *pm = (Param *)pnode;
            if (pm->pattern && pm->pattern->kind == NODE_IDENT) {
                callenv->names[callenv->count]   = strdup(((Ident *)pm->pattern)->name);
                callenv->values[callenv->count]  = args[i];
                callenv->mutable[callenv->count] = 1;
                callenv->count++;
            }
        }
        for (int i = nbind; i < f->nparams; i++) {
            Node *pnode = f->params[i];
            if (!pnode || pnode->kind != NODE_PARAM) continue;
            Param *pm = (Param *)pnode;
            if (pm->pattern && pm->pattern->kind == NODE_IDENT) {
                callenv->names[callenv->count]   = strdup(((Ident *)pm->pattern)->name);
                callenv->values[callenv->count]  = val_undefined();
                callenv->mutable[callenv->count] = 1;
                callenv->count++;
            }
        }
    } else {
        /* Slow path: env already had bindings (shouldn't normally happen
         * with a fresh acquire, but keep the correct behavior). */
        for (int i = 0; i < nbind; i++) {
            Node *pnode = f->params[i];
            if (!pnode || pnode->kind != NODE_PARAM) continue;
            Param *pm = (Param *)pnode;
            Value v = args[i];
            if (pm->pattern && pm->pattern->kind == NODE_IDENT) {
                env_define(I, callenv, ((Ident *)pm->pattern)->name, v, 1);
            }
        }
        for (int i = nbind; i < f->nparams; i++) {
            Node *pnode = f->params[i];
            if (!pnode || pnode->kind != NODE_PARAM) continue;
            Param *pm = (Param *)pnode;
            if (pm->pattern && pm->pattern->kind == NODE_IDENT) {
                env_define(I, callenv, ((Ident *)pm->pattern)->name,
                           val_undefined(), 1);
            }
        }
    }

    /* Execute body or expression */
    Value result = val_undefined();
    if (f->body) {
        /* body is a NODE_BLOCK — execute its statements in callenv */
        Block *b = (Block *)f->body;
        for (int i = 0; i < b->n; i++) {
            result = eval_statement(I, callenv, b->stmts[i]);
            if (I->has_error) { env_release(I, callenv); I->call_depth--; return val_undefined(); }
            if (I->ctl == CTL_RETURN) {
                result = I->return_value;
                I->ctl = CTL_NONE;
                I->return_value = val_undefined();
                break;
            }
            if (I->ctl == CTL_BREAK || I->ctl == CTL_CONTINUE) {
                env_release(I, callenv);
                I->call_depth--;
                return flywheel_err(I, "break/continue outside loop", where);
            }
        }
    } else if (f->expr_body) {
        result = eval_expr(I, callenv, f->expr_body);
        if (I->ctl == CTL_RETURN) {
            result = I->return_value;
            I->ctl = CTL_NONE;
            I->return_value = val_undefined();
        }
    }

    env_release(I, callenv);
    I->call_depth--;
    return result;
}

/* Return                                                       */
static Value eval_return(Interp *I, Env *env, ReturnStmt *r) {
    if (I->has_error) return val_undefined();
    Value v = val_undefined();
    if (r && r->arg) {
        v = eval_expr(I, env, r->arg);
        if (I->has_error) return val_undefined();
    }
    I->ctl = CTL_RETURN;
    I->return_value = v;
    return v;
}

/* Loops                                                        */
static Value eval_while(Interp *I, Env *env, WhileStmt *w) {
    if (I->has_error) return val_undefined();
    Value last = val_undefined();
    while (!I->has_error) {
        Value t = eval_expr(I, env, w->test);
        if (I->has_error) return val_undefined();
        if (!VAL_IS_TRUTHY(t)) break;

        last = eval_statement(I, env, w->body);
        if (I->has_error) return val_undefined();

        if (I->ctl == CTL_BREAK)     { I->ctl = CTL_NONE; break; }
        if (I->ctl == CTL_CONTINUE)  { I->ctl = CTL_NONE; continue; }
        if (I->ctl == CTL_RETURN)    return last;
    }
    return last;
}

static Value eval_for(Interp *I, Env *env, ForStmt *f) {
    if (I->has_error) return val_undefined();
    Env *loopenv = env_new(I, env);
    if (!loopenv) return val_undefined();

    if (f->init) {
        eval_statement(I, loopenv, f->init);
        if (I->has_error) { env_free(loopenv); return val_undefined(); }
    }

    Value last = val_undefined();
    while (!I->has_error) {
        if (f->test) {
            Value t = eval_expr(I, loopenv, f->test);
            if (I->has_error) { env_free(loopenv); return val_undefined(); }
            if (!VAL_IS_TRUTHY(t)) break;
        }

        last = eval_statement(I, loopenv, f->body);
        if (I->has_error) { env_free(loopenv); return val_undefined(); }

        if (I->ctl == CTL_BREAK)    { I->ctl = CTL_NONE; break; }
        if (I->ctl == CTL_RETURN)   { env_free(loopenv); return last; }
        if (I->ctl == CTL_CONTINUE) { I->ctl = CTL_NONE; }

        if (f->update) {
            eval_expr(I, loopenv, f->update);
            if (I->has_error) { env_free(loopenv); return val_undefined(); }
        }
    }
    env_free(loopenv);
    return last;
}

static Value eval_break(Interp *I) {
    I->ctl = CTL_BREAK;
    return val_undefined();
}

static Value eval_continue(Interp *I) {
    I->ctl = CTL_CONTINUE;
    return val_undefined();
}

static Value eval_assign(Interp *I, Env *env, AssignExpr *a) {
    if (I->has_error) return val_undefined();
    if (!a) return flywheel_err(I, "eval_assign: null node", NULL);

    /* For v0, only handle simple "x = value" and compound "+=" etc.
     * Pattern assignment (destructuring), member assignment (obj.x = 5)
     * are separate cases handled later. */

    /* Evaluate the RHS first (JS semantics: RHS before LHS binding write) */
    Value rhs = eval_expr(I, env, a->value);
    if (I->has_error) return val_undefined();

    /* Handle compound ops: x += 1 becomes x = x + 1 */
    Value final_rhs = rhs;
    if (a->op != ASSIGN_EQ) {
        Value cur;
        if (a->target->kind == NODE_IDENT) {
            cur = eval_expr(I, env, a->target);
            if (I->has_error) return val_undefined();
        } else {
            return flywheel_err(I, "compound assignment: unsupported target", (Node *)a);
        }
        /* Apply the operator to cur and rhs */
        BinaryExpr fake;
        memset(&fake, 0, sizeof(fake));
        fake.base.kind = NODE_BINARY;
        fake.base.line = a->base.line;
        fake.base.column = a->base.column;
        fake.left  = NULL;   /* unused because we'll compute directly */
        fake.right = NULL;
        switch (a->op) {
        case ASSIGN_ADD:
            if (cur.kind == VAL_STRING || rhs.kind == VAL_STRING) {
                const char *ls = val_to_cstr(cur);
                const char *rs = val_to_cstr(rhs);
                size_t n = strlen(ls) + strlen(rs) + 1;
                char *buf = (char *)malloc(n);
                if (!buf) return flywheel_err(I, "eval_assign: OOM in +=", (Node *)a);
                snprintf(buf, n, "%s%s", ls, rs);
                final_rhs = val_string_take(buf);
            } else {
                final_rhs = val_number(VAL_TO_NUMBER(cur) + VAL_TO_NUMBER(rhs));
            }
            break;
        case ASSIGN_SUB:    final_rhs = val_number(VAL_TO_NUMBER(cur) - VAL_TO_NUMBER(rhs)); break;
        case ASSIGN_MUL:    final_rhs = val_number(VAL_TO_NUMBER(cur) * VAL_TO_NUMBER(rhs)); break;
        case ASSIGN_DIV:    final_rhs = val_number(VAL_TO_NUMBER(cur) / VAL_TO_NUMBER(rhs)); break;
        case ASSIGN_MOD:    final_rhs = val_number(fmod(VAL_TO_NUMBER(cur), VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_POW:    final_rhs = val_number(pow(VAL_TO_NUMBER(cur), VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_BITAND: final_rhs = val_number((double)((int32_t)VAL_TO_NUMBER(cur) & (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_BITOR:  final_rhs = val_number((double)((int32_t)VAL_TO_NUMBER(cur) | (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_BITXOR: final_rhs = val_number((double)((int32_t)VAL_TO_NUMBER(cur) ^ (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_LSHIFT: final_rhs = val_number((double)((int32_t)VAL_TO_NUMBER(cur) << (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_RSHIFT: final_rhs = val_number((double)((int32_t)VAL_TO_NUMBER(cur) >> (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_URSHIFT:final_rhs = val_number((double)((uint32_t)VAL_TO_NUMBER(cur) >> (int32_t)VAL_TO_NUMBER(rhs))); break;
        case ASSIGN_AND:    final_rhs = VAL_IS_TRUTHY(cur) ? rhs : cur; break;
        case ASSIGN_OR:     final_rhs = VAL_IS_TRUTHY(cur) ? cur : rhs; break;
        case ASSIGN_NULLISH:final_rhs = !val_is_nullish(cur) ? cur : rhs; break;
        default:            final_rhs = rhs; break;
        }
    }

    /* Member assignment: obj.key = value, arr[i] = value */
    if (a->target->kind == NODE_MEMBER) {
        if (a->op != ASSIGN_EQ) {
            /* Compound: read current, apply, then write */
            Value cur = eval_member(I, env, (MemberExpr *)a->target);
            if (I->has_error) return val_undefined();
            Value combined;
            switch (a->op) {
            case ASSIGN_ADD:
                if (cur.kind == VAL_STRING || final_rhs.kind == VAL_STRING) {
                    const char *ls = val_to_cstr(cur);
                    const char *rs = val_to_cstr(final_rhs);
                    size_t ln = strlen(ls) + strlen(rs) + 1;
                    char *buf = (char *)malloc(ln);
                    if (!buf) return flywheel_err(I, "OOM in +=", (Node *)a);
                    snprintf(buf, ln, "%s%s", ls, rs);
                    combined = val_string_take(buf);
                } else {
                    combined = val_number(VAL_TO_NUMBER(cur) + VAL_TO_NUMBER(final_rhs));
                }
                break;
            case ASSIGN_SUB:  combined = val_number(VAL_TO_NUMBER(cur) - VAL_TO_NUMBER(final_rhs)); break;
            case ASSIGN_MUL:  combined = val_number(VAL_TO_NUMBER(cur) * VAL_TO_NUMBER(final_rhs)); break;
            case ASSIGN_DIV:  combined = val_number(VAL_TO_NUMBER(cur) / VAL_TO_NUMBER(final_rhs)); break;
            default:          combined = final_rhs; break;
            }
            return eval_member_assign(I, env, (MemberExpr *)a->target, combined);
        }
        return eval_member_assign(I, env, (MemberExpr *)a->target, final_rhs);
    }

    /* Now the LHS must be an identifier */
    if (a->target->kind == NODE_IDENT) {
        Ident *id = (Ident *)a->target;
        if (!id->name) return flywheel_err(I, "eval_assign: unnamed target", (Node *)a);

        /* FAST PATH: local slot — direct array write, no strcmp. */
        if (id->slot >= 0 && id->slot < env->count) {
            env->values[id->slot] = final_rhs;
            return final_rhs;
        }

        if (env_assign(I, env, id->name, final_rhs)) return final_rhs;
        if (I->has_error) return val_undefined();
        /* Not found anywhere */
        return flywheel_errf(I, (Node *)a, "%s is not defined", id->name);
    }

    return flywheel_err(I, "assignment target is not an identifier (yet)", (Node *)a);
}

/* Variable declaration                                         */
static Value eval_var_decl(Interp *I, Env *env, VarDecl *v) {
    if (I->has_error) return val_undefined();
    if (!v) return flywheel_err(I, "eval_var_decl: null node", NULL);

    int is_const = (v->kind == VARDECL_CONST);

    for (int i = 0; i < v->n; i++) {
        VarDeclarator *d = v->decls[i];
        if (!d) continue;

        Value init = val_undefined();
        if (d->init) {
            init = eval_expr(I, env, d->init);
            if (I->has_error) return val_undefined();
        } else if (is_const) {
            return flywheel_err(I, "const declaration requires an initializer", (Node *)d);
        }

        /* For v0, only simple identifier targets are supported. */
        if (d->id && d->id->kind == NODE_IDENT) {
            Ident *id = (Ident *)d->id;
            if (id->name) {
                env_define(I, env, id->name, init, is_const ? 0 : 1);
            }
        } else {
            return flywheel_err(I, "destructuring declarations not yet implemented", (Node *)d);
        }
    }
    return val_undefined();
}

/* Block — new child env                                        */
static Value eval_block(Interp *I, Env *env, Block *b) {
    if (I->has_error) return val_undefined();
    if (!b) return val_undefined();

    Env *child = env_new(I, env);
    if (!child) return val_undefined();

    Value last = val_undefined();
    for (int i = 0; i < b->n; i++) {
        last = eval_statement(I, child, b->stmts[i]);
        if (I->has_error) { env_free(child); return val_undefined(); }
        /* Propagate control signals (return/break/continue) immediately.
         * Without this, a break inside a nested block would keep executing
         * subsequent statements in the same block. */
        if (I->ctl != CTL_NONE) break;
    }
    env_free(child);
    return last;
}

/* Statement dispatcher                                         */
static Value eval_statement(Interp *I, Env *env, Node *n) {
    if (!g_cat_enabled) return eval_statement_impl(I, env, n);
    if (!n) return val_undefined();

    uint64_t t0 = plat_now_ns();
    Value v = eval_statement_impl(I, env, n);
    uint64_t dt = plat_now_ns() - t0;

    cat_state_t *s = cat_get(n);
    if (s) {
        s->count++;
        s->total_time_ns += dt;
        uint8_t kb = (uint8_t)(v.kind & 0xFF);
        if (kb == s->last_kind_byte) s->same_type_run++;
        else { s->last_kind_byte = kb; s->same_type_run = 1; }
    }
    return v;
}

static Value eval_statement_impl(Interp *I, Env *env, Node *s) {
    if (I->has_error) return val_undefined();
    if (!s) return val_undefined();

    switch (s->kind) {
    case NODE_EXPR_STMT:
        return eval_expr(I, env, ((ExprStmt *)s)->expr);

    case NODE_EMPTY_STMT:
        return val_undefined();

    case NODE_VAR_DECL:
        return eval_var_decl(I, env, (VarDecl *)s);

    case NODE_FUNC_DECL:
        return eval_func_decl(I, env, (FuncNode *)s);

    case NODE_RETURN:
        return eval_return(I, env, (ReturnStmt *)s);

    case NODE_BREAK:
        return eval_break(I);

    case NODE_CONTINUE:
        return eval_continue(I);

    case NODE_WHILE:
        return eval_while(I, env, (WhileStmt *)s);

    case NODE_FOR:
        return eval_for(I, env, (ForStmt *)s);

    case NODE_SWITCH:
        return eval_switch(I, env, (SwitchStmt *)s);

    case NODE_THROW:
        return eval_throw(I, env, (ThrowStmt *)s);

    case NODE_TRY:
        return eval_try(I, env, (TryStmt *)s);

    case NODE_BLOCK:
        return eval_block(I, env, (Block *)s);

    case NODE_IF: {
        IfStmt *st = (IfStmt *)s;
        Value test = eval_expr(I, env, st->test);
        if (I->has_error) return val_undefined();
        if (VAL_IS_TRUTHY(test)) {
            return eval_statement(I, env, st->cons);
        } else if (st->alt) {
            return eval_statement(I, env, st->alt);
        }
        return val_undefined();
    }

    default:
        return flywheel_errf(I, s, "statement kind %d not yet implemented", s->kind);
    }
}

static Value eval_program(Interp *I, Env *env, Program *p) {
    Value last = val_undefined();
    for (int i = 0; i < p->n; i++) {
        if (I->has_error) return val_undefined();
        last = eval_statement(I, env, p->stmts[i]);
        if (I->ctl != CTL_NONE) break;
    }
    return last;
}

/* Public entry point                                           */
FlyResult flywheel_eval(Interp *I, const char *source, const char *filename) {
    FlyResult result;
    memset(&result, 0, sizeof(result));

    if (!I) {
        result.status = FLY_INTERNAL;
        snprintf(result.error_msg, sizeof(result.error_msg), "null interp");
        return result;
    }

    /* clear prior error */
    I->has_error      = 0;
    I->last_status    = FLY_OK;
    I->last_error[0]  = '\0';
    I->error_line     = 0;
    I->error_column   = 0;

    /* parse */
    ParseResult pr = parser_parse(source, filename);
    if (pr.nerrors > 0) {
        result.status = FLY_PARSE_ERROR;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "%s", pr.errors ? pr.errors[0].msg : "parse error");
        result.error_line   = pr.errors ? pr.errors[0].line : 0;
        result.error_column = pr.errors ? pr.errors[0].column : 0;
        parser_free_result(&pr);
        ast_free_arena();
        return result;
    }

    if (!pr.program) {
        result.status = FLY_INTERNAL;
        snprintf(result.error_msg, sizeof(result.error_msg), "parser returned no AST");
        parser_free_result(&pr);
        ast_free_arena();
        return result;
    }

    /* execute */
    Value v = eval_program(I, I->globals, (Program *)pr.program);

    /* Top-level throw that wasn't caught: treat as a runtime error. */
    if (I->ctl == CTL_THROW) {
        result.status = FLY_RUNTIME_ERROR;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "uncaught: %s", val_to_cstr(I->thrown_value));
        result.error_line   = I->error_line;
        result.error_column = I->error_column;
        result.value = val_undefined();
        I->ctl = CTL_NONE;
    } else if (I->has_error) {
        result.status = I->last_status;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "%s", I->last_error);
        result.error_line   = I->error_line;
        result.error_column = I->error_column;
        result.value = val_undefined();
    } else {
        result.status = FLY_OK;
        result.value  = v;
    }

    parser_free_result(&pr);
    ast_free_arena();
    return result;
}

