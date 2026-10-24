/** builtins_shared.c — process-wide native prototypes.
 * Every Interp shares these. Built once. */

#include "builtins_shared.h"
#include "../include/value.h"
#include "../include/interp.h"
#include <stdlib.h>
#include <string.h>

/* Native function declarations from builtins.c — declared extern here. */
extern Value native_console_log(Interp *, Value, Value *, int);
extern Value native_console_error(Interp *, Value, Value *, int);
extern Value native_math_floor(Interp *, Value, Value *, int);
extern Value native_math_ceil(Interp *, Value, Value *, int);
extern Value native_math_round(Interp *, Value, Value *, int);
extern Value native_math_abs(Interp *, Value, Value *, int);
extern Value native_math_max(Interp *, Value, Value *, int);
extern Value native_math_min(Interp *, Value, Value *, int);
extern Value native_math_pow(Interp *, Value, Value *, int);
extern Value native_math_sqrt(Interp *, Value, Value *, int);
extern Value native_math_random(Interp *, Value, Value *, int);
extern Value native_json_stringify(Interp *, Value, Value *, int);
extern Value native_string_upper(Interp *, Value, Value *, int);
extern Value native_string_lower(Interp *, Value, Value *, int);
extern Value native_string_charat(Interp *, Value, Value *, int);
extern Value native_string_slice(Interp *, Value, Value *, int);
extern Value native_string_indexof(Interp *, Value, Value *, int);
extern Value native_string_includes(Interp *, Value, Value *, int);
extern Value native_array_push(Interp *, Value, Value *, int);
extern Value native_array_pop(Interp *, Value, Value *, int);
extern Value native_array_join(Interp *, Value, Value *, int);
extern Value native_array_indexof(Interp *, Value, Value *, int);

static Object *g_console = NULL;
static Object *g_math = NULL;
static Object *g_json = NULL;
static Object *g_string_proto = NULL;
static Object *g_array_proto = NULL;
static int     g_initialized = 0;

/** Add a native function to a parent object. Uses NULL Interp — safe because
 * object_new/object_set only use Interp for error reporting. */
static void add_fn(Object *parent, const char *name, NativeFn fn) {
    if (!parent || !name || !fn) return;
    Object *fnobj = object_new(NULL);
    if (!fnobj) return;
    fnobj->native = fn;
    Value fv;
    fv.kind = VAL_FUNCTION;
    fv.as.object = fnobj;
    object_set(NULL, parent, name, fv);
}

void builtins_shared_init(void) {
    if (g_initialized) return;

    /* --- console --- */
    g_console = object_new(NULL);
    if (g_console) {
        add_fn(g_console, "log",   native_console_log);
        add_fn(g_console, "error", native_console_error);
    }

    /* --- Math --- */
    g_math = object_new(NULL);
    if (g_math) {
        add_fn(g_math, "floor",  native_math_floor);
        add_fn(g_math, "ceil",   native_math_ceil);
        add_fn(g_math, "round",  native_math_round);
        add_fn(g_math, "abs",    native_math_abs);
        add_fn(g_math, "max",    native_math_max);
        add_fn(g_math, "min",    native_math_min);
        add_fn(g_math, "pow",    native_math_pow);
        add_fn(g_math, "sqrt",   native_math_sqrt);
        add_fn(g_math, "random", native_math_random);
        object_set(NULL, g_math, "PI", val_number(3.14159265358979323846));
        object_set(NULL, g_math, "E",  val_number(2.71828182845904523536));
    }

    /* --- JSON --- */
    g_json = object_new(NULL);
    if (g_json) {
        add_fn(g_json, "stringify", native_json_stringify);
    }

    /* --- String prototype --- */
    g_string_proto = object_new(NULL);
    if (g_string_proto) {
        add_fn(g_string_proto, "toUpperCase", native_string_upper);
        add_fn(g_string_proto, "toLowerCase", native_string_lower);
        add_fn(g_string_proto, "charAt",      native_string_charat);
        add_fn(g_string_proto, "slice",       native_string_slice);
        add_fn(g_string_proto, "indexOf",     native_string_indexof);
        add_fn(g_string_proto, "includes",    native_string_includes);
    }

    /* --- Array prototype --- */
    g_array_proto = object_new(NULL);
    if (g_array_proto) {
        add_fn(g_array_proto, "push",    native_array_push);
        add_fn(g_array_proto, "pop",     native_array_pop);
        add_fn(g_array_proto, "join",    native_array_join);
        add_fn(g_array_proto, "indexOf", native_array_indexof);
    }

    g_initialized = 1;
}

Object *builtins_shared_console(void)      { return g_console; }
Object *builtins_shared_math(void)         { return g_math; }
Object *builtins_shared_json(void)         { return g_json; }
Object *builtins_shared_string_proto(void) { return g_string_proto; }
Object *builtins_shared_array_proto(void)  { return g_array_proto; }

void builtins_shared_shutdown(void) {
    /* Currently nothing — process exit reclaims everything.
     * Do not free: other Interps may still hold pointers. */
    g_initialized = 0;
}
