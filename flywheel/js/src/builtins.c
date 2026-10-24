/* flywheel/src/builtins.c
 *
 * Native functions: console, Math, JSON, string methods, array methods.
 *
 * ERROR DISCIPLINE: every native takes (Interp*, this_val, args, argc)
 * and returns a Value. On failure, sets I->has_error with a specific
 * message and returns val_undefined(). Nothing crashes.
 */

#include "../include/interp.h"
#include "builtins_shared.h"
#include "../include/object.h"
#include "../include/value.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ---------------------------------------------------------------- */
/* Console                                                          */
/* ---------------------------------------------------------------- */
Value native_console_log(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)this_val;
    for (int i = 0; i < argc; i++) {
        if (i > 0) printf(" ");
        if (args[i].kind == VAL_STRING) {
            printf("%s", args[i].as.string ? args[i].as.string : "");
        } else {
            printf("%s", val_to_cstr(args[i]));
        }
    }
    printf("\n");
    return val_undefined();
}

Value native_console_error(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)this_val;
    for (int i = 0; i < argc; i++) {
        if (i > 0) fprintf(stderr, " ");
        if (args[i].kind == VAL_STRING) fprintf(stderr, "%s", args[i].as.string ? args[i].as.string : "");
        else fprintf(stderr, "%s", val_to_cstr(args[i]));
    }
    fprintf(stderr, "\n");
    return val_undefined();
}

/* ---------------------------------------------------------------- */
/* Math                                                             */
/* ---------------------------------------------------------------- */
Value native_math_floor(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "Math.floor: needs 1 arg", NULL);
    return val_number(floor(val_to_number(a[0])));
}
Value native_math_ceil(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "Math.ceil: needs 1 arg", NULL);
    return val_number(ceil(val_to_number(a[0])));
}
Value native_math_round(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "Math.round: needs 1 arg", NULL);
    return val_number(round(val_to_number(a[0])));
}
Value native_math_abs(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "Math.abs: needs 1 arg", NULL);
    return val_number(fabs(val_to_number(a[0])));
}
Value native_math_max(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)t;
    if (n < 1) return val_number(-INFINITY);
    double m = val_to_number(a[0]);
    for (int i = 1; i < n; i++) {
        double v = val_to_number(a[i]);
        if (v > m) m = v;
    }
    return val_number(m);
}
Value native_math_min(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)t;
    if (n < 1) return val_number(INFINITY);
    double m = val_to_number(a[0]);
    for (int i = 1; i < n; i++) {
        double v = val_to_number(a[i]);
        if (v < m) m = v;
    }
    return val_number(m);
}
Value native_math_pow(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 2) return flywheel_err(I, "Math.pow: needs 2 args", NULL);
    return val_number(pow(val_to_number(a[0]), val_to_number(a[1])));
}
Value native_math_sqrt(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "Math.sqrt: needs 1 arg", NULL);
    return val_number(sqrt(val_to_number(a[0])));
}
Value native_math_random(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)t; (void)a; (void)n;
    return val_number((double)rand() / (double)RAND_MAX);
}

/* ---------------------------------------------------------------- */
/* JSON                                                             */
/* ---------------------------------------------------------------- */
static void json_write(Value v, char *buf, size_t *pos, size_t cap, int depth);

static void json_write_str(const char *s, char *buf, size_t *pos, size_t cap) {
    if (*pos + 2 >= cap) return;
    buf[(*pos)++] = '"';
    for (const char *p = s; *p; p++) {
        if (*pos + 6 >= cap) break;
        switch (*p) {
        case '"':  buf[(*pos)++]='\\'; buf[(*pos)++]='"';  break;
        case '\\': buf[(*pos)++]='\\'; buf[(*pos)++]='\\'; break;
        case '\n': buf[(*pos)++]='\\'; buf[(*pos)++]='n';  break;
        case '\t': buf[(*pos)++]='\\'; buf[(*pos)++]='t';  break;
        default:   buf[(*pos)++] = *p; break;
        }
    }
    if (*pos < cap) buf[(*pos)++] = '"';
}

static void json_write(Value v, char *buf, size_t *pos, size_t cap, int depth) {
    if (*pos + 2 >= cap) return;
    if (depth > 16) { return; }
    switch (v.kind) {
    case VAL_NULL:      if (*pos + 4 < cap) { memcpy(buf+*pos, "null", 4); *pos += 4; } break;
    case VAL_UNDEFINED: if (*pos + 4 < cap) { memcpy(buf+*pos, "null", 4); *pos += 4; } break;
    case VAL_BOOL: {
        const char *s = v.as.boolean ? "true" : "false";
        size_t l = strlen(s);
        if (*pos + l < cap) { memcpy(buf + *pos, s, l); *pos += l; }
        break;
    }
    case VAL_NUMBER: {
        char nb[64];
        double d = v.as.number;
        if (d == (long long)d && fabs(d) < 1e15) snprintf(nb, sizeof(nb), "%lld", (long long)d);
        else snprintf(nb, sizeof(nb), "%g", d);
        size_t l = strlen(nb);
        if (*pos + l < cap) { memcpy(buf + *pos, nb, l); *pos += l; }
        break;
    }
    case VAL_STRING:
        json_write_str(v.as.string ? v.as.string : "", buf, pos, cap);
        break;
    case VAL_OBJECT:
    case VAL_FUNCTION: {
        Object *o = (Object *)v.as.object;
        if (!o) { if (*pos + 4 < cap) { memcpy(buf+*pos, "null", 4); *pos += 4; } return; }
        if (o->is_array) {
            if (*pos < cap) buf[(*pos)++] = '[';
            for (int i = 0; i < o->length; i++) {
                if (i > 0 && *pos < cap) buf[(*pos)++] = ',';
                json_write(o->elements[i], buf, pos, cap, depth + 1);
            }
            if (*pos < cap) buf[(*pos)++] = ']';
        } else {
            if (*pos < cap) buf[(*pos)++] = '{';
            for (int i = 0; i < o->count; i++) {
                if (i > 0 && *pos < cap) buf[(*pos)++] = ',';
                json_write_str(o->keys[i], buf, pos, cap);
                if (*pos < cap) buf[(*pos)++] = ':';
                json_write(o->values[i], buf, pos, cap, depth + 1);
            }
            if (*pos < cap) buf[(*pos)++] = '}';
        }
        break;
    }
    }
}

Value native_json_stringify(Interp *I, Value t, Value *a, int n) {
    (void)t;
    if (n < 1) return flywheel_err(I, "JSON.stringify: needs 1 arg", NULL);
    size_t cap = 4096;
    char *buf = (char *)malloc(cap);
    if (!buf) return flywheel_err(I, "JSON.stringify: OOM", NULL);
    size_t pos = 0;
    json_write(a[0], buf, &pos, cap, 0);
    buf[pos < cap ? pos : cap - 1] = '\0';
    return val_string_take(buf);
}

/* ---------------------------------------------------------------- */
/* String methods                                                  */
/* ---------------------------------------------------------------- */
Value native_string_upper(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)a; (void)n;
    if (t.kind != VAL_STRING) return val_undefined();
    const char *s = t.as.string ? t.as.string : "";
    size_t l = strlen(s);
    char *out = (char *)malloc(l + 1);
    if (!out) return val_undefined();
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    out[l] = '\0';
    return val_string_take(out);
}

Value native_string_lower(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)a; (void)n;
    if (t.kind != VAL_STRING) return val_undefined();
    const char *s = t.as.string ? t.as.string : "";
    size_t l = strlen(s);
    char *out = (char *)malloc(l + 1);
    if (!out) return val_undefined();
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    out[l] = '\0';
    return val_string_take(out);
}

Value native_string_charat(Interp *I, Value t, Value *a, int n) {
    (void)I;
    if (t.kind != VAL_STRING) return val_undefined();
    if (n < 1) return flywheel_err(I, "charAt: needs index", NULL);
    const char *s = t.as.string ? t.as.string : "";
    int i = (int)val_to_number(a[0]);
    int l = (int)strlen(s);
    if (i < 0 || i >= l) return val_string("");
    char buf[2] = { s[i], 0 };
    return val_string(buf);
}

Value native_string_slice(Interp *I, Value t, Value *a, int n) {
    (void)I;
    if (t.kind != VAL_STRING) return val_undefined();
    const char *s = t.as.string ? t.as.string : "";
    int l = (int)strlen(s);
    int start = (n >= 1) ? (int)val_to_number(a[0]) : 0;
    int end   = (n >= 2) ? (int)val_to_number(a[1]) : l;
    if (start < 0) start = 0;
    if (end > l)   end = l;
    if (end < start) end = start;
    int len = end - start;
    char *out = (char *)malloc(len + 1);
    if (!out) return flywheel_err(I, "slice: OOM", NULL);
    memcpy(out, s + start, len);
    out[len] = '\0';
    return val_string_take(out);
}

Value native_string_indexof(Interp *I, Value t, Value *a, int n) {
    (void)I;
    if (t.kind != VAL_STRING) return val_number(-1);
    if (n < 1) return val_number(-1);
    const char *s = t.as.string ? t.as.string : "";
    const char *needle = val_to_cstr(a[0]);
    const char *found = strstr(s, needle);
    return val_number(found ? (double)(found - s) : -1);
}

Value native_string_includes(Interp *I, Value t, Value *a, int n) {
    (void)I;
    if (t.kind != VAL_STRING) return val_bool(0);
    if (n < 1) return val_bool(0);
    const char *s = t.as.string ? t.as.string : "";
    return val_bool(strstr(s, val_to_cstr(a[0])) != NULL);
}

/* ---------------------------------------------------------------- */
/* Array methods                                                   */
/* ---------------------------------------------------------------- */
static Value native_array_is_array(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)t;
    return val_bool(n > 0 && a[0].kind == VAL_OBJECT && a[0].as.object &&
                    ((Object *)a[0].as.object)->is_array);
}

Value native_array_push(Interp *I, Value t, Value *a, int n) {
    if (t.kind != VAL_OBJECT) return flywheel_err(I, "push: not an array", NULL);
    Object *arr = (Object *)t.as.object;
    if (!arr || !arr->is_array) return flywheel_err(I, "push: not an array", NULL);
    for (int i = 0; i < n; i++) array_push(I, arr, a[i]);
    return val_number(arr->length);
}

Value native_array_pop(Interp *I, Value t, Value *a, int n) {
    (void)I; (void)a; (void)n;
    if (t.kind != VAL_OBJECT) return val_undefined();
    Object *arr = (Object *)t.as.object;
    if (!arr || !arr->is_array) return val_undefined();
    if (arr->length == 0) return val_undefined();
    Value last = arr->elements[arr->length - 1];
    arr->length--;
    return last;
}

Value native_array_join(Interp *I, Value t, Value *a, int n) {
    if (t.kind != VAL_OBJECT) return flywheel_err(I, "join: not an array", NULL);
    Object *arr = (Object *)t.as.object;
    if (!arr || !arr->is_array) return flywheel_err(I, "join: not an array", NULL);

    const char *sep = (n >= 1) ? val_to_cstr(a[0]) : ",";
    size_t cap = 256, pos = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return flywheel_err(I, "join: OOM", NULL);
    buf[0] = '\0';

    for (int i = 0; i < arr->length; i++) {
        if (i > 0) {
            size_t sl = strlen(sep);
            while (pos + sl + 2 > cap) { cap *= 2; char *nn = realloc(buf, cap); if (!nn) { free(buf); return flywheel_err(I, "join: OOM", NULL); } buf = nn; }
            memcpy(buf + pos, sep, sl); pos += sl;
        }
        const char *vs = val_to_cstr(arr->elements[i]);
        size_t vl = strlen(vs);
        while (pos + vl + 2 > cap) { cap *= 2; char *nn = realloc(buf, cap); if (!nn) { free(buf); return flywheel_err(I, "join: OOM", NULL); } buf = nn; }
        memcpy(buf + pos, vs, vl); pos += vl;
    }
    buf[pos] = '\0';
    return val_string_take(buf);
}

Value native_array_indexof(Interp *I, Value t, Value *a, int n) {
    (void)I;
    if (t.kind != VAL_OBJECT) return val_number(-1);
    if (n < 1) return val_number(-1);
    Object *arr = (Object *)t.as.object;
    if (!arr || !arr->is_array) return val_number(-1);
    for (int i = 0; i < arr->length; i++) {
        if (val_strict_equals(arr->elements[i], a[0])) return val_number(i);
    }
    return val_number(-1);
}

/* ---------------------------------------------------------------- */
/* Register everything                                             */
/* ---------------------------------------------------------------- */
static void add_global_fn(Interp *I, Object *parent, const char *name, NativeFn fn) {
    Object *fnobj = object_new(I);
    if (!fnobj) return;
    fnobj->native = fn;
    Value fv; fv.kind = VAL_FUNCTION; fv.as.object = fnobj;
    object_set(I, parent, name, fv);
}

void flywheel_load_natives(Interp *I) {
    if (!I) return;
    if (I->natives_loaded) return;

    /* One-time global init of all shared prototypes. */
    builtins_shared_init();

    /* Attach the shared objects to this Interp by pointer. */
    I->console_obj  = builtins_shared_console();
    I->math_obj     = builtins_shared_math();
    I->json_obj     = builtins_shared_json();
    I->string_proto = builtins_shared_string_proto();
    I->array_proto  = builtins_shared_array_proto();

    /* Bind the three globals in the interpreter's global env.
     * The global utility functions (parseInt, etc.) still get built per-Interp
     * for now — they're few and cheap. */
    if (I->console_obj) {
        Value cv; cv.kind = VAL_OBJECT; cv.as.object = I->console_obj;
        env_define(I, I->globals, "console", cv, 1);
    }
    if (I->math_obj) {
        Value mv; mv.kind = VAL_OBJECT; mv.as.object = I->math_obj;
        env_define(I, I->globals, "Math", mv, 1);
    }
    if (I->json_obj) {
        Value jv; jv.kind = VAL_OBJECT; jv.as.object = I->json_obj;
        env_define(I, I->globals, "JSON", jv, 1);
    }

    {
        Object *ao = object_new(I);
        if (ao) {
            object_set_native(I, ao, "isArray", native_array_is_array);
            Value av; av.kind = VAL_OBJECT; av.as.object = ao;
            env_define(I, I->globals, "Array", av, 1);
        }
    }
    I->natives_loaded = 1;
}
