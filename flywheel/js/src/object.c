/* flywheel/src/object.c
 *
 * Object model. Property storage, prototype chain, arrays.
 *
 * ERROR HANDLING: every public function checks Interp->has_error at
 * entry (fast bail if already failed) and sets it on failure. Never
 * crashes. Never exits. Always leaves a message + position.
 */

#include "../include/object.h"
#include "../include/interp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ---------------------------------------------------------------- */
/* Error helper — private to this file. Set once, first error wins. */
/* ---------------------------------------------------------------- */
static Value obj_err(Interp *I, const char *msg) {
    if (I && !I->has_error) {
        I->has_error = 1;
        I->last_status = FLY_RUNTIME_ERROR;
        snprintf(I->last_error, sizeof(I->last_error), "%s", msg);
    }
    return val_undefined();
}

/* ---------------------------------------------------------------- */
/* Lifecycle                                                       */
/* ---------------------------------------------------------------- */
Object *object_new(Interp *I) {
    if (I && I->has_error) return NULL;

    Object *o = (Object *)malloc(sizeof(Object));
    if (!o) {
        if (I) obj_err(I, "object_new: out of memory");
        return NULL;
    }
    o->keys      = NULL;
    o->values    = NULL;
    o->count     = 0;
    o->capacity  = 0;
    o->elements      = NULL;
    o->length        = 0;
    o->elem_capacity = 0;
    o->shape         = 0;
    o->prototype = NULL;
    o->native    = NULL;
    o->is_array  = 0;
    o->fn_node   = NULL;
    o->closure   = NULL;
    o->bound_this = val_undefined();
    return o;
}

static void object_free_depth(Object *o, int depth) {
    if (!o || depth > 32) return;
    if (o->elements) { free(o->elements); o->elements = NULL; }
    for (int i = 0; i < o->count; i++) {
        free(o->keys[i]);
        Value v = o->values[i];
        if (v.kind == VAL_STRING && v.as.string) {
            free(v.as.string);
        } else if ((v.kind == VAL_OBJECT || v.kind == VAL_FUNCTION) && v.as.object) {
            object_free_depth(v.as.object, depth + 1);
        }
    }
    free(o->keys);
    free(o->values);
    free(o);
    /* prototype intentionally NOT freed — it is often shared. */
}

void object_free(Object *o) {
    object_free_depth(o, 0);
}

/* ---------------------------------------------------------------- */
/* Property table growth                                           */
/* ---------------------------------------------------------------- */
static int object_grow(Interp *I, Object *o) {
    int new_cap = o->capacity ? o->capacity * 2 : 8;
    char **nk = (char **)realloc(o->keys,   sizeof(char *) * new_cap);
    if (!nk) { obj_err(I, "object_grow: realloc keys failed"); return 0; }
    o->keys = nk;
    Value *nv = (Value *)realloc(o->values, sizeof(Value) * new_cap);
    if (!nv) { obj_err(I, "object_grow: realloc values failed"); return 0; }
    o->values = nv;
    o->capacity = new_cap;
    return 1;
}

/* ---------------------------------------------------------------- */
/* Key lookup                                                      */
/* ---------------------------------------------------------------- */
/* Compute the shape of an object — FNV-1a over the ordered keys. */
static uint32_t object_compute_shape(Object *o) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < o->count; i++) {
        const char *k = o->keys[i];
        while (*k) { h ^= (uint8_t)*k++; h *= 16777619u; }
        h ^= 0xFF; h *= 16777619u;
    }
    return h;
}

static int object_find(Object *o, const char *key) {
    for (int i = 0; i < o->count; i++) {
        if (strcmp(o->keys[i], key) == 0) return i;
    }
    return -1;
}

/* ---------------------------------------------------------------- */
/* Get — walks prototype chain                                     */
/* ---------------------------------------------------------------- */
Value object_get(Interp *I, Object *o, const char *key) {
    if (I && I->has_error) return val_undefined();
    if (!o || !key) return obj_err(I, "object_get: null object or key");

    /* Own property */
    int idx = object_find(o, key);
    if (idx >= 0) return o->values[idx];

    /* Prototype chain */
    if (o->prototype) {
        return object_get(I, o->prototype, key);
    }
    return val_undefined();
}

Value object_get_index(Interp *I, Object *o, int idx) {
    if (I && I->has_error) return val_undefined();
    if (!o) return obj_err(I, "object_get_index: null object");
    if (o->is_array) {
        if (idx < 0 || idx >= o->count) return val_undefined();
        return o->values[idx];
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", idx);
    return object_get(I, o, buf);
}

/* ---------------------------------------------------------------- */
/* Set — creates or updates own property                           */
/* ---------------------------------------------------------------- */
void object_set(Interp *I, Object *o, const char *key, Value v) {
    if (I && I->has_error) return;
    if (!o || !key) { obj_err(I, "object_set: null object or key"); return; }

    int idx = object_find(o, key);
    if (idx >= 0) {
        /* Free old string value if present */
        if (o->values[idx].kind == VAL_STRING && o->values[idx].as.string) {
            free(o->values[idx].as.string);
        }
        o->values[idx] = v;
        return;
    }

    if (o->count >= o->capacity) {
        if (!object_grow(I, o)) return;
    }
    o->keys[o->count]   = strdup(key);
    o->values[o->count] = v;
    o->count++;
    o->shape = object_compute_shape(o);
}

/* ---------------------------------------------------------------- */
/* Has / Delete                                                    */
/* ---------------------------------------------------------------- */
int object_has(Interp *I, Object *o, const char *key) {
    if (I && I->has_error) return 0;
    if (!o || !key) { obj_err(I, "object_has: null object or key"); return 0; }
    if (object_find(o, key) >= 0) return 1;
    if (o->prototype) return object_has(I, o->prototype, key);
    return 0;
}

void object_delete(Interp *I, Object *o, const char *key) {
    if (I && I->has_error) return;
    if (!o || !key) { obj_err(I, "object_delete: null object or key"); return; }

    int idx = object_find(o, key);
    if (idx < 0) return;

    free(o->keys[idx]);
    if (o->values[idx].kind == VAL_STRING && o->values[idx].as.string) {
        free(o->values[idx].as.string);
    }
    /* Shift left */
    for (int i = idx; i < o->count - 1; i++) {
        o->keys[i]   = o->keys[i + 1];
        o->values[i] = o->values[i + 1];
    }
    o->count--;
}

/* ---------------------------------------------------------------- */
/* Native method helper                                            */
/* ---------------------------------------------------------------- */
void object_set_native(Interp *I, Object *o, const char *name, NativeFn fn) {
    if (I && I->has_error) return;
    if (!o || !name || !fn) { obj_err(I, "object_set_native: null argument"); return; }

    /* Create a function-like object that holds the native pointer */
    Object *fnobj = object_new(I);
    if (!fnobj) return;
    fnobj->native = fn;
    Value fv;
    fv.kind = VAL_FUNCTION;
    fv.as.object = fnobj;
    object_set(I, o, name, fv);
}

/* ---------------------------------------------------------------- */
/* Arrays                                                          */
/* ---------------------------------------------------------------- */
Object *array_new(Interp *I) {
    if (I && I->has_error) return NULL;
    Object *o = object_new(I);
    if (!o) return NULL;
    o->is_array = 1;
    return o;
}

int array_length(Interp *I, Object *arr) {
    (void)I;
    if (!arr || !arr->is_array) return 0;
    return arr->length;
}

Value array_get(Interp *I, Object *arr, int i) {
    (void)I;
    if (!arr || !arr->is_array) return val_undefined();
    if (i < 0 || i >= arr->length) return val_undefined();
    return arr->elements[i];
}

void array_set(Interp *I, Object *arr, int i, Value v) {
    if (!arr || !arr->is_array) return;
    if (i < 0) return;
    if (i >= arr->elem_capacity) {
        int nc = arr->elem_capacity ? arr->elem_capacity * 2 : 8;
        while (nc <= i) nc *= 2;
        Value *ne = (Value *)realloc(arr->elements, nc * sizeof(Value));
        if (!ne) { obj_err(I, "array_set: OOM"); return; }
        arr->elements = ne;
        arr->elem_capacity = nc;
    }
    if (i >= arr->length) {
        for (int j = arr->length; j < i; j++) arr->elements[j] = val_undefined();
        arr->length = i + 1;
    }
    arr->elements[i] = v;
}

void array_push(Interp *I, Object *arr, Value v) {
    if (!arr || !arr->is_array) return;
    if (arr->length >= arr->elem_capacity) {
        int nc = arr->elem_capacity ? arr->elem_capacity * 2 : 8;
        Value *ne = (Value *)realloc(arr->elements, nc * sizeof(Value));
        if (!ne) { obj_err(I, "array_push: OOM"); return; }
        arr->elements = ne;
        arr->elem_capacity = nc;
    }
    arr->elements[arr->length++] = v;
}

/* ---------------------------------------------------------------- */
/* Debug                                                           */
/* ---------------------------------------------------------------- */
void object_print(Object *o) {
    if (!o) { printf("null"); return; }
    if (o->is_array) {
        printf("[");
        for (int i = 0; i < o->count; i++) {
            if (i > 0) printf(", ");
            val_print(o->values[i]);
        }
        printf("]");
        return;
    }
    printf("{");
    for (int i = 0; i < o->count; i++) {
        if (i > 0) printf(", ");
        printf("%s: ", o->keys[i]);
        val_print(o->values[i]);
    }
    printf("}");
}
