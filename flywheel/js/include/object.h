/* flywheel/include/object.h
 *
 * JavaScript objects. Key-value maps with a prototype pointer.
 *
 * ERROR HANDLING: every function takes Interp* and returns a status or
 * a Value. Nothing crashes. On failure, Interp->has_error is set with
 * a specific message and line/column, and callers propagate.
 */

#ifndef FLYWHEEL_OBJECT_H
#define FLYWHEEL_OBJECT_H

#include "value.h"
#include <stddef.h>

typedef struct Object   Object;
typedef struct Interp   Interp;

/* Native function signature: called when a built-in method is invoked.
 * `this_val` is the receiver. Return val_undefined() and set I->has_error
 * on failure — do not crash. */
typedef Value (*NativeFn)(Interp *I, Value this_val, Value *args, int argc);

struct Object {
    char     **keys;
    Value     *values;
    int        count;
    int        capacity;

    /* Contiguous array storage — used when is_array == 1.
     * Array elements are NOT stored in keys/values. */
    Value     *elements;
    int        length;
    int        elem_capacity;

    Object    *prototype;      /* may be NULL */

    /* Optional accessor maps (name -> native function). Checked before
     * plain property reads/writes, so host objects can expose live
     * properties such as DOM textContent without special-casing the
     * interpreter. */
    Object    *getters;
    Object    *setters;

    /* Native method payload (if this object IS a callable native). */
    NativeFn   native;

    /* Array flag. Arrays are objects whose keys are "0", "1", ... */
    int        is_array;

    /* SHAPE — a hash of (keys in order). Same set of keys inserted in
     * the same order → same shape. Used by property access caching:
     * if (obj->shape == cached_shape) → read cached_slot directly. */
    uint32_t   shape;

    /* User function payload. */
    void      *fn_node;        /* AST FuncNode */
    void      *closure;        /* Env* captured at definition */

    /* Bound receiver — when a method is extracted from a primitive
     * (like "abc".toUpperCase), this Value holds the receiver so the
     * native can operate on it. Kind == VAL_UNDEFINED when unbound. */
    Value      bound_this;
};

/* Lifecycle */
Object *object_new(Interp *I);
void    object_free(Object *o);   /* recursive? no — flat, prototype not freed */

/* Property access Every function sets I->has_error on internal failure. */
Value   object_get(Interp *I, Object *o, const char *key);
Value   object_get_index(Interp *I, Object *o, int idx);
void    object_set(Interp *I, Object *o, const char *key, Value v);
int     object_has(Interp *I, Object *o, const char *key);
void    object_delete(Interp *I, Object *o, const char *key);

/* Convenience: define a native method on an object. */
void    object_set_native(Interp *I, Object *o, const char *name, NativeFn fn);

/* Native accessors: reading/writing `name` calls fn(this=o, args...). */
void    object_set_getter(Interp *I, Object *o, const char *name, NativeFn fn);
void    object_set_setter(Interp *I, Object *o, const char *name, NativeFn fn);

/* Arrays (Object with is_array = 1, keys are decimal strings) */
Object *array_new(Interp *I);
int     array_length(Interp *I, Object *arr);
Value   array_get(Interp *I, Object *arr, int i);
void    array_push(Interp *I, Object *arr, Value v);
void    array_set(Interp *I, Object *arr, int i, Value v);

/* Debug */
void    object_print(Object *o);

#endif
