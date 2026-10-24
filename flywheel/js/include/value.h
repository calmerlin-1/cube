/* flywheel/include/value.h
 *
 * JavaScript values. Tagged union + string heap.
 *
 * Every Value is 16 bytes on 64-bit: a 4-byte tag, 4 bytes padding,
 * then either a double, a pointer, or an integer payload.
 *
 * Strings are heap-allocated (malloc'd). They are NOT garbage-collected
 * in v0. Every string created lives until flywheel_interp_free().
 * (Add GC later — correctness first.)
 */

#ifndef FLYWHEEL_VALUE_H
#define FLYWHEEL_VALUE_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    VAL_UNDEFINED = 0,
    VAL_NULL      = 1,
    VAL_BOOL      = 2,
    VAL_NUMBER    = 3,
    VAL_STRING    = 4,
    VAL_OBJECT    = 5,
    VAL_FUNCTION  = 6,
} ValueKind;

typedef struct Value {
    ValueKind kind;
    union {
        int     boolean;
        double  number;
        char   *string;     /* NUL-terminated, owned by interp */
        void   *object;     /* Object* — see object.h */
    } as;
} Value;

/* Constructors */
Value  val_undefined(void);
Value  val_null(void);
Value  val_bool(int b);
Value  val_number(double n);
Value  val_string(const char *s);      /* copies the string */
Value  val_string_take(char *s);        /* takes ownership, no copy */

/* Type checks */
int    val_is_undefined(Value v);
int    val_is_null(Value v);
int    val_is_nullish(Value v);
int    val_is_number(Value v);
int    val_is_string(Value v);
int    val_is_bool(Value v);
int    val_is_object(Value v);
int    val_is_callable(Value v);
int    val_is_truthy(Value v);

/* Type coercion */
double      val_to_number(Value v);

/* Inline hot coercions — called on every loop condition and arithmetic op.
 * Duplicated here for cross-TU inlining; the .c file keeps a non-inline
 * definition as a fallback for the linker. */
static inline int val_is_truthy_inline(Value v) {
    switch (v.kind) {
    case VAL_UNDEFINED: return 0;
    case VAL_NULL:      return 0;
    case VAL_BOOL:      return v.as.boolean != 0;
    case VAL_NUMBER:    return v.as.number != 0.0 && !(v.as.number != v.as.number);
    case VAL_STRING:    return v.as.string && v.as.string[0] != '\0';
    case VAL_OBJECT:
    case VAL_FUNCTION:  return 1;
    }
    return 0;
}

static inline double val_to_number_inline(Value v) {
    switch (v.kind) {
    case VAL_NUMBER:    return v.as.number;
    case VAL_BOOL:      return v.as.boolean ? 1.0 : 0.0;
    case VAL_NULL:      return 0.0;
    case VAL_UNDEFINED: return 0.0 / 0.0;    /* NaN */
    case VAL_STRING:    return 0.0;          /* handled by fallback */
    case VAL_OBJECT:
    case VAL_FUNCTION:  return 0.0 / 0.0;
    }
    return 0.0 / 0.0;
}

#define VAL_IS_TRUTHY(v)  val_is_truthy_inline(v)
/* Fast path only for numbers; everything else defers to the function. */
#define VAL_TO_NUMBER(v)  ((v).kind == VAL_NUMBER ? (v).as.number : val_to_number(v))
int         val_to_bool(Value v);
const char *val_to_cstr(Value v);       /* borrowed, valid until next call */
Value       val_to_string(Value v);      /* allocates a new string Value */

/* Equality (JS rules) */
int    val_strict_equals(Value a, Value b);
int    val_loose_equals(Value a, Value b);

/* Debug */
void   val_print(Value v);              /* to stdout, JS-ish format */

#endif
