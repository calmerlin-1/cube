/* flywheel/src/value.c
 *
 * Value constructors, type checks, coercion, equality, printing.
 */

#include "../include/value.h"
#include "../include/object.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* Constructors                                                  */
Value val_undefined(void) { Value v; v.kind = VAL_UNDEFINED; v.as.number = 0; return v; }
Value val_null(void)      { Value v; v.kind = VAL_NULL;      v.as.number = 0; return v; }
Value val_bool(int b)     { Value v; v.kind = VAL_BOOL;      v.as.boolean = b ? 1 : 0; return v; }
Value val_number(double n){ Value v; v.kind = VAL_NUMBER;    v.as.number = n; return v; }

Value val_string(const char *s) {
    Value v;
    v.kind = VAL_STRING;
    v.as.string = s ? strdup(s) : NULL;
    if (!v.as.string) { v.kind = VAL_STRING; v.as.string = NULL; }
    return v;
}

Value val_string_take(char *s) {
    Value v;
    v.kind = VAL_STRING;
    v.as.string = s;
    return v;
}

/* Type checks                                                   */
int val_is_undefined(Value v) { return v.kind == VAL_UNDEFINED; }
int val_is_null(Value v)      { return v.kind == VAL_NULL; }
int val_is_nullish(Value v)   { return v.kind == VAL_UNDEFINED || v.kind == VAL_NULL; }
int val_is_number(Value v)    { return v.kind == VAL_NUMBER; }
int val_is_string(Value v)    { return v.kind == VAL_STRING; }
int val_is_bool(Value v)      { return v.kind == VAL_BOOL; }
int val_is_object(Value v)    { return v.kind == VAL_OBJECT || v.kind == VAL_FUNCTION; }
int val_is_callable(Value v)  { return v.kind == VAL_FUNCTION; }

int val_is_truthy(Value v) {
    switch (v.kind) {
    case VAL_UNDEFINED: return 0;
    case VAL_NULL:      return 0;
    case VAL_BOOL:      return v.as.boolean != 0;
    case VAL_NUMBER:    return v.as.number != 0.0 && !isnan(v.as.number);
    case VAL_STRING:    return v.as.string && v.as.string[0] != '\0';
    case VAL_OBJECT:
    case VAL_FUNCTION:  return 1;
    }
    return 0;
}

/* Coercion                                                      */
double val_to_number(Value v) {
    switch (v.kind) {
    case VAL_UNDEFINED: return NAN;
    case VAL_NULL:      return 0.0;
    case VAL_BOOL:      return v.as.boolean ? 1.0 : 0.0;
    case VAL_NUMBER:    return v.as.number;
    case VAL_STRING: {
        if (!v.as.string) return 0.0;
        char *end = NULL;
        double d = strtod(v.as.string, &end);
        if (end == v.as.string) return NAN;
        return d;
    }
    case VAL_OBJECT:
    case VAL_FUNCTION:  return NAN;
    }
    return NAN;
}

int val_to_bool(Value v) { return val_is_truthy(v); }

const char *val_to_cstr(Value v) {
    static char buf[64];
    switch (v.kind) {
    case VAL_UNDEFINED: return "undefined";
    case VAL_NULL:      return "null";
    case VAL_BOOL:      return v.as.boolean ? "true" : "false";
    case VAL_NUMBER: {
        double n = v.as.number;
        if (isnan(n)) return "NaN";
        if (isinf(n)) return n < 0 ? "-Infinity" : "Infinity";
        if (n == (long long)n && fabs(n) < 1e15) {
            snprintf(buf, sizeof(buf), "%lld", (long long)n);
        } else {
            snprintf(buf, sizeof(buf), "%g", n);
        }
        return buf;
    }
    case VAL_STRING:    return v.as.string ? v.as.string : "";
    case VAL_OBJECT:    return "[object Object]";
    case VAL_FUNCTION:  return "[function]";
    }
    return "?";
}

Value val_to_string(Value v) {
    switch (v.kind) {
    case VAL_STRING: return v;
    default:         return val_string(val_to_cstr(v));
    }
}

/* Equality                                                      */
int val_strict_equals(Value a, Value b) {
    if (a.kind != b.kind) return 0;
    switch (a.kind) {
    case VAL_UNDEFINED:
    case VAL_NULL:      return 1;
    case VAL_BOOL:      return a.as.boolean == b.as.boolean;
    case VAL_NUMBER:    return a.as.number == b.as.number;  /* NaN != NaN */
    case VAL_STRING: {
        if (!a.as.string && !b.as.string) return 1;
        if (!a.as.string || !b.as.string) return 0;
        return strcmp(a.as.string, b.as.string) == 0;
    }
    case VAL_OBJECT:
    case VAL_FUNCTION:  return a.as.object == b.as.object;
    }
    return 0;
}

int val_loose_equals(Value a, Value b) {
    if (a.kind == b.kind) return val_strict_equals(a, b);
    if (val_is_nullish(a) && val_is_nullish(b)) return 1;
    if (val_is_nullish(a) || val_is_nullish(b)) return 0;
    /* number vs string */
    if (a.kind == VAL_NUMBER && b.kind == VAL_STRING)
        return a.as.number == val_to_number(b);
    if (a.kind == VAL_STRING && b.kind == VAL_NUMBER)
        return val_to_number(a) == b.as.number;
    /* bool coerces to number */
    if (a.kind == VAL_BOOL) return val_loose_equals(val_number(a.as.boolean), b);
    if (b.kind == VAL_BOOL) return val_loose_equals(a, val_number(b.as.boolean));
    return 0;
}

/* Debug                                                         */
void val_print(Value v) {
    switch (v.kind) {
    case VAL_STRING: printf("%s", v.as.string ? v.as.string : ""); break;
    default:         printf("%s", val_to_cstr(v)); break;
    }
}
