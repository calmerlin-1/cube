/* flywheel/include/interp.h
 *
 * Public entry point for the Flywheel interpreter.
 *
 * Usage:
 *   Interp *I = flywheel_new();
 *   flywheel_load_natives(I);           // install console, Math, JSON
 *   FlyResult r = flywheel_eval(I, "1 + 2", "<input>");
 *   if (r.status == FLY_OK) val_print(r.value);
 *   else fprintf(stderr, "%s\n", r.error_msg);
 *   flywheel_free(I);
 */

#ifndef FLYWHEEL_INTERP_H
#define FLYWHEEL_INTERP_H

#include "value.h"
#include "object.h"
#include "env.h"
#include "../include/parser.h"

typedef enum {
    FLY_OK = 0,
    FLY_PARSE_ERROR,
    FLY_RUNTIME_ERROR,
    FLY_INTERNAL
} FlyStatus;

typedef struct {
    FlyStatus status;
    Value     value;         /* valid iff status == FLY_OK */
    char      error_msg[512];
    int       error_line;
    int       error_column;
} FlyResult;

struct Interp {
    Env      *globals;
    int       strict;
    /* call stack depth limit — prevents C stack overflow on deep recursion */
    int       call_depth;
    int       max_call_depth;

    /* Error state. Every runtime function checks has_error at entry
     * and returns a benign default if set. The first error wins. */
    int       has_error;
    FlyStatus last_status;
    char      last_error[512];
    int       error_line;
    int       error_column;

    /* Control flow signals — set by return/break/continue.
     * Cleared by the loop or function that handles them. */
    int       ctl;               /* CTL_NONE / CTL_RETURN / CTL_BREAK / CTL_CONTINUE */
    Value     return_value;

    /* Thrown value for CTL_THROW */
    Value     thrown_value;

    /* Method prototypes: string and array methods live here as
     * objects whose keys are method names and values are natives. */
    Object   *string_proto;
    Object   *array_proto;
    Object   *number_proto;

    /* Idempotency flag: natives are built once per Interp. */
    int       natives_loaded;

    /* Builtin object roots — freed in flywheel_free */
    Object   *console_obj;
    Object   *math_obj;
    Object   *json_obj;
    Object   *parseint_obj;

    /* Env free list — envs are recycled across function calls instead
     * of being malloc'd/freed each time. */
    Env      *env_free_list;

    /* Host data — opaque pointer set by an embedding engine.
     * The DOM module stores an html_document_t* here. */
    void     *host_data;
};

typedef enum {
    CTL_NONE     = 0,
    CTL_RETURN   = 1,
    CTL_BREAK    = 2,
    CTL_CONTINUE = 3,
    CTL_THROW    = 4,
} ControlSignal;

Interp *flywheel_new(void);
void    flywheel_free(Interp *I);

/* Evaluate source code as a script. */
FlyResult flywheel_eval(Interp *I, const char *source, const char *filename);

/* Register all built-ins: console, Object, Array, String, Math, JSON. */
void    flywheel_load_natives(Interp *I);

/* Error helper — public so builtins.c and other modules can report
 * errors the same way the interpreter does. Sets I->has_error (first
 * error wins), records line/column if `where` is non-NULL, returns
 * val_undefined() for convenient tail-call use. */
Value   flywheel_err(Interp *I, const char *msg, Node *where);
Value   flywheel_errf(Interp *I, Node *where, const char *fmt, ...);

/* Get/set a global by name (used by built-ins and tests). */
Value   flywheel_get_global(Interp *I, const char *name);
void    flywheel_set_global(Interp *I, const char *name, Value v);

#endif
