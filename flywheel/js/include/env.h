/* flywheel/include/env.h
 *
 * Lexical environments: variable bindings with parent chain.
 *
 * Lookup walks from current env up through parents.
 * Assignment walks parents too, but only succeeds on mutable bindings.
 * Definition always adds to THIS env.
 *
 * ERROR HANDLING: every function takes Interp* and follows the same
 * rules as object.c — no crashes, always reports, first error wins.
 */

#ifndef FLYWHEEL_ENV_H
#define FLYWHEEL_ENV_H

#include "value.h"

typedef struct Env Env;
typedef struct Interp Interp;

struct Env {
    char   **names;
    Value   *values;
    int     *mutable;
    int      count;
    int      capacity;
    Env     *parent;
    int      refcount;    /* every closure that captures this env bumps this */
};

/* Create a new env, optionally with a parent. Never returns NULL silently:
 * on OOM, sets I->has_error and returns NULL. */
Env   *env_new(Interp *I, Env *parent);

/* Free this env only (children/parent not affected). */
void   env_free(Env *e);

/* Free this env AND all ancestors. Use at interpreter shutdown. */
void   env_free_chain(Env *e);

/* Define a binding in THIS env. Overwrites if the name already exists
 * in this env. */
void   env_define(Interp *I, Env *e, const char *name, Value v, int is_mutable);

/* Look up a name walking the parent chain.
 * Returns 1 and writes *out on found. Returns 0 (no error) if not found.
 * Sets I->has_error on internal failure. */
int    env_lookup(Interp *I, Env *e, const char *name, Value *out);

/* Assign to an existing binding. Walks parent chain. Returns 1 on success.
 * Sets I->has_error if the binding exists but is not mutable.
 * Returns 0 if not found (no error). */
int    env_assign(Interp *I, Env *e, const char *name, Value v);

/* Bump refcount. Called by eval_func_decl when a closure captures
 * this env. Keeps the env alive past the defining stack frame. */
void   env_retain(Env *e);


/* Env recycle helpers: use the Interp free list to avoid
 * a malloc/free pair per function call. */
Env   *env_acquire(Interp *I, Env *parent);
void   env_release(Interp *I, Env *e);

#endif
