/* flywheel/src/env.c
 *
 * Lexical environments. Same error-handling discipline as object.c.
 */

#include "../include/env.h"
#include "../include/interp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---------------------------------------------------------------- */
/* Local error helper (private to this file)                       */
/* ---------------------------------------------------------------- */
static void env_err(Interp *I, const char *msg) {
    if (I && !I->has_error) {
        I->has_error = 1;
        I->last_status = FLY_RUNTIME_ERROR;
        snprintf(I->last_error, sizeof(I->last_error), "%s", msg);
    }
}

/* ---------------------------------------------------------------- */
/* Lifecycle                                                       */
/* ---------------------------------------------------------------- */
Env *env_new(Interp *I, Env *parent) {
    if (I && I->has_error) return NULL;

    Env *e = (Env *)malloc(sizeof(Env));
    if (!e) {
        env_err(I, "env_new: out of memory");
        return NULL;
    }
    e->names    = NULL;
    e->values   = NULL;
    e->mutable  = NULL;
    e->count    = 0;
    e->capacity = 0;
    e->parent   = parent;
    e->refcount = 1;
    return e;
}

void env_free(Env *e) {
    if (!e) return;
    /* A closure may still hold a reference. Decrement; free only at 0. */
    if (e->refcount > 1) {
        e->refcount--;
        return;
    }
    for (int i = 0; i < e->count; i++) {
        free(e->names[i]);
        if (e->values[i].kind == VAL_STRING && e->values[i].as.string) {
            free(e->values[i].as.string);
        }
    }
    free(e->names);
    free(e->values);
    free(e->mutable);
    free(e);
}

void env_free_chain(Env *e) {
    while (e) {
        Env *parent = e->parent;
        env_free(e);
        e = parent;
    }
}

/* ---------------------------------------------------------------- */
/* Growth                                                          */
/* ---------------------------------------------------------------- */
static int env_grow(Interp *I, Env *e) {
    int new_cap = e->capacity ? e->capacity * 2 : 8;

    char **nn = (char **)realloc(e->names, sizeof(char *) * new_cap);
    if (!nn) { env_err(I, "env_grow: realloc names failed"); return 0; }
    e->names = nn;

    Value *nv = (Value *)realloc(e->values, sizeof(Value) * new_cap);
    if (!nv) { env_err(I, "env_grow: realloc values failed"); return 0; }
    e->values = nv;

    int *nm = (int *)realloc(e->mutable, sizeof(int) * new_cap);
    if (!nm) { env_err(I, "env_grow: realloc mutable failed"); return 0; }
    e->mutable = nm;

    e->capacity = new_cap;
    return 1;
}

/* ---------------------------------------------------------------- */
/* Find in THIS env                                                */
/* ---------------------------------------------------------------- */
static int env_find(Env *e, const char *name) {
    for (int i = 0; i < e->count; i++) {
        if (strcmp(e->names[i], name) == 0) return i;
    }
    return -1;
}

/* ---------------------------------------------------------------- */
/* Define — this env only                                          */
/* ---------------------------------------------------------------- */
void env_define(Interp *I, Env *e, const char *name, Value v, int is_mutable) {
    if (I && I->has_error) return;
    if (!e || !name) { env_err(I, "env_define: null env or name"); return; }

    int idx = env_find(e, name);
    if (idx >= 0) {
        /* Overwrite existing */
        if (e->values[idx].kind == VAL_STRING && e->values[idx].as.string) {
            free(e->values[idx].as.string);
        }
        e->values[idx]  = v;
        e->mutable[idx] = is_mutable;
        return;
    }

    if (e->count >= e->capacity) {
        if (!env_grow(I, e)) return;
    }

    e->names[e->count]   = strdup(name);
    e->values[e->count]  = v;
    e->mutable[e->count] = is_mutable;
    e->count++;
}

/* ---------------------------------------------------------------- */
/* Lookup — walks parent chain                                     */
/* ---------------------------------------------------------------- */
int env_lookup(Interp *I, Env *e, const char *name, Value *out) {
    if (I && I->has_error) return 0;
    if (!e || !name) { env_err(I, "env_lookup: null env or name"); return 0; }

    for (Env *cur = e; cur; cur = cur->parent) {
        int idx = env_find(cur, name);
        if (idx >= 0) {
            if (out) *out = cur->values[idx];
            return 1;
        }
    }
    return 0;   /* not found is NOT an error */
}

/* ---------------------------------------------------------------- */
/* Assign — walks parent chain                                     */
/* ---------------------------------------------------------------- */
int env_assign(Interp *I, Env *e, const char *name, Value v) {
    if (I && I->has_error) return 0;
    if (!e || !name) { env_err(I, "env_assign: null env or name"); return 0; }

    for (Env *cur = e; cur; cur = cur->parent) {
        int idx = env_find(cur, name);
        if (idx >= 0) {
            if (!cur->mutable[idx]) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "assignment to constant variable '%s'", name);
                env_err(I, buf);
                return 0;
            }
            if (cur->values[idx].kind == VAL_STRING && cur->values[idx].as.string) {
                free(cur->values[idx].as.string);
            }
            cur->values[idx] = v;
            return 1;
        }
    }
    return 0;   /* not found is NOT an error at this layer */
}

/* Bump the reference count. Called when a closure captures this env. */
void env_retain(Env *e) {
    if (e) e->refcount++;
}

/* ---------------------------------------------------------------- */
/* Env free list — recycle envs across function calls               */
/* ---------------------------------------------------------------- */
Env *env_acquire(Interp *I, Env *parent) {
    if (!I) return env_new(NULL, parent);
    Env *e = I->env_free_list;
    if (e) {
        I->env_free_list = (Env *)e->parent;   /* parent slot used as next link */
        e->count    = 0;
        e->parent   = parent;
        e->refcount = 1;
        return e;
    }
    return env_new(I, parent);
}

void env_release(Interp *I, Env *e) {
    if (!e) return;
    /* If a closure captured this env, just decrement — the env must
     * survive as long as the closure does. */
    if (e->refcount > 1) {
        e->refcount--;
        return;
    }
    if (!I) {
        env_free(e);
        return;
    }
    /* Recycle: hang it on the free list via the parent slot */
    e->parent = (Env *)I->env_free_list;
    I->env_free_list = e;
}
