/** dbug.h — static + trace + crash analyzer for C source. */
#ifndef CUBE_TOOLS_DBUG_H
#define CUBE_TOOLS_DBUG_H

#include <stddef.h>
#include "sear.h"

#define DBUG_VERSION "0.1"

typedef enum {
    DBUG_MODE_STATIC,
    DBUG_MODE_TRACE,
    DBUG_MODE_CRASH
} dbug_mode_t;

typedef struct {
    dbug_mode_t  mode;
    const char  *file;       /* input: source file (static) or log (crash) */
    const char  *prog;       /* trace: binary to run */
    const char **args;       /* trace: child argv (excluding prog) */
    int          n_args;
    int          color;
    int          verbose;
} dbug_opts_t;

/* ---- per pass ---- */
int dbug_static(const dbug_opts_t *o);
int dbug_trace (const dbug_opts_t *o);
int dbug_crash (const dbug_opts_t *o);
int dbug_build (const dbug_opts_t *o);

void dbug_usage(void);

/* ---- helpers shared across passes ---- */
int dbug_is_ident(int c);
int dbug_is_keyword(const char *name, size_t len);
/* Return 1 if `name` is a known risky libc call. */
int dbug_is_risky(const char *name);
/* Find the line index of the closing brace that matches the opening
 * brace on or after `start`. Returns `start` if none found. */
size_t dbug_body_end(const sear_file_t *f, size_t start);

#endif
