/** tree.c — walk a directory, run a per-file mode, aggregate. */

#include "erdict.h"
#include "symbols.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    size_t *bad;
    const erdict_opts_t *opts;
} tree_ctx_t;

static int run_lint_one(const char *path, void *ud) {
    tree_ctx_t *ctx = ud;
    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;
    erdict_opts_t dummy;
    memset(&dummy, 0, sizeof dummy);
    if (erdict_mode_lint(&f, &dummy) != 0) (*ctx->bad)++;
    erdict_file_free(&f);
    return 0;
}

static int run_syntax_one(const char *path, void *ud) {
    tree_ctx_t *ctx = ud;
    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;
    erdict_opts_t dummy;
    memset(&dummy, 0, sizeof dummy);
    if (erdict_mode_syntax(&f, &dummy) != 0) (*ctx->bad)++;
    erdict_file_free(&f);
    return 0;
}

static int run_check_one(const char *path, void *ud) {
    tree_ctx_t *ctx = ud;
    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;
    if (erdict_mode_check(&f, ctx->opts) != 0) (*ctx->bad)++;
    erdict_file_free(&f);
    return 0;
}

static int run_callers_one(const char *path, void *ud) {
    tree_ctx_t *ctx = ud;
    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;
    erdict_opts_t local = *ctx->opts;
    local.quiet_zero = 1;
    erdict_mode_callers(&f, &local);
    erdict_file_free(&f);
    return 0;
}

/* Silent per-file check: does this file define the named function?
 * Uses the same semi/brace heuristic as --section. */
static int file_defines(const erdict_file_t *f, const char *name) {
    erdict_sym_t *syms = NULL;
    size_t n = 0;
    if (erdict_symbols_scan(f, &syms, &n) != 0) return 0;
    int found = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind != ERDICT_SYM_FUNC) continue;
        if (strcmp(syms[i].name, name)) continue;
        size_t ln = syms[i].line_no;
        if (ln < 1 || ln > f->n_lines) continue;
        const erdict_line_t *L = &f->lines[ln - 1];
        const char *semi  = memchr(L->p, ';', L->len);
        const char *brace = memchr(L->p, '{', L->len);
        if (!semi || brace) { found = 1; break; }
    }
    free(syms);
    return found;
}

static int run_callees_one(const char *path, void *ud) {
    tree_ctx_t *ctx = ud;
    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;
    if (ctx->opts->pattern && !file_defines(&f, ctx->opts->pattern)) {
        erdict_file_free(&f);
        return 0;
    }
    erdict_mode_callees(&f, ctx->opts);   /* informational, not a failure */
    erdict_file_free(&f);
    return 0;
}

int erdict_mode_tree(const erdict_opts_t *o) {
    const char *const suffixes[] = { ".c", ".h", NULL };
    size_t bad = 0;
    tree_ctx_t ctx = { &bad, o };
    int (*cb)(const char *, void *) = NULL;

    if      (!strcmp(o->mode, "lint"))    cb = run_lint_one;
    else if (!strcmp(o->mode, "syntax"))  cb = run_syntax_one;
    else if (!strcmp(o->mode, "check"))   cb = run_check_one;
    else if (!strcmp(o->mode, "callers")) cb = run_callers_one;
    else if (!strcmp(o->mode, "callees")) cb = run_callees_one;
    else { erdict_err("tree mode: unknown --%s", o->mode); return 2; }

    /* Cache include discovery: scan --includes-from roots ONCE, not per file */
    const char *cache_buf[4096];
    size_t n_cache = 0;
    for (size_t r = 0; r < o->n_includes_from; r++) {
        const char **dirs = NULL;
        size_t ndirs = 0;
        if (erdict_scan_includes(o->includes_from[r], &dirs, &ndirs) == 0) {
            for (size_t i = 0; i < ndirs && n_cache < 4096; i++)
                cache_buf[n_cache++] = dirs[i];
        }
    }
    erdict_opts_t *o_mut = (erdict_opts_t *)o;
    o_mut->cached_incs = cache_buf;
    o_mut->n_cached_incs = n_cache;

    for (size_t i = 0; i < o->n_files; i++)
        erdict_walk(o->files[i], suffixes, cb, &ctx);

    if (bad) {
        printf("\n  %s%zu files with issues%s\n", COL.red, bad, COL.reset);
        return 1;
    }
    printf("\n  %sall clean%s\n", COL.green, COL.reset);
    return 0;
}
