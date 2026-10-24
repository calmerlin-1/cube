/** check.c — external cc -fsyntax-only verification. */

#include "erdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Walk a directory, collect every dir containing at least one .h file. */
typedef struct {
    char **dirs;
    size_t n, cap;
} inc_list_t;

static int add_dir(inc_list_t *l, const char *dir) {
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->dirs[i], dir)) return 0;
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->dirs = erdict_xrealloc(l->dirs, l->cap * sizeof(*l->dirs));
    }
    l->dirs[l->n++] = erdict_xstrdup(dir);
    return 0;
}

static int scan_inc_cb(const char *path, void *ud) {
    inc_list_t *l = ud;
    if (!erdict_endswith(path, ".h")) return 0;
    const char *slash = strrchr(path, '/');
    if (!slash) return 0;
    size_t dlen = (size_t)(slash - path);
    char *dir = erdict_xstrndup(path, dlen);
    add_dir(l, dir);
    free(dir);
    return 0;
}

int erdict_scan_includes(const char *root, const char ***out, size_t *out_n) {
    const char *const suffixes[] = { ".h", NULL };
    inc_list_t l = {0};
    /* Always add root itself first: covers #include "subdir/header.h" */
    add_dir(&l, root);
    erdict_walk(root, suffixes, scan_inc_cb, &l);
    if (l.n == 0) { *out = NULL; *out_n = 0; return -1; }
    *out = (const char **)l.dirs;
    *out_n = l.n;
    return 0;
}
/* Search walker context for find_includer */
typedef struct {
    const char *hdr_base;   /* basename of header, e.g. "udp.h" */
    char       *out;
    size_t      out_len;
    int         found;
} find_inc_ctx_t;

static int find_inc_cb(const char *path, void *ud) {
    find_inc_ctx_t *c = ud;
    if (c->found) return 0;
    if (!erdict_endswith(path, ".c")) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "#include", 8)) continue;
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '"') continue;
        p++;
        char *q = strchr(p, '"');
        if (!q) continue;
        size_t nl = (size_t)(q - p);
        if (nl == strlen(c->hdr_base) &&
            !strncmp(p, c->hdr_base, nl)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    if (found) {
        size_t copy = strlen(path);
        if (copy >= c->out_len) copy = c->out_len - 1;
        memcpy(c->out, path, copy);
        c->out[copy] = 0;
        c->found = 1;
    }
    return 0;
}

int erdict_find_includer(const char *header_path, const char *root,
                         char *out_path, size_t out_len) {
    if (!header_path || !root || !out_path || out_len < 2) return -1;
    out_path[0] = 0;
    const char *base = strrchr(header_path, '/');
    base = base ? base + 1 : header_path;

    find_inc_ctx_t c = { base, out_path, out_len, 0 };
    const char *const suffixes[] = { ".c", NULL };
    erdict_walk(root, suffixes, find_inc_cb, &c);
    return c.found ? 0 : -1;
}

int erdict_check_external(const char *path, const char *cc, const char *cstd,
                          const char **incs, size_t n_incs) {
    if (!cc) cc = getenv("CC");
    if (!cc) cc = "cc";

    char cmd[4096];
    size_t w = 0;
    w += (size_t)snprintf(cmd + w, sizeof cmd - w, "%s -fsyntax-only", cc);
    if (cstd && *cstd)
        w += (size_t)snprintf(cmd + w, sizeof cmd - w, " -std=%s", cstd);
    w += (size_t)snprintf(cmd + w, sizeof cmd - w, " -I.");
    for (size_t i = 0; i < n_incs && w < sizeof cmd - 64; i++)
        w += (size_t)snprintf(cmd + w, sizeof cmd - w, " -I%s", incs[i]);
    snprintf(cmd + w, sizeof cmd - w, " %s 2>&1", path);

    FILE *p = popen(cmd, "r");
    if (!p) {
        erdict_err("cannot run %s", cc);
        return 4;
    }

    char line[1024];
    int saw_error = 0;
    int shown = 0;
    while (fgets(line, sizeof line, p)) {
        if (strstr(line, "error:") || strstr(line, "fatal error:") ||
            strstr(line, "Error:"))
        {
            saw_error = 1;
            if (shown < 15) {
                fprintf(stderr, "  %s", line);
                shown++;
            }
        }
    }
    pclose(p);
    return saw_error ? 1 : 0;
}

int erdict_mode_check(const erdict_file_t *f, const erdict_opts_t *o) {
    erdict_syntax_result_t r;
    int syn_ok = erdict_syntax_check(f, &r) == 0;

    printf("  %s%s%s\n", COL.bold, f->path, COL.reset);
    printf("  %ssyntax%s   %s%s%s\n",
           COL.cyan, COL.reset,
           syn_ok ? COL.green : COL.red,
           syn_ok ? "OK" : "FAIL",
           COL.reset);

    if (!syn_ok) {
        printf("  %scc%s       %sskipped (syntax failed)%s\n",
               COL.cyan, COL.reset, COL.yellow, COL.reset);
        return 1;
    }

    const char *all_incs[512];
    size_t n_all = 0;
    for (size_t i = 0; i < o->n_incs && n_all < 512; i++)
        all_incs[n_all++] = o->incs[i];
    if (o->n_cached_incs > 0) {
        for (size_t i = 0; i < o->n_cached_incs && n_all < 512; i++)
            all_incs[n_all++] = o->cached_incs[i];
    } else {
        for (size_t r = 0; r < o->n_includes_from; r++) {
            const char **dirs = NULL;
            size_t ndirs = 0;
            if (erdict_scan_includes(o->includes_from[r], &dirs, &ndirs) == 0) {
                for (size_t i = 0; i < ndirs && n_all < 512; i++)
                    all_incs[n_all++] = dirs[i];
            }
        }
    }
    if (o->no_cc_check) {
        printf("  %scc%s       %sskipped (--no-cc-check)%s\n",
               COL.cyan, COL.reset, COL.yellow, COL.reset);
        return syn_ok ? 0 : 1;
    }

    if (o->from_make && n_all < 512) {
        char mbuf[2048];
        /* Target: basename of file without extension */
        const char *base = strrchr(f->path, '/');
        base = base ? base + 1 : f->path;
        char tname[256];
        snprintf(tname, sizeof tname, "%s", base);
        char *dot = strrchr(tname, '.');
        if (dot) *dot = 0;
        if (erdict_make_incs(o->from_make, tname, mbuf, sizeof mbuf) == 0) {
            char *tok = strtok(mbuf, " ");
            while (tok && n_all < 512) {
                if (tok[0] == '-' && tok[1] == 'I' && tok[2]) {
                    all_incs[n_all++] = erdict_xstrdup(tok + 2);
                }
                tok = strtok(NULL, " ");
            }
        }
    }
    /* For .h files: find a .c that includes it and cc-check that instead.
     * A header alone is not a translation unit. */
    const char *check_target = f->path;
    char includer[1024] = {0};
    int cc_ok;
    if (erdict_endswith(f->path, ".h")) {
        const char *root = o->from_make ? o->from_make : ".";
        /* Search the header's own directory first; walk "." only as fallback */
        const char *hdr_dir = f->path;
        char hdr_dirbuf[512];
        const char *slash = strrchr(f->path, '/');
        if (slash) {
            size_t dlen = (size_t)(slash - f->path);
            if (dlen < sizeof hdr_dirbuf) {
                memcpy(hdr_dirbuf, f->path, dlen);
                hdr_dirbuf[dlen] = 0;
                hdr_dir = hdr_dirbuf;
            }
        }
        int found_inc = erdict_find_includer(f->path, hdr_dir, includer, sizeof includer);
        if (found_inc != 0) {
            /* Fallback: walk the whole root */
            found_inc = erdict_find_includer(f->path, root, includer, sizeof includer);
        }
        if (found_inc == 0) {
            check_target = includer;
        } else {
            /* No includer found — cannot verify. Skip cc with a note. */
            printf("  %scc%s       %sskipped (no .c includes this header)%s\n",
                   COL.cyan, COL.reset, COL.yellow, COL.reset);
            return syn_ok ? 0 : 1;
        }
    }
    cc_ok = erdict_check_external(check_target, NULL, NULL, all_incs, n_all) == 0;

    printf("  %scc%s       %s%s%s\n",
           COL.cyan, COL.reset,
           cc_ok ? COL.green : COL.red,
           cc_ok ? "OK" : "FAIL",
           COL.reset);

    return (syn_ok && cc_ok) ? 0 : 1;
}
