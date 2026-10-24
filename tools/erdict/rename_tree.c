/** rename_tree.c — cross-file identifier rename with rollback. */

#include "erdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char   *path;
    char   *old_buf;
    size_t  old_len;
    char   *new_buf;
    size_t  new_len;
    size_t  hits;
} file_change_t;

typedef struct {
    file_change_t *changes;
    size_t n;
    size_t cap;
    const char *old_name;
    const char *new_name;
    size_t old_len;
    size_t new_len;
    int    no_cc_check;
    const char **incs;
    size_t n_incs;
    int    err;
} rt_ctx_t;

static int ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int id_at(const char *line, size_t len, size_t pos,
                 const char *name, size_t name_len) {
    if (pos + name_len > len) return 0;
    if (memcmp(line + pos, name, name_len) != 0) return 0;
    if (pos > 0 && ident_char(line[pos-1])) return 0;
    if (pos + name_len < len && ident_char(line[pos+name_len])) return 0;
    return 1;
}

static char *read_raw(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = erdict_xmalloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = 0;
    if (out_len) *out_len = got;
    return buf;
}

/* Scan one file: count occurrences, build renamed content if any. */
static int prep_file(rt_ctx_t *c, const char *path) {
    size_t old_len = 0;
    char *old = read_raw(path, &old_len);
    if (!old) return 0;

    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) { free(old); return 0; }

    size_t hits = 0;
    for (size_t i = 0; i < f.n_lines; i++) {
        erdict_line_t *l = &f.lines[i];
        size_t j = 0;
        while (j + c->old_len <= l->len) {
            if (id_at(l->p, l->len, j, c->old_name, c->old_len)) { hits++; j += c->old_len; }
            else j++;
        }
    }
    if (hits == 0) { erdict_file_free(&f); free(old); return 0; }

    size_t cap = f.buf_len + hits * (c->new_len > c->old_len ?
                                      c->new_len - c->old_len : 0) + 256;
    char *nb = erdict_xmalloc(cap);
    size_t w = 0;
    for (size_t i = 0; i < f.n_lines; i++) {
        erdict_line_t *l = &f.lines[i];
        size_t j = 0;
        while (j < l->len) {
            if (j + c->old_len <= l->len &&
                id_at(l->p, l->len, j, c->old_name, c->old_len))
            {
                if (w + c->new_len + 4 > cap) { cap *= 2; nb = erdict_xrealloc(nb, cap); }
                memcpy(nb + w, c->new_name, c->new_len);
                w += c->new_len;
                j += c->old_len;
            } else {
                if (w + 4 > cap) { cap *= 2; nb = erdict_xrealloc(nb, cap); }
                nb[w++] = l->p[j++];
            }
        }
        if (l->cr) nb[w++] = '\r';
        if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
    }
    nb[w] = 0;
    erdict_file_free(&f);

    /* L3 + cc check the RESULT */
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.l3-scratch", path);
    FILE *fp = fopen(tmp, "wb");
    if (fp) { fwrite(nb, 1, w, fp); fclose(fp); }
    erdict_file_t tmpf;
    int l3_ok = 0;
    if (erdict_file_load(tmp, &tmpf) == 0) {
        erdict_syntax_result_t tr;
        l3_ok = erdict_syntax_check(&tmpf, &tr) == 0;
        erdict_file_free(&tmpf);
    }
    unlink(tmp);
    if (!l3_ok) {
        erdict_err("rename would break syntax in %s", path);
        free(old); free(nb); c->err = 1;
        return 0;
    }

    if (!c->no_cc_check) {
        snprintf(tmp, sizeof tmp, "%s.cc-scratch.c", path);
        fp = fopen(tmp, "wb");
        if (fp) { fwrite(nb, 1, w, fp); fclose(fp); }
        int cc_ok = erdict_check_external(tmp, NULL, NULL, c->incs, c->n_incs) == 0;
        unlink(tmp);
        if (!cc_ok) {
            erdict_err("rename would break cc in %s", path);
            free(old); free(nb); c->err = 1;
            return 0;
        }
    }

    if (c->n == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 16;
        c->changes = erdict_xrealloc(c->changes, c->cap * sizeof(*c->changes));
    }
    file_change_t *fc = &c->changes[c->n++];
    fc->path = erdict_xstrdup(path);
    fc->old_buf = old;
    fc->old_len = old_len;
    fc->new_buf = nb;
    fc->new_len = w;
    fc->hits = hits;
    return 0;
}

static int scan_cb(const char *path, void *ud) {
    rt_ctx_t *c = ud;
    if (c->err) return 0;
    prep_file(c, path);
    return 0;
}

static int rollback(rt_ctx_t *c, size_t written) {
    int rc = 0;
    for (size_t i = written; i > 0; i--) {
        file_change_t *fc = &c->changes[i - 1];
        erdict_journal_pop(fc->path);
        FILE *fp = fopen(fc->path, "wb");
        if (!fp) { rc = -1; continue; }
        fwrite(fc->old_buf, 1, fc->old_len, fp);
        fclose(fp);
    }
    return rc;
}

int erdict_mode_rename_tree(const erdict_opts_t *o) {
    if (!o->pattern || !*o->pattern) {
        erdict_err("--rename-func requires '<old>:<new>'");
        return 2;
    }
    const char *colon = strchr(o->pattern, ':');
    if (!colon) {
        erdict_err("--rename-func requires '<old>:<new>'");
        return 2;
    }
    size_t old_len = (size_t)(colon - o->pattern);
    const char *new_name = colon + 1;
    size_t new_len = strlen(new_name);
    if (old_len == 0 || new_len == 0) {
        erdict_err("--rename-func: empty old or new name");
        return 2;
    }

    rt_ctx_t c = {0};
    c.old_name = o->pattern;
    c.old_len = old_len;
    c.new_name = new_name;
    c.new_len = new_len;
    c.no_cc_check = o->no_cc_check;
    c.incs = o->incs;
    c.n_incs = o->n_incs;

    const char *const suffixes[] = { ".c", ".h", NULL };
    for (size_t i = 0; i < o->n_files; i++)
        erdict_walk(o->files[i], suffixes, scan_cb, &c);

    if (c.err) {
        for (size_t i = 0; i < c.n; i++) {
            free(c.changes[i].path);
            free(c.changes[i].old_buf);
            free(c.changes[i].new_buf);
        }
        free(c.changes);
        return 1;
    }

    if (c.n == 0) {
        printf("  no occurrences of '%s' in tree\n", o->pattern);
        free(c.changes);
        return 1;
    }

    size_t total_hits = 0;
    for (size_t i = 0; i < c.n; i++) total_hits += c.changes[i].hits;

    printf("  %srename-func -r%s  %s%s%s -> %s%s%s\n",
           COL.cyan, COL.reset,
           COL.yellow, o->pattern, COL.reset,
           COL.green, new_name, COL.reset);
    for (size_t i = 0; i < c.n; i++)
        printf("    %s%s%s  %zu occurrence%s\n",
               COL.bold, c.changes[i].path, COL.reset,
               c.changes[i].hits, c.changes[i].hits == 1 ? "" : "s");
    printf("  %zu file%s · %zu occurrence%s\n",
           c.n, c.n == 1 ? "" : "s",
           total_hits, total_hits == 1 ? "" : "s");

    if (!o->apply) {
        printf("  %sdry run%s · rerun with --apply to write\n", COL.dim, COL.reset);
        for (size_t i = 0; i < c.n; i++) {
            free(c.changes[i].path);
            free(c.changes[i].old_buf);
            free(c.changes[i].new_buf);
        }
        free(c.changes);
        return 0;
    }

    /* write phase with rollback */
    size_t written = 0;
    for (size_t i = 0; i < c.n; i++) {
        file_change_t *fc = &c.changes[i];
        char action[128];
        snprintf(action, sizeof action, "rename-func %s -> %s", o->pattern, new_name);
        if (erdict_journal_append(fc->path, fc->old_buf, fc->old_len,
                                  fc->new_buf, fc->new_len, action) != 0)
        {
            erdict_err("journal failed for %s; rolling back", fc->path);
            rollback(&c, written);
            goto done_err;
        }
        FILE *fp = fopen(fc->path, "wb");
        if (!fp) {
            erdict_err("cannot write %s; rolling back", fc->path);
            rollback(&c, written);
            goto done_err;
        }
        if (fwrite(fc->new_buf, 1, fc->new_len, fp) != fc->new_len) {
            fclose(fp);
            erdict_err("short write %s; rolling back", fc->path);
            rollback(&c, written);
            goto done_err;
        }
        fclose(fp);
        written++;
    }

    printf("  %sapplied%s · %zu file%s renamed\n",
           COL.green, COL.reset, c.n, c.n == 1 ? "" : "s");
    for (size_t i = 0; i < c.n; i++) {
        free(c.changes[i].path);
        free(c.changes[i].old_buf);
        free(c.changes[i].new_buf);
    }
    free(c.changes);
    return 0;

done_err:
    for (size_t i = 0; i < c.n; i++) {
        free(c.changes[i].path);
        free(c.changes[i].old_buf);
        free(c.changes[i].new_buf);
    }
    free(c.changes);
    return 2;
}
