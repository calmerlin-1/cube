/** patch.c — write modes: patch / insert / insert-after / delete / append / prepend.
 *
 * All write modes are dry-run by default. --apply commits.
 */

#include "sear.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static char *read_all_stdin(size_t *out_len) {
    size_t cap = 4096, len = 0;
    char *buf = sear_xmalloc(cap);
    for (;;) {
        if (len == cap) { cap *= 2; buf = sear_xrealloc(buf, cap); }
        ssize_t n = read(0, buf + len, cap - len);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; free(buf); return NULL; }
        len += (size_t)n;
    }
    if (len == cap) { cap += 1; buf = sear_xrealloc(buf, cap); }
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

static int write_back(const char *path, const char *data, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { sear_err("cannot write %s: %s", path, strerror(errno)); return -1; }
    size_t w = 0;
    while (w < n) {
        ssize_t r = write(fd, data + w, n - w);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        w += (size_t)r;
    }
    close(fd);
    return 0;
}

/* Emit one line's bytes into nb at *w, reconstructing \r and \n from
 * line metadata.  io.c mutates f->buf in place, replacing every \n with
 * \0 — so we cannot copy raw buffer bytes; we must rebuild them here. */
static void emit_line(const sear_line_t *l, char *nb, size_t *w) {
    memcpy(nb + *w, l->p, l->len);
    *w += l->len;
    if (l->cr) nb[(*w)++] = '\r';
    size_t content = l->len + (l->cr ? 1 : 0);
    if (l->raw_len > content) nb[(*w)++] = '\n';
}

/* Return the byte size a line will occupy when emitted. */
static size_t line_emit_len(const sear_line_t *l) {
    size_t n = l->len;
    if (l->cr) n += 1;
    size_t content = l->len + (l->cr ? 1 : 0);
    if (l->raw_len > content) n += 1;
    return n;
}

/* Build the new file content. Range [s, e] inclusive, 0-based. */
static char *build_replacement(const sear_file_t *f,
                               size_t s, size_t e,
                               const char *repl, size_t repl_len,
                               int mode_is_insert,
                               size_t *out_len)
{
    (void)mode_is_insert;

    size_t before = 0;
    for (size_t i = 0; i < s; i++) before += line_emit_len(&f->lines[i]);
    size_t after = 0;
    for (size_t i = e + 1; i < f->n_lines; i++) after += line_emit_len(&f->lines[i]);

    size_t new_len = before + repl_len + after;
    char *nb = sear_xmalloc(new_len + 1);

    size_t w = 0;
    for (size_t i = 0; i < s; i++) emit_line(&f->lines[i], nb, &w);
    if (repl_len) { memcpy(nb + w, repl, repl_len); w += repl_len; }
    for (size_t i = e + 1; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);

    nb[w] = 0;
    if (out_len) *out_len = w;
    return nb;
}

static size_t line_start_off(const sear_file_t *f, size_t line_1) {
    if (line_1 == 0) return 0;
    if (line_1 > f->n_lines) return f->buf_len;
    return (size_t)(f->lines[line_1 - 1].p - f->buf);
}

static size_t line_end_off(const sear_file_t *f, size_t line_1) {
    if (line_1 == 0) return 0;
    if (line_1 >= f->n_lines) return f->buf_len;
    return (size_t)(f->lines[line_1].p - f->buf);
}

/* Insert repl at byte offset at_off, which we map back to a line index
 * k (0..n_lines): emit lines [0,k), repl, lines [k, n_lines). */
static char *build_insert(const sear_file_t *f, size_t at_off,
                          const char *repl, size_t repl_len,
                          size_t *out_len)
{
    size_t k = f->n_lines;
    for (size_t i = 0; i < f->n_lines; i++) {
        size_t start = line_start_off(f, i + 1);
        size_t end   = line_end_off(f, i + 1);
        if (at_off >= start && at_off <= end) { k = i; break; }
    }

    size_t before = 0;
    for (size_t i = 0; i < k; i++) before += line_emit_len(&f->lines[i]);
    size_t after = 0;
    for (size_t i = k; i < f->n_lines; i++) after += line_emit_len(&f->lines[i]);

    size_t new_len = before + repl_len + after;
    char *nb = sear_xmalloc(new_len + 1);

    size_t w = 0;
    for (size_t i = 0; i < k; i++) emit_line(&f->lines[i], nb, &w);
    if (repl_len) { memcpy(nb + w, repl, repl_len); w += repl_len; }
    for (size_t i = k; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);

    nb[w] = 0;
    if (out_len) *out_len = w;
    return nb;
}

static int commit_or_dryrun(const sear_file_t *f, const sear_opts_t *o,
                            const char *nb, size_t nb_len,
                            const char *action)
{
    if (!o->apply) {
        printf("  dry run · %s · %zu bytes → %zu bytes\n",
               action, f->buf_len, nb_len);
        return 0;
    }
    if (write_back(f->path, nb, nb_len) != 0) return 2;
    printf("  applied · %s · %zu → %zu bytes\n", action, f->buf_len, nb_len);
    return 0;
}

int sear_mode_patch(const sear_file_t *f, const sear_opts_t *o) {
    const char *mode = o->mode;

    if (!strcmp(mode, "append")) {
        size_t rl = 0;
        char *repl = read_all_stdin(&rl);
        if (!repl) { sear_err("stdin read failed"); return 2; }
        /* rebuild existing content line-by-line so newlines are intact */
        size_t base = 0;
        for (size_t i = 0; i < f->n_lines; i++) base += line_emit_len(&f->lines[i]);
        int add_nl = (base > 0 && f->lines[f->n_lines - 1].raw_len == f->lines[f->n_lines - 1].len);
        size_t nl = base + (add_nl ? 1 : 0) + rl;
        char *nb = sear_xmalloc(nl + 1);
        size_t w = 0;
        for (size_t i = 0; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);
        if (add_nl) nb[w++] = '\n';
        memcpy(nb + w, repl, rl);
        w += rl;
        nb[w] = 0;
        nl = w;
        int rc = commit_or_dryrun(f, o, nb, nl, "append");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "prepend")) {
        size_t rl = 0;
        char *repl = read_all_stdin(&rl);
        if (!repl) { sear_err("stdin read failed"); return 2; }
        size_t base = 0;
        for (size_t i = 0; i < f->n_lines; i++) base += line_emit_len(&f->lines[i]);
        size_t nl = rl + base;
        char *nb = sear_xmalloc(nl + 1);
        memcpy(nb, repl, rl);
        size_t w = rl;
        for (size_t i = 0; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);
        nb[w] = 0;
        nl = w;
        int rc = commit_or_dryrun(f, o, nb, nl, "prepend");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "insert")) {
        size_t rl = 0;
        char *repl = read_all_stdin(&rl);
        if (!repl) { sear_err("stdin read failed"); return 2; }
        size_t at = line_start_off(f, o->r_start + 1);
        size_t nl = 0;
        char *nb = build_insert(f, at, repl, rl, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "insert");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "insert-after")) {
        size_t rl = 0;
        char *repl = read_all_stdin(&rl);
        if (!repl) { sear_err("stdin read failed"); return 2; }
        size_t at = line_end_off(f, o->r_start + 1);
        size_t nl = 0;
        char *nb = build_insert(f, at, repl, rl, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "insert-after");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "delete")) {
        size_t nl = 0;
        char *nb = build_replacement(f, o->r_start, o->r_end, "", 0, 0, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "delete");
        free(nb);
        return rc;
    }

    if (!strcmp(mode, "patch")) {
        size_t rl = 0;
        char *repl = read_all_stdin(&rl);
        if (!repl) { sear_err("stdin read failed"); return 2; }
        size_t nl = 0;
        char *nb = build_replacement(f, o->r_start, o->r_end, repl, rl, 0, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "patch");
        free(repl); free(nb);
        return rc;
    }

    sear_err("unknown patch mode: %s", mode);
    return 2;
}

/* ============================================================
 * --subst /pattern/: replace every line matching the pattern
 * with the stdin content. Multi-line stdin is written verbatim;
 * the matched line's terminating newline is preserved.
 * ============================================================ */

int sear_mode_subst(const sear_file_t *f, const sear_opts_t *o) {
    if (!o->pattern) { sear_err("--subst requires a pattern"); return 2; }

    const char *pat = o->pattern;
    size_t plen = strlen(pat);
    int is_regex = 0;
    char *re_copy = NULL;
    if (plen >= 2 && pat[0] == '/' && pat[plen-1] == '/') {
        is_regex = 1;
        re_copy = sear_xstrndup(pat + 1, plen - 2);
    }

    sear_pattern_t *p = is_regex
        ? sear_pattern_regex(re_copy)
        : sear_pattern_substring(pat, o->icase);
    free(re_copy);
    if (!p) { sear_err("bad pattern"); return 2; }

    size_t rl = 0;
    char *repl = read_all_stdin(&rl);
    if (!repl) { sear_err("stdin read failed"); sear_pattern_free(p); return 2; }

    /* Count matches first for the dry-run summary. */
    size_t hits = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        if (sear_pattern_find(p, f->lines[i].p, f->lines[i].len) != SIZE_MAX)
            hits++;
    }

    if (hits == 0) {
        printf("  no lines match %s\n", o->pattern);
        sear_pattern_free(p);
        free(repl);
        return 0;
    }

    /* Build the new file: for each line, either original or stdin content. */
    /* Simple dynamic buffer. */
    size_t cap = f->buf_len + rl * hits + 256, len = 0;
    char *out = sear_xmalloc(cap);
    for (size_t i = 0; i < f->n_lines; i++) {
        const sear_line_t *l = &f->lines[i];
        int matched = sear_pattern_find(p, l->p, l->len) != SIZE_MAX;
        const char *src = matched ? repl : l->p;
        size_t src_len = matched ? rl : l->len;
        if (len + src_len + 2 > cap) {
            cap = (len + src_len + 2) * 2;
            out = sear_xrealloc(out, cap);
        }
        memcpy(out + len, src, src_len);
        len += src_len;
        /* preserve line ending style: if original had \r\n, keep it */
        if (l->cr) out[len++] = '\r';
        out[len++] = '\n';
    }
    out[len] = 0;

    printf("  %s%s%s   %zu line%s to replace\n",
           COL.bold, f->path, COL.reset,
           hits, hits == 1 ? "" : "s");

    int rc;
    if (!o->apply) {
        printf("  dry run · %zu → %zu bytes · %zu hits\n",
               f->buf_len, len, hits);
        rc = 0;
    } else {
        rc = write_back(f->path, out, len) == 0 ? 0 : 2;
        if (rc == 0)
            printf("  applied · %zu → %zu bytes · %zu hits\n",
                   f->buf_len, len, hits);
    }

    free(out);
    free(repl);
    sear_pattern_free(p);
    return rc;
}
