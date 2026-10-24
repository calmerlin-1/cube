/** patch.c — write modes with journal + L3 + cc check. */

#include "erdict.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* Read stdin OR --from-file. Returns malloc'd buffer. */
static char *read_repl(const erdict_opts_t *o, size_t *out_len);

static char *read_all_stdin(size_t *out_len) {
    size_t cap = 4096, len = 0;
    char *buf = erdict_xmalloc(cap);
    for (;;) {
        if (len == cap) { cap *= 2; buf = erdict_xrealloc(buf, cap); }
        ssize_t n = read(0, buf + len, cap - len);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; free(buf); return NULL; }
        len += (size_t)n;
    }
    if (len == cap) { cap += 1; buf = erdict_xrealloc(buf, cap); }
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

static char *read_file_raw(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
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

static char *read_repl(const erdict_opts_t *o, size_t *out_len) {
    if (o && o->from_file) return read_file_raw(o->from_file, out_len);
    return read_all_stdin(out_len);
}

static int write_back(const char *path, const char *data, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { erdict_err("cannot write %s: %s", path, strerror(errno)); return -1; }
    size_t w = 0;
    while (w < n) {
        ssize_t r = write(fd, data + w, n - w);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        w += (size_t)r;
    }
    close(fd);
    return 0;
}

static void emit_line(const erdict_line_t *l, char *nb, size_t *w) {
    memcpy(nb + *w, l->p, l->len);
    *w += l->len;
    if (l->cr) nb[(*w)++] = '\r';
    size_t content = l->len + (l->cr ? 1 : 0);
    if (l->raw_len > content) nb[(*w)++] = '\n';
}

static size_t line_emit_len(const erdict_line_t *l) {
    size_t n = l->len;
    if (l->cr) n += 1;
    size_t content = l->len + (l->cr ? 1 : 0);
    if (l->raw_len > content) n += 1;
    return n;
}

static char *build_replacement(const erdict_file_t *f, size_t s, size_t e,
                                const char *repl, size_t repl_len, size_t *out_len)
{
    size_t before = 0;
    for (size_t i = 0; i < s; i++) before += line_emit_len(&f->lines[i]);
    size_t after = 0;
    for (size_t i = e + 1; i < f->n_lines; i++) after += line_emit_len(&f->lines[i]);

    size_t new_len = before + repl_len + after;
    char *nb = erdict_xmalloc(new_len + 1);
    size_t w = 0;
    for (size_t i = 0; i < s; i++) emit_line(&f->lines[i], nb, &w);
    if (repl_len) { memcpy(nb + w, repl, repl_len); w += repl_len; }
    for (size_t i = e + 1; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);
    nb[w] = 0;
    if (out_len) *out_len = w;
    return nb;
}

static size_t line_start_off(const erdict_file_t *f, size_t line_1) {
    if (line_1 == 0) return 0;
    if (line_1 > f->n_lines) return f->buf_len;
    return (size_t)(f->lines[line_1 - 1].p - f->buf);
}

static size_t line_end_off(const erdict_file_t *f, size_t line_1) {
    if (line_1 == 0) return 0;
    if (line_1 >= f->n_lines) return f->buf_len;
    return (size_t)(f->lines[line_1].p - f->buf);
}

static char *build_insert(const erdict_file_t *f, size_t at_off,
                            const char *repl, size_t repl_len, size_t *out_len)
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
    char *nb = erdict_xmalloc(new_len + 1);
    size_t w = 0;
    for (size_t i = 0; i < k; i++) emit_line(&f->lines[i], nb, &w);
    if (repl_len) { memcpy(nb + w, repl, repl_len); w += repl_len; }
    for (size_t i = k; i < f->n_lines; i++) emit_line(&f->lines[i], nb, &w);
    nb[w] = 0;
    if (out_len) *out_len = w;
    return nb;
}

/* FIX 3: string/comment-aware balance. Braces inside "..." '...' /* *\/ // are ignored. */
static int l3_check_buffer(const char *buf, size_t n, const char *orig_path) {
    (void)orig_path;
    int brace = 0, paren = 0, bracket = 0;
    int in_str = 0, in_chr = 0, in_bc = 0, in_lc = 0;
    char q = 0;
    for (size_t i = 0; i < n; i++) {
        char c = buf[i];
        char nx = (i + 1 < n) ? buf[i + 1] : 0;

        if (in_lc)  { if (c == '\n') in_lc = 0; continue; }
        if (in_bc)  { if (c == '*' && nx == '/') { in_bc = 0; i++; } continue; }
        if (in_str) { if (c == '\\') { i++; continue; } if (c == q) in_str = 0; continue; }
        if (in_chr) { if (c == '\\') { i++; continue; } if (c == q) in_chr = 0; continue; }

        if (c == '/' && nx == '/') { in_lc = 1; i++; continue; }
        if (c == '/' && nx == '*') { in_bc = 1; i++; continue; }
        if (c == '"' || c == '\'') { in_str = (c == '"'); in_chr = (c == '\''); q = c; continue; }

        if (c == '{') brace++;
        else if (c == '}') { brace--; if (brace < 0) return 0; }
        else if (c == '(') paren++;
        else if (c == ')') { paren--; if (paren < 0) return 0; }
        else if (c == '[') bracket++;
        else if (c == ']') { bracket--; if (bracket < 0) return 0; }
    }
    if (brace != 0 || paren != 0 || bracket != 0) return 0;
    if (in_str || in_chr || in_bc) return 0;
    return 1;
}

/* Scratch file goes NEXT TO source with a leading dot prefix — resolves
 * relative #includes and is skipped by make's *.c wildcards. */
static void scratch_path_for(const char *orig_path, char *out, size_t out_len) {
    char dirpart[512] = {0};
    const char *slash = strrchr(orig_path, '/');
    const char *bname = slash ? slash + 1 : orig_path;
    if (slash) {
        size_t dl = (size_t)(slash - orig_path);
        if (dl < sizeof dirpart - 1) { memcpy(dirpart, orig_path, dl); dirpart[dl] = 0; }
    }
    snprintf(out, out_len, "%s%s.erdict-scratch-%s.%d.c",
             dirpart[0] ? dirpart : "",
             dirpart[0] ? "/" : "",
             bname, (int)getpid());
}

static int cc_check_buffer(const char *buf, size_t n, const char *orig_path,
                            const erdict_opts_t *o) {
    char tmp[1024];
    scratch_path_for(orig_path, tmp, sizeof tmp);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return 1;
    fwrite(buf, 1, n, fp);
    fclose(fp);

    const char *ck_incs[256];
    size_t n_ck = 0;
    if (o) {
        for (size_t i = 0; i < o->n_incs && n_ck < 256; i++)
            ck_incs[n_ck++] = o->incs[i];
        if (o->n_cached_incs > 0) {
            for (size_t i = 0; i < o->n_cached_incs && n_ck < 256; i++)
                ck_incs[n_ck++] = o->cached_incs[i];
        } else {
            for (size_t r = 0; r < o->n_includes_from; r++) {
                const char **dirs = NULL;
                size_t ndirs = 0;
                if (erdict_scan_includes(o->includes_from[r], &dirs, &ndirs) == 0) {
                    for (size_t i = 0; i < ndirs && n_ck < 256; i++)
                        ck_incs[n_ck++] = dirs[i];
                }
            }
        }
    }
    if (o && o->from_make && n_ck < 256) {
        char mbuf[2048];
        const char *base = strrchr(orig_path, '/');
        base = base ? base + 1 : orig_path;
        char tname[256];
        snprintf(tname, sizeof tname, "%s", base);
        char *dot = strrchr(tname, '.');
        if (dot) *dot = 0;
        if (erdict_make_incs(o->from_make, tname, mbuf, sizeof mbuf) == 0) {
            char *tok = strtok(mbuf, " ");
            while (tok && n_ck < 256) {
                if (tok[0] == '-' && tok[1] == 'I' && tok[2]) {
                    ck_incs[n_ck++] = erdict_xstrdup(tok + 2);
                }
                tok = strtok(NULL, " ");
            }
        }
    }

    /* For .h files: find a .c that includes it, cc-check that instead. */
    const char *check_target = tmp;
    char includer[1024] = {0};
    int ok;
    if (erdict_endswith(orig_path, ".h")) {
        const char *root = (o && o->from_make) ? o->from_make : ".";
        const char *hdr_dir = orig_path;
        char hdr_dirbuf[512];
        const char *slash = strrchr(orig_path, '/');
        if (slash) {
            size_t dlen = (size_t)(slash - orig_path);
            if (dlen < sizeof hdr_dirbuf) {
                memcpy(hdr_dirbuf, orig_path, dlen);
                hdr_dirbuf[dlen] = 0;
                hdr_dir = hdr_dirbuf;
            }
        }
        int found_inc = erdict_find_includer(orig_path, hdr_dir, includer, sizeof includer);
        if (found_inc != 0) {
            found_inc = erdict_find_includer(orig_path, root, includer, sizeof includer);
        }
        if (found_inc == 0) {
            check_target = includer;
        } else {
            erdict_err("  cc       skipped (no .c includes this header)");
            unlink(tmp);
            return 1;
        }
    }
    ok = erdict_check_external(check_target, NULL, NULL, ck_incs, n_ck) == 0;
    if (ok) {
        unlink(tmp);
    } else {
        erdict_err("  scratch kept for inspection: %s", tmp);
        erdict_err("  reproduce with: cc -fsyntax-only -I. <incs> %s", tmp);
        erdict_err("  delete after: rm %s", tmp);
    }
    return ok;
}

static int confirm_apply(const char *action, const erdict_opts_t *o) {
    if (!o->ask)  return 1;
    if (o->yes)   return 1;
    if (!isatty(0)) return 0;
    fprintf(stderr, "  %sapply%s %s? [y/N] ", COL.yellow, COL.reset, action);
    fflush(stderr);
    int c = getchar();
    int next;
    while ((next = getchar()) != '\n' && next != EOF) {}
    return c == 'y' || c == 'Y';
}

static int commit_or_dryrun(const erdict_file_t *f, const erdict_opts_t *o,
                             const char *nb, size_t nb_len, const char *action)
{
    int l3_ok = l3_check_buffer(nb, nb_len, f->path);

    if (!o->apply) {
        printf("  %sdry run%s · %s · %zu bytes → %zu bytes\n",
               COL.dim, COL.reset, action, f->buf_len, nb_len);
        printf("  %sl3%s     %s%s%s\n",
               COL.cyan, COL.reset,
               l3_ok ? COL.green : COL.red,
               l3_ok ? "OK" : "FAIL",
               COL.reset);
        if (o->no_cc_check)
            printf("  %scc%s     %sskipped (--no-cc-check)%s\n",
                   COL.cyan, COL.reset, COL.yellow, COL.reset);
        printf("  %srun with --apply to write, journal, and cc-check%s\n", COL.dim, COL.reset);
        return 0;
    }

    /* FIX 1: --force bypasses BOTH gates. Real build is authority. */
    if (o->force) {
        erdict_err("  --force: bypassing syntax and cc gates");
    } else {
        if (!l3_ok) {
            erdict_err("refusing to write: result fails --syntax (unbalanced braces/quotes)");
            erdict_err("  the file %s was NOT modified", f->path);
            erdict_err("  use --force to bypass");
            return 1;
        }
        if (!o->no_cc_check) {
            if (!cc_check_buffer(nb, nb_len, f->path, o)) {
                erdict_err("refusing to write: replacement fails cc -fsyntax-only");
                erdict_err("  the file %s was NOT modified", f->path);
                erdict_err("  examine the scratch above, then delete it");
                erdict_err("  use --force to bypass");
                return 1;
            }
        }
    }

    if (!confirm_apply(action, o)) {
        fprintf(stderr, "  aborted\n");
        return 0;
    }

    size_t old_len = 0;
    char *old = read_file_raw(f->path, &old_len);
    if (!old) old_len = 0;

    if (erdict_journal_append(f->path, old ? old : "", old_len,
                              nb, nb_len, action) != 0)
    {
        free(old);
        erdict_err("journal failed; refusing to write");
        return 2;
    }
    free(old);

    if (write_back(f->path, nb, nb_len) != 0) {
        extern int erdict_journal_pop(const char *file);
        erdict_journal_pop(f->path);
        return 2;
    }
    printf("  %sapplied%s · %s · %zu → %zu bytes\n",
           COL.green, COL.reset, action, f->buf_len, nb_len);
    if (o->rebuild) {
        printf("  %srebuild%s · running make -j4\n", COL.cyan, COL.reset);
        fflush(stdout);
        int mk = system("make -j4 2>&1 | tail -15");
        if (mk != 0) {
            erdict_err("rebuild failed (make exit %d)", mk);
            return 3;
        }
    }
    return 0;
}

static int is_safe_insert_line(const erdict_file_t *f, size_t line_no) {
    if (line_no < 1 || line_no > f->n_lines) return 1;
    const erdict_line_t *l = &f->lines[line_no - 1];
    size_t end = l->len;
    while (end > 0 && (l->p[end-1] == ' ' || l->p[end-1] == '\t' ||
                       l->p[end-1] == '\r' || l->p[end-1] == '\n')) end--;
    if (end == 0) return 1;
    char last = l->p[end-1];
    if (last == ';' || last == '}' || last == '{') return 1;
    if (last == ',') return 0;
    if (last == '\\') return 0;
    if (last == '(' || last == '[') return 0;
    const char *s = l->p;
    size_t i = 0;
    while (i < l->len && (s[i] == ' ' || s[i] == '\t')) i++;
    if (i < l->len && s[i] == '#') return 1;
    return 1;
}

int erdict_mode_patch(const erdict_file_t *f, const erdict_opts_t *o) {
    const char *mode = o->mode;

    if (o->expect_hash && o->range_str &&
        strcmp(mode, "append") && strcmp(mode, "prepend")) {
        size_t s = 0, e = 0;
        if (erdict_parse_range(f, o, &s, &e) == 0) {
            char hbuf[17];
            erdict_hash_range(f, s, e, hbuf);
            if (strcmp(hbuf, o->expect_hash) != 0) {
                erdict_err("hash mismatch: expected %s, got %s",
                           o->expect_hash, hbuf);
                erdict_err("  file %s unchanged", f->path);
                erdict_err("  re-read the range with: erdict %s %s",
                           f->path, o->range_str);
                return 1;
            }
        }
    }

    if (!strcmp(mode, "append")) {
        size_t rl = 0;
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }
        size_t base = 0;
        for (size_t i = 0; i < f->n_lines; i++) base += line_emit_len(&f->lines[i]);
        int add_nl = (base > 0 && f->lines[f->n_lines - 1].raw_len == f->lines[f->n_lines - 1].len);
        size_t nl = base + (add_nl ? 1 : 0) + rl;
        char *nb = erdict_xmalloc(nl + 1);
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
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }
        size_t base = 0;
        for (size_t i = 0; i < f->n_lines; i++) base += line_emit_len(&f->lines[i]);
        size_t nl = rl + base;
        char *nb = erdict_xmalloc(nl + 1);
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
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }
        if (!o->force && !is_safe_insert_line(f, o->r_start + 1)) {
            erdict_err("refusing --insert: line %zu looks like "
                       "a partial statement", o->r_start + 1);
            erdict_err("  line content: %.60s", f->lines[o->r_start].p);
            erdict_err("  use --patch %zu,%zu to replace a range, or --force to override",
                       o->r_start + 1, o->r_start + 1);
            free(repl);
            return 1;
        }
        size_t at = line_start_off(f, o->r_start + 1);
        size_t nl = 0;
        char *nb = build_insert(f, at, repl, rl, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "insert");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "insert-after")) {
        size_t rl = 0;
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }
        if (!o->force && !is_safe_insert_line(f, o->r_start + 1)) {
            erdict_err("refusing --insert-after: line %zu looks like "
                       "a partial statement", o->r_start + 1);
            erdict_err("  line content: %.60s", f->lines[o->r_start].p);
            erdict_err("  use --patch %zu,%zu to replace a range, or --force to override",
                       o->r_start + 1, o->r_start + 1);
            free(repl);
            return 1;
        }
        size_t at = line_end_off(f, o->r_start + 1);
        size_t nl = 0;
        char *nb = build_insert(f, at, repl, rl, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "insert-after");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "delete")) {
        if (!o->force && f->n_lines > 0) {
            size_t removed = o->r_end - o->r_start + 1;
            if (removed * 2 > f->n_lines) {
                erdict_err("refusing to delete %zu of %zu lines (>50%%); use --force",
                           removed, f->n_lines);
                return 1;
            }
        }
        size_t nl = 0;
        char *nb = build_replacement(f, o->r_start, o->r_end, "", 0, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "delete");
        free(nb);
        return rc;
    }

    if (!strcmp(mode, "patch")) {
        size_t rl = 0;
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }
        size_t nl = 0;
        char *nb = build_replacement(f, o->r_start, o->r_end, repl, rl, &nl);
        int rc = commit_or_dryrun(f, o, nb, nl, "patch");
        free(repl); free(nb);
        return rc;
    }

    if (!strcmp(mode, "patch-func")) {
        if (!o->pattern) { erdict_err("--patch-func requires a name"); return 2; }
        size_t rl = 0;
        char *repl = read_repl(o, &rl);
        if (!repl) { erdict_err("replacement read failed"); return 2; }

        erdict_sym_t *syms = NULL;
        size_t n = 0;
        if (erdict_symbols_scan(f, &syms, &n) != 0) {
            erdict_err("symbol scan failed"); free(repl); return 2;
        }
        size_t found_line = 0;
        int nfound = 0;
        for (size_t i = 0; i < n; i++) {
            if (syms[i].kind != ERDICT_SYM_FUNC) continue;
            if (strcmp(syms[i].name, o->pattern)) continue;
            if (!found_line) found_line = syms[i].line_no;
            nfound++;
        }
        if (nfound == 0) {
            erdict_err("no function '%s'", o->pattern);
            free(syms); free(repl); return 1;
        }
        if (nfound > 1) {
            erdict_err("'%s' defined %d times; ambiguous", o->pattern, nfound);
            free(syms); free(repl); return 2;
        }

        size_t start = found_line - 1;
        size_t open_line = 0, open_col = 0;
        for (size_t i = start; i < f->n_lines && !open_line; i++) {
            const char *p = f->lines[i].p;
            for (size_t k = 0; k < f->lines[i].len; k++) {
                if (p[k] == '{') { open_line = i + 1; open_col = k; break; }
            }
        }
        size_t end_line = 0, end_col = 0;
        if (!open_line ||
            erdict_find_matching_brace(f, open_line, open_col,
                                       &end_line, &end_col) != 0) {
            erdict_err("cannot find function body for '%s'", o->pattern);
            free(syms); free(repl); return 2;
        }
        size_t end = end_line - 1;

        const erdict_line_t *last = &f->lines[end_line - 1];
        size_t after = last->len - (end_col + 1);
        for (size_t j = end_col + 1; j < last->len; j++) {
            if (last->p[j] != ' ' && last->p[j] != '\t') { after = 1; break; }
            after = 0;
        }
        if (after) {
            erdict_err("refusing: '%s' ends mid-line (minified C not supported)", o->pattern);
            free(syms); free(repl); return 2;
        }

        size_t nl = 0;
        char *nb = build_replacement(f, start, end, repl, rl, &nl);
        char action[128];
        snprintf(action, sizeof action, "patch-func-%s-L%zu-%zu", o->pattern, start + 1, end + 1);
        int rc = commit_or_dryrun(f, o, nb, nl, action);
        free(repl); free(nb); free(syms);
        return rc;
    }

    erdict_err("unknown patch mode: %s", mode);
    return 2;
}

int erdict_mode_subst(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--subst requires a pattern"); return 2; }

    const char *pat = o->pattern;
    size_t plen = strlen(pat);
    int is_regex = 0;
    char *re_copy = NULL;
    if (plen >= 2 && pat[0] == '/' && pat[plen-1] == '/') {
        is_regex = 1;
        re_copy = erdict_xstrndup(pat + 1, plen - 2);
    }
    erdict_pattern_t *p = is_regex
        ? erdict_pattern_regex(re_copy)
        : erdict_pattern_substring(pat, o->icase);
    free(re_copy);
    if (!p) { erdict_err("bad pattern"); return 2; }

    size_t rl = 0;
    char *repl = read_repl(o, &rl);
    if (!repl) { erdict_err("replacement read failed"); erdict_pattern_free(p); return 2; }

    size_t hits = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        if (erdict_pattern_find(p, f->lines[i].p, f->lines[i].len) != SIZE_MAX)
            hits++;
    }
    if (hits == 0) {
        printf("  no lines match %s\n", o->pattern);
        erdict_pattern_free(p); free(repl); return 0;
    }

    size_t cap = f->buf_len + rl * hits + 256, len = 0;
    char *out = erdict_xmalloc(cap);
    for (size_t i = 0; i < f->n_lines; i++) {
        const erdict_line_t *l = &f->lines[i];
        int matched = erdict_pattern_find(p, l->p, l->len) != SIZE_MAX;
        const char *src = matched ? repl : l->p;
        size_t src_len = matched ? rl : l->len;
        if (len + src_len + 2 > cap) {
            cap = (len + src_len + 2) * 2;
            out = erdict_xrealloc(out, cap);
        }
        memcpy(out + len, src, src_len);
        len += src_len;
        if (l->cr) out[len++] = '\r';
        out[len++] = '\n';
    }
    out[len] = 0;

    int rc;
    if (!o->apply) {
        int l3_ok = l3_check_buffer(out, len, f->path);
        printf("  %sdry run%s · subst · %zu → %zu bytes · %zu hits\n",
               COL.dim, COL.reset, f->buf_len, len, hits);
        printf("  %sl3%s     %s%s%s\n",
               COL.cyan, COL.reset,
               l3_ok ? COL.green : COL.red, l3_ok ? "OK" : "FAIL", COL.reset);
        rc = 0;
    } else if (o->force) {
        erdict_err("  --force: bypassing syntax and cc gates");
        size_t old_len = 0;
        char *old = read_file_raw(f->path, &old_len);
        if (!old) old_len = 0;
        if (erdict_journal_append(f->path, old ? old : "", old_len,
                                  out, len, "subst") != 0)
        {
            free(old);
            erdict_err("journal failed; refusing to write");
            free(out); free(repl); erdict_pattern_free(p); return 2;
        }
        free(old);
        rc = write_back(f->path, out, len) == 0 ? 0 : 2;
        if (rc == 0)
            printf("  %sapplied%s · %zu → %zu bytes · %zu hits\n",
                   COL.green, COL.reset, f->buf_len, len, hits);
    } else {
        int l3_ok = l3_check_buffer(out, len, f->path);
        int cc_ok = o->no_cc_check ? 1 : cc_check_buffer(out, len, f->path, o);
        if (!l3_ok) {
            erdict_err("refusing to write: result fails --syntax (unbalanced braces/quotes)");
            erdict_err("  the file %s was NOT modified", f->path);
            erdict_err("  use --force to bypass");
            free(out); free(repl); erdict_pattern_free(p); return 1;
        }
        if (!cc_ok) {
            erdict_err("refusing to write: replacement fails cc -fsyntax-only");
            erdict_err("  the file %s was NOT modified", f->path);
            erdict_err("  use --force to bypass");
            free(out); free(repl); erdict_pattern_free(p); return 1;
        }
        size_t old_len = 0;
        char *old = read_file_raw(f->path, &old_len);
        if (!old) old_len = 0;
        if (erdict_journal_append(f->path, old ? old : "", old_len,
                                  out, len, "subst") != 0)
        {
            free(old);
            erdict_err("journal failed; refusing to write");
            free(out); free(repl); erdict_pattern_free(p); return 2;
        }
        free(old);
        rc = write_back(f->path, out, len) == 0 ? 0 : 2;
        if (rc == 0)
            printf("  %sapplied%s · %zu → %zu bytes · %zu hits\n",
                   COL.green, COL.reset, f->buf_len, len, hits);
    }
    free(out); free(repl); erdict_pattern_free(p);
    return rc;
}
