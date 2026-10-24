/** query.c — symbol queries: callers, callees, signature. */

#include "erdict.h"
#include "symbols.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

static int ident_at(const char *line, size_t len, size_t pos,
                    const char *name, size_t name_len)
{
    if (pos + name_len > len) return 0;
    if (memcmp(line + pos, name, name_len) != 0) return 0;
    if (pos > 0 && (isalnum((unsigned char)line[pos-1]) || line[pos-1] == '_')) return 0;
    if (pos + name_len < len &&
        (isalnum((unsigned char)line[pos+name_len]) || line[pos+name_len] == '_')) return 0;
    return 1;
}

int erdict_mode_callers(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--callers requires a name"); return 2; }
    const char *name = o->pattern;
    size_t name_len = strlen(name);

    erdict_sym_t *syms = NULL;
    size_t n = 0;
    erdict_symbols_scan(f, &syms, &n);
    size_t def_line = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind == ERDICT_SYM_FUNC && !strcmp(syms[i].name, name)) {
            def_line = syms[i].line_no;
            break;
        }
    }
    free(syms);

    size_t hits = 0;
    size_t tw = 0, cr = 0, tabs = 0;
    int header_printed = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        if (def_line && l->line_no == def_line) continue;
        size_t j = 0;
        int found = 0;
        while (j + name_len <= l->len) {
            if (ident_at(l->p, l->len, j, name, name_len)) { found = 1; break; }
            j++;
        }
        if (!found) continue;
        if (!header_printed) {
            printf("  %s%s%s\n", COL.bold, f->path, COL.reset);
            header_printed = 1;
        }
        erdict_ws_classify(f, l);
        hits++;
        if (l->trail) tw++;
        if (l->cr) cr++;
        tabs += l->lead_tab;
        printf("  %sL%-5zu%s %sC%-3zu%s ", COL.cyan, l->line_no, COL.reset,
               COL.dim_cyan, j + 1, COL.reset);
        fwrite(l->p, 1, l->len, stdout);
        putchar('\n');
    }
    if (hits > 0 || !o->quiet_zero) {
        if (hits == 0) printf("  %s%s%s\n", COL.bold, f->path, COL.reset);
        printf("\n  %zu %scaller%s%s · %zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n",
               hits, COL.cyan, hits == 1 ? "" : "s", COL.reset,
               tabs, COL.cyan, COL.reset, tw, COL.cyan, COL.reset, cr, COL.cyan, COL.reset);
    }
    return hits ? 0 : 1;
}

int erdict_mode_signature(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--signature requires a name"); return 2; }
    erdict_sym_t *syms = NULL;
    size_t n = 0;
    if (erdict_symbols_scan(f, &syms, &n) != 0) { erdict_err("symbol scan failed"); return 2; }

    size_t def_line = 0;
    int nfound = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind != ERDICT_SYM_FUNC) continue;
        if (strcmp(syms[i].name, o->pattern)) continue;
        if (!def_line) def_line = syms[i].line_no;
        nfound++;
    }
    if (!nfound) {
        erdict_err("no function '%s'", o->pattern);
        free(syms);
        return 1;
    }
    if (nfound > 1) {
        erdict_err("'%s' defined %d times; ambiguous", o->pattern, nfound);
        free(syms);
        return 2;
    }

    size_t start = def_line - 1;
    size_t open_line = 0;
    for (size_t i = start; i < f->n_lines && !open_line; i++) {
        const char *p = f->lines[i].p;
        for (size_t k = 0; k < f->lines[i].len; k++)
            if (p[k] == '{') { open_line = i + 1; break; }
        if (strstr(p, ";") && !strchr(p, '{')) { open_line = i + 1; break; }
    }
    size_t end = open_line ? open_line - 1 : start;

    printf("  %s%s%s   signature %s%s%s   L%zu-%zu  (%zu lines)\n",
           COL.bold, f->path, COL.reset,
           COL.cyan, o->pattern, COL.reset,
           start + 1, end + 1, end - start + 1);
    for (size_t i = start; i <= end; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
        erdict_print_line_plain(stdout, l);
    }
    free(syms);
    return 0;
}

int erdict_mode_callees(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--callees requires a name"); return 2; }
    erdict_sym_t *syms = NULL;
    size_t n = 0;
    if (erdict_symbols_scan(f, &syms, &n) != 0) { erdict_err("symbol scan failed"); return 2; }

    size_t def_line = 0;
    int nfound = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind != ERDICT_SYM_FUNC) continue;
        if (strcmp(syms[i].name, o->pattern)) continue;
        size_t ln = syms[i].line_no;
        if (ln < 1 || ln > f->n_lines) continue;
        const erdict_line_t *L = &f->lines[ln - 1];
        const char *semi  = memchr(L->p, ';', L->len);
        const char *brace = memchr(L->p, '{', L->len);
        if (!semi || brace) {
            if (!def_line) def_line = ln;
            nfound++;
        }
    }
    if (!nfound) {
        erdict_err("no function '%s'", o->pattern);
        free(syms);
        return 1;
    }
    if (nfound > 1) {
        erdict_err("'%s' defined %d times; ambiguous", o->pattern, nfound);
        free(syms);
        return 2;
    }

    size_t start = def_line - 1;
    size_t open_line = 0, open_col = 0;
    for (size_t i = start; i < f->n_lines && !open_line; i++) {
        const char *p = f->lines[i].p;
        for (size_t k = 0; k < f->lines[i].len; k++) {
            if (p[k] == '{') { open_line = i + 1; open_col = k; break; }
        }
    }
    size_t end_line = 0;
    if (!open_line ||
        erdict_find_matching_brace(f, open_line, open_col, &end_line, NULL) != 0)
    {
        erdict_err("cannot find body of '%s'", o->pattern);
        free(syms);
        return 2;
    }
    size_t end = end_line - 1;

    /* For each known function name other than the target, scan the body. */
    size_t calls = 0;
    printf("  %s%s%s   callees of %s%s%s   body L%zu-%zu\n",
           COL.bold, f->path, COL.reset,
           COL.cyan, o->pattern, COL.reset,
           start + 1, end + 1);
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind != ERDICT_SYM_FUNC) continue;
        if (!strcmp(syms[i].name, o->pattern)) continue;
        const char *callee = syms[i].name;
        size_t cl = strlen(callee);
        for (size_t ln = start; ln <= end; ln++) {
            erdict_line_t *l = &f->lines[ln];
            if (l->line_no == def_line) continue;
            size_t j = 0;
            int hit = 0;
            size_t hit_col = 0;
            while (j + cl <= l->len) {
                if (ident_at(l->p, l->len, j, callee, cl)) { hit = 1; hit_col = j; break; }
                j++;
            }
            if (!hit) continue;
            calls++;
            printf("  %sL%-5zu%s %sC%-3zu%s %s%s%s\n",
                   COL.cyan, l->line_no, COL.reset,
                   COL.dim_cyan, hit_col + 1, COL.reset,
                   COL.green, callee, COL.reset);
        }
    }

    size_t distinct = 0;
    for (size_t a = 0; a < n; a++) {
        if (syms[a].kind != ERDICT_SYM_FUNC) continue;
        if (!strcmp(syms[a].name, o->pattern)) continue;
        const char *cn = syms[a].name;
        size_t cl2 = strlen(cn);
        int seen = 0;
        for (size_t ln = start; ln <= end && !seen; ln++) {
            erdict_line_t *l2 = &f->lines[ln];
            if (l2->line_no == def_line) continue;
            size_t j2 = 0;
            while (j2 + cl2 <= l2->len) {
                if (ident_at(l2->p, l2->len, j2, cn, cl2)) { seen = 1; break; }
                j2++;
            }
        }
        if (seen) distinct++;
    }
    printf("\n  %zu %scallee%s%s · %zu %sunique%s\n",
           calls, COL.cyan, calls == 1 ? "" : "s", COL.reset,
           distinct, COL.cyan, COL.reset);
    free(syms);
    return 0;
}

/* ---- imports ---- */

static int find_include_line(const erdict_file_t *f, const char *needle,
                             size_t *out_line, size_t *out_count)
{
    size_t n = 0, first = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        const char *p = l->p;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '#') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "include", 7) != 0) continue;
        if (strstr(l->p, needle)) {
            n++;
            if (!first) first = l->line_no;
        }
    }
    if (out_line) *out_line = first;
    if (out_count) *out_count = n;
    return n ? 0 : -1;
}

int erdict_mode_patch_import(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--patch-import requires old text"); return 2; }
    size_t line = 0, count = 0;
    if (find_include_line(f, o->pattern, &line, &count) != 0) {
        erdict_err("no #include containing '%s'", o->pattern);
        return 1;
    }
    if (count > 1) {
        erdict_err("'%s' appears in %zu #include lines; ambiguous", o->pattern, count);
        return 2;
    }
    if (!o->file) { erdict_err("--patch-import needs a new value"); return 2; }

    char newline[1024];
    if (o->file[0] == '<' || o->file[0] == '"')
        snprintf(newline, sizeof newline, "#include %s\n", o->file);
    else
        snprintf(newline, sizeof newline, "#include \"%s\"\n", o->file);

    size_t nb_len = 0;
    /* build replacement: line N-1 replaced with newline */
    char *nb = erdict_xmalloc(f->buf_len + strlen(newline) + 64);
    size_t w = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        if (f->lines[i].line_no == line) {
            size_t nl = strlen(newline);
            memcpy(nb + w, newline, nl);
            w += nl;
        } else {
            const erdict_line_t *l = &f->lines[i];
            memcpy(nb + w, l->p, l->len);
            w += l->len;
            if (l->cr) nb[w++] = '\r';
            size_t content = l->len + (l->cr ? 1 : 0);
            if (l->raw_len > content) nb[w++] = '\n';
        }
    }
    nb[w] = 0;
    nb_len = w;

    erdict_syntax_result_t r;
    if (erdict_syntax_check(f, &r) != 0) { /* pre-check on original */ }

    printf("  %spatch-import%s  L%zu  ->  %s\n",
           COL.cyan, COL.reset, line, newline);

    int rc;
    if (!o->apply) {
        printf("  %sdry run%s · %zu → %zu bytes\n", COL.dim, COL.reset, f->buf_len, nb_len);
        rc = 0;
    } else {
        char *tmp_path = erdict_xmalloc(strlen(f->path) + 32);
        sprintf(tmp_path, "%s.l3-scratch", f->path);
        FILE *fp = fopen(tmp_path, "wb");
        if (fp) { fwrite(nb, 1, nb_len, fp); fclose(fp); }
        erdict_file_t tmpf;
        int l3_ok = 0;
        if (erdict_file_load(tmp_path, &tmpf) == 0) {
            erdict_syntax_result_t tr;
            l3_ok = erdict_syntax_check(&tmpf, &tr) == 0;
            erdict_file_free(&tmpf);
        }
        unlink(tmp_path);
        free(tmp_path);
        if (!l3_ok) { erdict_err("refusing: result fails --syntax"); free(nb); return 1; }

        size_t old_len = 0;
        char *old = NULL;
        FILE *ofp = fopen(f->path, "rb");
        if (ofp) {
            fseek(ofp, 0, SEEK_END); old_len = (size_t)ftell(ofp); rewind(ofp);
            old = erdict_xmalloc(old_len + 1);
            fread(old, 1, old_len, ofp); old[old_len] = 0;
            fclose(ofp);
        }
        if (erdict_journal_append(f->path, old ? old : "", old_len,
                                  nb, nb_len, "patch-import") != 0)
        {
            free(old); free(nb); erdict_err("journal failed"); return 2;
        }
        free(old);
        FILE *wfp = fopen(f->path, "wb");
        if (wfp) { fwrite(nb, 1, nb_len, wfp); fclose(wfp); }
        printf("  %sapplied%s · %zu → %zu bytes\n",
               COL.green, COL.reset, f->buf_len, nb_len);
        rc = 0;
    }
    free(nb);
    return rc;
}

int erdict_mode_add_import(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern || !*o->pattern) { erdict_err("--add-import requires a header"); return 2; }
    size_t line = 0, count = 0;
    if (find_include_line(f, o->pattern, &line, &count) == 0) {
        printf("  no change · '%s' already included at L%zu\n", o->pattern, line);
        return 0;
    }
    /* find last include line */
    size_t last = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        const char *p = f->lines[i].p;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') {
            p++;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "include", 7) == 0) last = i + 1;
        }
    }
    if (!last) last = 1;

    char newline[1024];
    if (o->pattern[0] == '<' || o->pattern[0] == '"')
        snprintf(newline, sizeof newline, "#include %s\n", o->pattern);
    else
        snprintf(newline, sizeof newline, "#include \"%s\"\n", o->pattern);

    printf("  %sadd-import%s   after L%zu   %s",
           COL.cyan, COL.reset, last, newline);
    int rc;
    if (!o->apply) {
        printf("  %sdry run%s\n", COL.dim, COL.reset);
        rc = 0;
    } else {
        size_t nb_cap = f->buf_len + strlen(newline) + 64;
        char *nb = erdict_xmalloc(nb_cap);
        size_t w = 0;
        for (size_t i = 0; i < f->n_lines; i++) {
            const erdict_line_t *l = &f->lines[i];
            memcpy(nb + w, l->p, l->len); w += l->len;
            if (l->cr) nb[w++] = '\r';
            size_t content = l->len + (l->cr ? 1 : 0);
            if (l->raw_len > content) nb[w++] = '\n';
            if (l->line_no == last) {
                size_t nl = strlen(newline);
                memcpy(nb + w, newline, nl); w += nl;
            }
        }
        nb[w] = 0;
        size_t old_len = 0;
        char *old = NULL;
        FILE *ofp = fopen(f->path, "rb");
        if (ofp) {
            fseek(ofp, 0, SEEK_END); old_len = (size_t)ftell(ofp); rewind(ofp);
            old = erdict_xmalloc(old_len + 1);
            fread(old, 1, old_len, ofp); old[old_len] = 0;
            fclose(ofp);
        }
        if (erdict_journal_append(f->path, old ? old : "", old_len,
                                  nb, w, "add-import") != 0)
        {
            free(old); free(nb); erdict_err("journal failed"); return 2;
        }
        free(old);
        FILE *wfp = fopen(f->path, "wb");
        if (wfp) { fwrite(nb, 1, w, wfp); fclose(wfp); }
        printf("  %sapplied%s · +%zu bytes\n", COL.green, COL.reset, strlen(newline));
        free(nb);
        rc = 0;
    }
    return rc;
}

int erdict_mode_sort_imports(const erdict_file_t *f, const erdict_opts_t *o) {
    size_t first = 0, last = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        const char *p = f->lines[i].p;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') {
            p++;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "include", 7) == 0) {
                if (!first) first = i + 1;
                last = i + 1;
            }
        }
    }
    if (!first) { printf("  no includes\n"); return 0; }
    printf("  %ssort-imports%s  L%zu-%zu  (%zu lines)\n",
           COL.cyan, COL.reset, first, last, last - first + 1);

    if (!o->apply) {
        printf("  %sdry run%s\n", COL.dim, COL.reset);
        return 0;
    }

    /* Collect include lines, sort, rewrite in place. */
    size_t count = last - first + 1;
    char **lines = erdict_xmalloc(count * sizeof *lines);
    for (size_t i = 0; i < count; i++) {
        erdict_line_t *l = &f->lines[first - 1 + i];
        lines[i] = erdict_xstrndup(l->p, l->len);
    }
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            if (strcmp(lines[i], lines[j]) > 0) {
                char *t = lines[i]; lines[i] = lines[j]; lines[j] = t;
            }

    /* Build new file */
    char *nb = erdict_xmalloc(f->buf_len + 256);
    size_t w = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        if (l->line_no >= first && l->line_no <= last) {
            size_t k = l->line_no - first;
            memcpy(nb + w, lines[k], strlen(lines[k]));
            w += strlen(lines[k]);
            if (l->cr) nb[w++] = '\r';
            if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
        } else {
            memcpy(nb + w, l->p, l->len); w += l->len;
            if (l->cr) nb[w++] = '\r';
            if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
        }
    }
    nb[w] = 0;

    for (size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);

    size_t old_len = 0;
    char *old = NULL;
    FILE *ofp = fopen(f->path, "rb");
    if (ofp) {
        fseek(ofp, 0, SEEK_END); old_len = (size_t)ftell(ofp); rewind(ofp);
        old = erdict_xmalloc(old_len + 1);
        fread(old, 1, old_len, ofp); old[old_len] = 0;
        fclose(ofp);
    }
    if (erdict_journal_append(f->path, old ? old : "", old_len,
                              nb, w, "sort-imports") != 0)
    {
        free(old); free(nb); erdict_err("journal failed"); return 2;
    }
    free(old);
    FILE *wfp = fopen(f->path, "wb");
    if (wfp) { fwrite(nb, 1, w, wfp); fclose(wfp); }
    printf("  %sapplied%s · %zu lines sorted\n", COL.green, COL.reset, count);
    free(nb);
    return 0;
}

int erdict_mode_add_func(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern || !*o->pattern) {
        erdict_err("--add-func requires a name");
        return 2;
    }
    /* check for existing definition */
    erdict_sym_t *syms = NULL;
    size_t n = 0;
    erdict_symbols_scan(f, &syms, &n);
    int exists = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind == ERDICT_SYM_FUNC && !strcmp(syms[i].name, o->pattern)) {
            exists = 1; break;
        }
    }
    free(syms);
    if (exists) {
        erdict_err("function '%s' already exists; use --patch-func to replace", o->pattern);
        return 2;
    }

    size_t rl = 0;
    char *buf = erdict_xmalloc(4096);
    size_t cap = 4096, len = 0;
    for (;;) {
        if (len == cap) { cap *= 2; buf = erdict_xrealloc(buf, cap); }
        ssize_t r = read(0, buf + len, cap - len);
        if (r == 0) break;
        if (r < 0) { free(buf); erdict_err("stdin read failed"); return 2; }
        len += (size_t)r;
    }
    rl = len;
    if (rl == 0) { free(buf); erdict_err("--add-func requires stdin body"); return 2; }

    /* build new file: original + "\n" + body */
    size_t total = f->buf_len + 1 + rl + 1;
    char *nb = erdict_xmalloc(total);
    size_t w = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        const erdict_line_t *l = &f->lines[i];
        memcpy(nb + w, l->p, l->len); w += l->len;
        if (l->cr) nb[w++] = '\r';
        if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
    }
    if (w > 0 && nb[w-1] != '\n') nb[w++] = '\n';
    nb[w++] = '\n';
    memcpy(nb + w, buf, rl);
    w += rl;
    nb[w] = 0;

    /* syntax + cc check */
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.l3-scratch", f->path);
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
        erdict_err("refusing to write: result would fail --syntax");
        free(buf); free(nb);
        return 1;
    }

    if (!o->apply) {
        printf("  %sdry run%s · add-func %s · +%zu bytes\n",
               COL.dim, COL.reset, o->pattern, rl);
        free(buf); free(nb);
        return 0;
    }

    size_t old_len = 0;
    char *old = NULL;
    FILE *ofp = fopen(f->path, "rb");
    if (ofp) {
        fseek(ofp, 0, SEEK_END); old_len = (size_t)ftell(ofp); rewind(ofp);
        old = erdict_xmalloc(old_len + 1);
        if (fread(old, 1, old_len, ofp) != old_len) { /* size may have changed */ }
        old[old_len] = 0;
        fclose(ofp);
    }
    char action[128];
    snprintf(action, sizeof action, "add-func %s", o->pattern);
    if (erdict_journal_append(f->path, old ? old : "", old_len, nb, w, action) != 0) {
        free(old); free(buf); free(nb);
        erdict_err("journal failed"); return 2;
    }
    free(old);

    fp = fopen(f->path, "wb");
    if (!fp) {
        erdict_journal_pop(f->path); free(buf); free(nb);
        erdict_err("cannot write"); return 2;
    }
    if (fwrite(nb, 1, w, fp) != w) {
        fclose(fp); erdict_journal_pop(f->path); free(buf); free(nb);
        erdict_err("short write"); return 2;
    }
    fclose(fp);
    printf("  %sapplied%s · add-func %s · +%zu bytes\n",
           COL.green, COL.reset, o->pattern, rl);
    free(buf); free(nb);
    return 0;
}

int erdict_mode_add_decl(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern || !*o->pattern) {
        erdict_err("--add-decl requires text");
        return 2;
    }
    /* find the LAST #endif in the file, insert the declaration before it */
    size_t endif_line = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        const char *p = f->lines[i].p;
        size_t j = 0;
        while (j < f->lines[i].len && (p[j] == ' ' || p[j] == '\t')) j++;
        if (j + 6 <= f->lines[i].len && strncmp(p + j, "#endif", 6) == 0)
            endif_line = i + 1;
    }
    if (!endif_line) {
        erdict_err("no #endif found; --add-decl needs a header guard");
        return 2;
    }

    /* build new file: lines 0..endif_line-2, then decl line, then rest */
    char decl[2048];
    snprintf(decl, sizeof decl, "%s\n", o->pattern);
    size_t dlen = strlen(decl);

    size_t total = f->buf_len + dlen + 2;
    char *nb = erdict_xmalloc(total);
    size_t w = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        if (f->lines[i].line_no == endif_line) {
            memcpy(nb + w, decl, dlen);
            w += dlen;
        }
        const erdict_line_t *l = &f->lines[i];
        memcpy(nb + w, l->p, l->len); w += l->len;
        if (l->cr) nb[w++] = '\r';
        if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
    }
    nb[w] = 0;

    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.l3-scratch", f->path);
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
        erdict_err("refusing to write: result would fail --syntax");
        free(nb);
        return 1;
    }

    if (!o->apply) {
        printf("  %sdry run%s · add-decl before L%zu · +%zu bytes\n",
               COL.dim, COL.reset, endif_line, dlen);
        free(nb);
        return 0;
    }

    size_t old_len = 0;
    char *old = NULL;
    FILE *ofp = fopen(f->path, "rb");
    if (ofp) {
        fseek(ofp, 0, SEEK_END); old_len = (size_t)ftell(ofp); rewind(ofp);
        old = erdict_xmalloc(old_len + 1);
        if (fread(old, 1, old_len, ofp) != old_len) { }
        old[old_len] = 0;
        fclose(ofp);
    }
    char action[128];
    snprintf(action, sizeof action, "add-decl");
    if (erdict_journal_append(f->path, old ? old : "", old_len, nb, w, action) != 0) {
        free(old); free(nb);
        erdict_err("journal failed"); return 2;
    }
    free(old);

    fp = fopen(f->path, "wb");
    if (!fp) {
        erdict_journal_pop(f->path); free(nb);
        erdict_err("cannot write"); return 2;
    }
    if (fwrite(nb, 1, w, fp) != w) {
        fclose(fp); erdict_journal_pop(f->path);
        free(nb); erdict_err("short write"); return 2;
    }
    fclose(fp);
    printf("  %sapplied%s · add-decl before L%zu · +%zu bytes\n",
           COL.green, COL.reset, endif_line, dlen);
    free(nb);
    return 0;
}

int erdict_mode_rename_func(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern || !*o->pattern) {
        erdict_err("--rename-func requires '<old>:<new>'");
        return 2;
    }
    const char *pair = o->pattern;
    const char *colon = strchr(pair, ':');
    if (!colon) {
        erdict_err("--rename-func requires '<old>:<new>'");
        return 2;
    }
    size_t old_len = (size_t)(colon - pair);
    const char *new_name = colon + 1;
    size_t new_len = strlen(new_name);
    if (old_len == 0 || new_len == 0) {
        erdict_err("--rename-func: empty old or new name");
        return 2;
    }

    /* count occurrences (word-boundary) */
    size_t hits = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        size_t j = 0;
        while (j + old_len <= l->len) {
            if (ident_at(l->p, l->len, j, pair, old_len)) { hits++; j += old_len; }
            else j++;
        }
    }
    if (hits == 0) {
        erdict_err("no occurrences of '%s'", pair);
        return 1;
    }

    /* build new file */
    size_t cap = f->buf_len + hits * (new_len - old_len + 2) + 128;
    char *nb = erdict_xmalloc(cap);
    size_t w = 0;
    size_t applied = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        size_t j = 0;
        while (j < l->len) {
            if (j + old_len <= l->len && ident_at(l->p, l->len, j, pair, old_len)) {
                if (w + new_len + 4 > cap) { cap *= 2; nb = erdict_xrealloc(nb, cap); }
                memcpy(nb + w, new_name, new_len);
                w += new_len;
                j += old_len;
                applied++;
            } else {
                if (w + 4 > cap) { cap *= 2; nb = erdict_xrealloc(nb, cap); }
                nb[w++] = l->p[j++];
            }
        }
        if (l->cr) nb[w++] = '\r';
        if (l->raw_len > l->len + (l->cr ? 1 : 0)) nb[w++] = '\n';
    }
    nb[w] = 0;

    printf("  %srename-func%s  %s%s%s -> %s%s%s   %zu occurrence%s\n",
           COL.cyan, COL.reset,
           COL.yellow, pair, COL.reset,
           COL.green, new_name, COL.reset,
           applied, applied == 1 ? "" : "s");

    /* L3 + cc */
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.l3-scratch", f->path);
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
        erdict_err("refusing to write: result would fail --syntax");
        free(nb);
        return 1;
    }

    int cc_ok = 1;
    if (!o->no_cc_check) {
        snprintf(tmp, sizeof tmp, "%s.cc-scratch.c", f->path);
        fp = fopen(tmp, "wb");
        if (fp) { fwrite(nb, 1, w, fp); fclose(fp); }
        cc_ok = erdict_check_external(tmp, NULL, NULL,
                                      o->incs, o->n_incs) == 0;
        unlink(tmp);
        if (!cc_ok) {
            erdict_err("refusing to write: result would fail cc -fsyntax-only");
            free(nb);
            return 1;
        }
    }

    if (!o->apply) {
        printf("  %sdry run%s · %zu → %zu bytes\n",
               COL.dim, COL.reset, f->buf_len, w);
        free(nb);
        return 0;
    }

    /* journal + write */
    size_t old_len_file = 0;
    char *old_buf = NULL;
    FILE *ofp = fopen(f->path, "rb");
    if (ofp) {
        fseek(ofp, 0, SEEK_END); old_len_file = (size_t)ftell(ofp); rewind(ofp);
        old_buf = erdict_xmalloc(old_len_file + 1);
        size_t got = fread(old_buf, 1, old_len_file, ofp);
        old_buf[got] = 0;
        fclose(ofp);
    }
    char action[128];
    snprintf(action, sizeof action, "rename-func %s -> %s", pair, new_name);
    if (erdict_journal_append(f->path, old_buf ? old_buf : "", old_len_file,
                              nb, w, action) != 0)
    {
        free(old_buf); free(nb);
        erdict_err("journal failed"); return 2;
    }
    free(old_buf);

    fp = fopen(f->path, "wb");
    if (!fp) {
        erdict_journal_pop(f->path); free(nb);
        erdict_err("cannot write"); return 2;
    }
    if (fwrite(nb, 1, w, fp) != w) {
        fclose(fp); erdict_journal_pop(f->path);
        free(nb); erdict_err("short write"); return 2;
    }
    fclose(fp);
    printf("  %sapplied%s · rename-func · %zu → %zu bytes\n",
           COL.green, COL.reset, f->buf_len, w);
    free(nb);
    return 0;
}
