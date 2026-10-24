/** structure.c — list functions, structs, macros, imports, globals. */

#include "erdict.h"
#include "symbols.h"
#include <stdio.h>
#include <string.h>

static int match_opt(const char *name, const char *pat) {
    if (!pat) return 1;
    return strstr(name, pat) != NULL;
}

static void ws_counts(const erdict_file_t *f, size_t *tw, size_t *cr, size_t *tabs) {
    *tw = 0; *cr = 0; *tabs = 0;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
        if (l->trail) (*tw)++;
        if (l->cr)    (*cr)++;
        if (l->lead_tab) (*tabs)++;
    }
}

int erdict_mode_structure(const erdict_file_t *f, const erdict_opts_t *o) {
    erdict_sym_t *syms = NULL;
    size_t n = 0;
    if (erdict_symbols_scan(f, &syms, &n) != 0) {
        erdict_err("symbol scan failed");
        return 2;
    }

    const char *mode = o->mode;
    int want_func    = !strcmp(mode, "funcs") || !strcmp(mode, "list");
    int want_struct  = !strcmp(mode, "structs") || !strcmp(mode, "list");
    int want_macro   = !strcmp(mode, "macros") || !strcmp(mode, "list");
    int want_import  = !strcmp(mode, "imports") || !strcmp(mode, "list");
    int want_global  = !strcmp(mode, "globals") || !strcmp(mode, "list");

    printf("  %s%s%s\n", COL.bold, f->path, COL.reset);

    size_t c_func = 0, c_struct = 0, c_macro = 0, c_import = 0, c_global = 0;

    for (size_t i = 0; i < n; i++) {
        erdict_sym_t *s = &syms[i];
        int show = 0;
        const char *kind = "";
        switch (s->kind) {
        case ERDICT_SYM_FUNC:
            if (want_func && match_opt(s->name, o->pattern)) { show = 1; kind = "FUNC"; }
            c_func++;
            break;
        case ERDICT_SYM_STRUCT:
            if (want_struct && match_opt(s->name, o->pattern)) { show = 1; kind = "STRUCT"; }
            c_struct++;
            break;
        case ERDICT_SYM_MACRO:
            if (want_macro && match_opt(s->name, o->pattern)) { show = 1; kind = "MACRO"; }
            c_macro++;
            break;
        case ERDICT_SYM_IMPORT:
            if (want_import) { show = 1; kind = "INCLUDE"; }
            c_import++;
            break;
        case ERDICT_SYM_GLOBAL:
            if (want_global && match_opt(s->name, o->pattern)) { show = 1; kind = "GLOBAL"; }
            c_global++;
            break;
        }
        if (!show) continue;
        const char *kc = COL.dim;
        if      (s->kind == ERDICT_SYM_FUNC)   kc = COL.green;
        else if (s->kind == ERDICT_SYM_STRUCT) kc = COL.yellow;
        else if (s->kind == ERDICT_SYM_MACRO)  kc = COL.yellow;
        else if (s->kind == ERDICT_SYM_IMPORT) kc = COL.cyan;
        else if (s->kind == ERDICT_SYM_GLOBAL) kc = COL.dim_cyan;
        printf("  %sL%-5zu%s %s%-8s%s %s%s%s\n",
               COL.cyan, s->line_no, COL.reset,
               kc, kind, COL.reset,
               COL.bold, s->name, COL.reset);
    }

    size_t tw, cr, tabs;
    ws_counts(f, &tw, &cr, &tabs);

    const char *C = COL.cyan, *Z = COL.reset;
    printf("\n  ");
    int first = 1;
    if (want_func)    { printf("%zu %sfunc%s%s", c_func, C, c_func == 1 ? "" : "s", Z); first = 0; }
    if (want_struct) {
        printf("%s%zu %sstruct%s%s", first ? "" : " · ", c_struct, C,
               c_struct == 1 ? "" : "s", Z); first = 0;
    }
    if (want_macro) {
        printf("%s%zu %smacro%s%s", first ? "" : " · ", c_macro, C,
               c_macro == 1 ? "" : "s", Z); first = 0;
    }
    if (want_import) {
        printf("%s%zu %sinclude%s%s", first ? "" : " · ", c_import, C,
               c_import == 1 ? "" : "s", Z); first = 0;
    }
    if (want_global) {
        printf("%s%zu %sglobal%s%s", first ? "" : " · ", c_global, C,
               c_global == 1 ? "" : "s", Z); first = 0;
    }
    printf(" · %zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n", tabs, C, Z, tw, C, Z, cr, C, Z);

    free(syms);
    return 0;
}


int erdict_mode_lint(const erdict_file_t *f, const erdict_opts_t *o) {
    (void)o;
    size_t findings = 0;
    printf("  %s%s%s\n", COL.bold, f->path, COL.reset);
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
        int has = 0;
        if (l->trail)    has = 1;
        if (l->cr)       has = 1;
        if (l->lead_tab) has = 1;
        if (l->len > 100) has = 1;
        if (!has) continue;
        findings++;
        printf("  %sL%-5zu%s", COL.cyan, l->line_no, COL.reset);
        if (l->trail)     printf(" %sTW%s", COL.yellow, COL.reset);
        if (l->cr)        printf(" %sCR%s", COL.yellow, COL.reset);
        if (l->lead_tab)  printf(" %sTAB%s", COL.yellow, COL.reset);
        if (l->len > 100) printf(" %sLONG(%zu)%s", COL.yellow, l->len, COL.reset);
        printf("\n");
    }
    printf("\n  %zu %sfindings%s · %zu %slines%s\n",
           findings, COL.cyan, COL.reset, f->n_lines, COL.cyan, COL.reset);
    return findings ? 1 : 0;
}

int erdict_find_matching_brace(const erdict_file_t *f,
                               size_t start_line_1, size_t start_col_0,
                               size_t *end_line_1, size_t *end_col_0)
{
    if (start_line_1 < 1 || start_line_1 > f->n_lines) return -1;

    int depth = 0, opened = 0;
    int in_block = 0, in_str = 0;
    char quote = 0;

    for (size_t ln = start_line_1; ln <= f->n_lines; ln++) {
        const erdict_line_t *L = &f->lines[ln - 1];
        const char *p = L->p;
        size_t n = L->len;
        size_t k = (ln == start_line_1) ? start_col_0 : 0;
        for (; k < n; k++) {
            char c = p[k];
            if (in_block) {
                if (c == '*' && k + 1 < n && p[k+1] == '/') { in_block = 0; k++; }
                continue;
            }
            if (in_str) {
                if (c == '\\' && k + 1 < n) { k++; continue; }
                if (c == quote) in_str = 0;
                continue;
            }
            if (c == '/' && k + 1 < n && p[k+1] == '/') break;
            if (c == '/' && k + 1 < n && p[k+1] == '*') { in_block = 1; k++; continue; }
            if (c == '"' || c == '\'') { in_str = 1; quote = c; continue; }
            if (c == '{') { depth++; opened = 1; }
            else if (c == '}') {
                depth--;
                if (opened && depth == 0) {
                    if (end_line_1) *end_line_1 = ln;
                    if (end_col_0)  *end_col_0  = k;
                    return 0;
                }
            }
        }
    }
    return -1;
}

int erdict_mode_section(const erdict_file_t *f, const erdict_opts_t *o) {
    if (!o->pattern) { erdict_err("--section requires a name"); return 2; }

    erdict_sym_t *syms = NULL;
    size_t n = 0;
    if (erdict_symbols_scan(f, &syms, &n) != 0) { erdict_err("symbol scan failed"); return 2; }

    size_t found_line = 0;
    int exact = 0;
    for (size_t i = 0; i < n && !exact; i++) {
        if (syms[i].kind != ERDICT_SYM_FUNC) continue;
        if (strcmp(syms[i].name, o->pattern)) continue;
        size_t ln = syms[i].line_no;
        if (ln < 1 || ln > f->n_lines) continue;
        const erdict_line_t *L = &f->lines[ln - 1];
        const char *semi  = memchr(L->p, ';', L->len);
        const char *brace = memchr(L->p, '{', L->len);
        if (!semi || brace) { found_line = ln; exact = 1; }
    }
    if (!exact) {
        for (size_t i = 0; i < n && !found_line; i++) {
            if (syms[i].kind != ERDICT_SYM_FUNC) continue;
            if (!strstr(syms[i].name, o->pattern)) continue;
            size_t ln = syms[i].line_no;
            if (ln < 1 || ln > f->n_lines) continue;
            const erdict_line_t *L = &f->lines[ln - 1];
            const char *semi  = memchr(L->p, ';', L->len);
            const char *brace = memchr(L->p, '{', L->len);
            if (!semi || brace) found_line = ln;
        }
    }

    if (!found_line) {
        erdict_err("section '%s' not found", o->pattern);
        fprintf(stderr, "  closest matches:\n");
        int shown = 0;
        for (size_t i = 0; i < n && shown < 5; i++) {
            if (syms[i].kind != ERDICT_SYM_FUNC) continue;
            if (strstr(syms[i].name, o->pattern) ||
                strstr(o->pattern, syms[i].name))
            {
                fprintf(stderr, "    L%zu  %s\n", syms[i].line_no, syms[i].name);
                shown++;
            }
        }
        if (!shown) {
            for (size_t i = 0; i < n && shown < 10; i++) {
                if (syms[i].kind != ERDICT_SYM_FUNC) continue;
                fprintf(stderr, "    L%zu  %s\n", syms[i].line_no, syms[i].name);
                shown++;
            }
        }
        free(syms);
        return 1;
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
    size_t end = f->n_lines - 1;
    if (open_line &&
        erdict_find_matching_brace(f, open_line, open_col, &end_line, &end_col) == 0)
    {
        end = end_line - 1;
        const erdict_line_t *last = &f->lines[end_line - 1];
        int after = 0;
        for (size_t j = end_col + 1; j < last->len; j++)
            if (last->p[j] != ' ' && last->p[j] != '\t') { after = 1; break; }
        if (after) {
            erdict_err("refusing: '%s' ends mid-line (minified C not supported)", o->pattern);
            free(syms);
            return 2;
        }
    }

    printf("  %s%s%s   section %s%s%s   L%zu-%zu  (%zu lines)\n",
           COL.bold, f->path, COL.reset,
           COL.cyan, o->pattern, COL.reset,
           start + 1, end + 1, end - start + 1);

    size_t tw = 0, cr = 0, tabs = 0;
    for (size_t i = start; i <= end; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
        if (l->trail) tw++;
        if (l->cr)    cr++;
        if (l->lead_tab) tabs++;
        erdict_print_line_plain(stdout, l);
    }

    const char *C = COL.cyan, *Z = COL.reset;
    printf("\n  %zu %slines%s · %zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n",
           end - start + 1, C, Z, tabs, C, Z, tw, C, Z, cr, C, Z);

    free(syms);
    return 0;
}
