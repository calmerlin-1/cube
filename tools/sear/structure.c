/** structure.c — list functions, structs, macros, imports, globals. */

#include "sear.h"
#include "symbols.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int match_opt(const char *name, const char *pat) {
    if (!pat) return 1;
    return strstr(name, pat) != NULL;
}

int sear_mode_structure(const sear_file_t *f, const sear_opts_t *o) {
    sear_sym_t *syms = NULL;
    size_t n = 0;
    if (sear_symbols_scan(f, &syms, &n) != 0) {
        sear_err("symbol scan failed");
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
        sear_sym_t *s = &syms[i];
        int show = 0;
        const char *kind = "";
        switch (s->kind) {
        case SEAR_SYM_FUNC:
            if (want_func && match_opt(s->name, o->pattern)) { show = 1; kind = "FUNC"; }
            c_func++;
            break;
        case SEAR_SYM_STRUCT:
            if (want_struct && match_opt(s->name, o->pattern)) { show = 1; kind = "STRUCT"; }
            c_struct++;
            break;
        case SEAR_SYM_MACRO:
            if (want_macro && match_opt(s->name, o->pattern)) { show = 1; kind = "MACRO"; }
            c_macro++;
            break;
        case SEAR_SYM_IMPORT:
            if (want_import) { show = 1; kind = "INCLUDE"; }
            c_import++;
            break;
        case SEAR_SYM_GLOBAL:
            if (want_global && match_opt(s->name, o->pattern)) { show = 1; kind = "GLOBAL"; }
            c_global++;
            break;
        }
        if (!show) continue;
        const char *kc = COL.dim;
        if      (s->kind == SEAR_SYM_FUNC)   kc = COL.green;
        else if (s->kind == SEAR_SYM_STRUCT) kc = COL.yellow;
        else if (s->kind == SEAR_SYM_MACRO)  kc = COL.yellow;
        else if (s->kind == SEAR_SYM_IMPORT) kc = COL.cyan;
        else if (s->kind == SEAR_SYM_GLOBAL) kc = COL.dim_cyan;
        printf("  %sL%-5zu%s %s%-8s%s %s%s%s\n",
               COL.cyan, s->line_no, COL.reset,
               kc, kind, COL.reset,
               COL.bold, s->name, COL.reset);
    }

    printf("\n  ");
    int first = 1;
    if (want_func)    { printf("%zu func%s", c_func, c_func == 1 ? "" : "s"); first = 0; }
    if (want_struct)  { printf("%s%zu struct%s", first ? "" : " · ", c_struct, c_struct == 1 ? "" : "s"); first = 0; }
    if (want_macro)   { printf("%s%zu macro%s", first ? "" : " · ", c_macro, c_macro == 1 ? "" : "s"); first = 0; }
    if (want_import)  { printf("%s%zu include%s", first ? "" : " · ", c_import, c_import == 1 ? "" : "s"); first = 0; }
    if (want_global)  { printf("%s%zu global%s", first ? "" : " · ", c_global, c_global == 1 ? "" : "s"); first = 0; }
    printf("\n");

    free(syms);
    return 0;
}

/* --section <name>: print the body of a named function. Uses the symbol table to find the definition, then walks braces from that line to the matching close. */

typedef struct { const char *name; size_t line_no; } sec_hit_t;

int sear_mode_section(const sear_file_t *f, const sear_opts_t *o) {
    if (!o->pattern) { sear_err("--section requires a name"); return 2; }

    sear_sym_t *syms = NULL;
    size_t n = 0;
    if (sear_symbols_scan(f, &syms, &n) != 0) { sear_err("symbol scan failed"); return 2; }

    /* exact match that is a definition (no trailing ';'), then substring */
    size_t found_line = 0;
    int exact = 0;
    for (size_t i = 0; i < n && !exact; i++) {
        if (syms[i].kind != SEAR_SYM_FUNC) continue;
        if (strcmp(syms[i].name, o->pattern)) continue;
        size_t ln = syms[i].line_no;
        if (ln < 1 || ln > f->n_lines) continue;
        const sear_line_t *L = &f->lines[ln - 1];
        const char *semi  = memchr(L->p, ';', L->len);
        const char *brace = memchr(L->p, '{', L->len);
        if (!semi || brace) { found_line = ln; exact = 1; }
    }
    if (!exact) {
        for (size_t i = 0; i < n && !found_line; i++) {
            if (syms[i].kind != SEAR_SYM_FUNC) continue;
            if (!strstr(syms[i].name, o->pattern)) continue;
            size_t ln = syms[i].line_no;
            if (ln < 1 || ln > f->n_lines) continue;
            const sear_line_t *L = &f->lines[ln - 1];
            const char *semi  = memchr(L->p, ';', L->len);
            const char *brace = memchr(L->p, '{', L->len);
            if (!semi || brace) found_line = ln;
        }
    }

    if (!found_line) {
        /* hint: list similar names */
        sear_err("section '%s' not found", o->pattern);
        fprintf(stderr, "  closest matches:\n");
        int shown = 0;
        for (size_t i = 0; i < n && shown < 5; i++) {
            if (syms[i].kind != SEAR_SYM_FUNC) continue;
            if (strstr(syms[i].name, o->pattern) ||
                strstr(o->pattern, syms[i].name))
            {
                fprintf(stderr, "    L%zu  %s\n", syms[i].line_no, syms[i].name);
                shown++;
            }
        }
        /* if nothing similar, list first 10 funcs */
        if (!shown) {
            for (size_t i = 0; i < n && shown < 10; i++) {
                if (syms[i].kind != SEAR_SYM_FUNC) continue;
                fprintf(stderr, "    L%zu  %s\n", syms[i].line_no, syms[i].name);
                shown++;
            }
        }
        free(syms);
        return 2;
    }

    /* Walk from found_line to matching close brace. */
    size_t start = found_line - 1;
    int depth = 0;
    int opened = 0;
    size_t end = f->n_lines - 1;

    for (size_t i = start; i < f->n_lines; i++) {
        const char *p = f->lines[i].p;
        size_t len = f->lines[i].len;
        for (size_t k = 0; k < len; k++) {
            if (p[k] == '{') { depth++; opened = 1; }
            else if (p[k] == '}') {
                depth--;
                if (opened && depth == 0) { end = i; goto done; }
            }
        }
    }
done:

    printf("  %s%s%s   section %s%s%s   L%zu-%zu  (%zu lines)\n",
           COL.bold, f->path, COL.reset,
           COL.cyan, o->pattern, COL.reset,
           start + 1, end + 1, end - start + 1);

    for (size_t i = start; i <= end; i++) {
        sear_line_t *l = &f->lines[i];
        sear_ws_classify(f, l);
        sear_print_line_plain(stdout, l);
    }

    free(syms);
    return 0;
}
