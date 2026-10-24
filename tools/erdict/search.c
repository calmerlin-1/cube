/** search.c — pattern search mode.
 * Picks substring vs regex based on the pattern's delimiters. */

#include "erdict.h"
#include <stdio.h>
#include <string.h>

/* If pattern looks like /.../ treat as regex, else substring. */
erdict_pattern_t *erdict_make_pattern(const erdict_opts_t *o) {
    if (!o->pattern) return NULL;
    size_t n = strlen(o->pattern);
    if (n >= 2 && o->pattern[0] == '/' && o->pattern[n-1] == '/') {
        char *re = erdict_xstrndup(o->pattern + 1, n - 2);
        erdict_pattern_t *p = erdict_pattern_regex_icase(re, o->icase);
        free(re);
        return p;
    }
    return erdict_pattern_substring(o->pattern, o->icase);
}

/** Emit JSON-escaped text for a line. */
static void json_escape_line(const erdict_line_t *l) {
    for (size_t k = 0; k < l->len; k++) {
        unsigned char c = (unsigned char)l->p[k];
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c == '\n' || c == '\r' || c == '\t') {
            putchar('\\');
            putchar(c == '\n' ? 'n' : c == '\r' ? 'r' : 't');
        } else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
}

int erdict_mode_search(const erdict_file_t *f, const erdict_opts_t *o) {
    erdict_pattern_t *p = erdict_make_pattern(o);
    if (!p) {
        erdict_err("bad pattern: %s", o->pattern ? o->pattern : "(null)");
        return 2;
    }

    size_t matches = 0;
    size_t tw = 0, cr = 0, tabs = 0;

    if (!o->json) {
        printf("  %s\n", f->path);
    } else {
        printf("{\"file\":\"%s\",\"matches\":[", f->path);
    }

    int first = 1;
    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        size_t off = erdict_pattern_find(p, l->p, l->len);
        if (off == SIZE_MAX) continue;

        erdict_ws_classify(f, l);
        matches++;
        if (l->trail) tw++;
        if (l->cr) cr++;
        tabs += l->lead_tab;

        if (o->json) {
            if (!first) printf(",");
            first = 0;
            printf("{\"line\":%zu,\"col\":%zu,\"text\":\"",
                   l->line_no, erdict_col_of_match(l->p, l->len, off));
            json_escape_line(l);
            printf("\"}");
        } else if (o->brief) {
            printf("  L%-4zu C%-3zu  ",
                   l->line_no, erdict_col_of_match(l->p, l->len, off));
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
        } else if (o->count_only) {
            /* print only at the end */
        } else {
            erdict_print_line_detail(stdout, l, off, 1);
        }
    }

    if (o->json) printf("],\"count\":%zu}\n", matches);

    if (!o->json && !o->brief) {
        const char *C = COL.cyan, *Z = COL.reset;
        printf("\n  %zu %smatch%s%s in %s1 file%s · %zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n",
               matches, C, matches == 1 ? "" : "es", Z,
               C, Z,
               tabs, C, Z, tw, C, Z, cr, C, Z);
    } else if (o->count_only) {
        printf("%zu\n", matches);
    }

    erdict_pattern_free(p);
    return matches ? 0 : 1;
}


/* ============================================================
 * Multi-file search: iterate over o->files, one run_one_file
 * per file, then a combined summary at the end.
 * ============================================================ */

typedef struct {
    erdict_pattern_t *pat;
    const erdict_opts_t *o;
    size_t  total_matches;
    size_t  total_files_with_matches;
    size_t  total_tabs;
    size_t  total_tw;
    size_t  total_cr;
    int     first;       /* first file header in full mode */
    int     first_json;  /* first JSON object emitted */
} multi_ctx_t;

static int run_one_file(const char *path, void *ud) {
    multi_ctx_t *mc = ud;

    erdict_file_t f;
    if (erdict_file_load(path, &f) != 0) return 0;

    size_t matches = 0, tw = 0, cr = 0, tabs = 0;
    for (size_t i = 0; i < f.n_lines; i++) {
        erdict_line_t *l = &f.lines[i];
        size_t off = erdict_pattern_find(mc->pat, l->p, l->len);
        if (off == SIZE_MAX) continue;
        erdict_ws_classify(&f, l);
        matches++;
        if (l->trail) tw++;
        if (l->cr) cr++;
        tabs += l->lead_tab;

        if (mc->o->json) {
            if (!mc->first_json) printf(",");
            mc->first_json = 0;
            printf("{\"file\":\"%s\",\"line\":%zu,\"col\":%zu,\"text\":\"",
                   path, l->line_no,
                   erdict_col_of_match(l->p, l->len, off));
            json_escape_line(l);
            printf("\"}");
        } else if (mc->o->brief && !mc->o->json) {
            printf("  %s%s%s:%zu:%zu  ",
                   COL.cyan, path, COL.reset,
                   l->line_no, erdict_col_of_match(l->p, l->len, off));
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
        } else if (!mc->o->count_only) {
            if (matches == 1) {
                if (!mc->first) putchar('\n');
                mc->first = 0;
                printf("  %s%s%s\n", COL.bold, path, COL.reset);
            }
            erdict_print_line_detail(stdout, l, off, 1);
        }
    }

    if (matches > 0) {
        mc->total_matches += matches;
        mc->total_files_with_matches++;
        mc->total_tabs += tabs;
        mc->total_tw += tw;
        mc->total_cr += cr;
    }

    erdict_file_free(&f);
    return 0;
}

int erdict_mode_search_multi(const erdict_opts_t *o) {
    erdict_pattern_t *p = erdict_make_pattern(o);
    if (!p) {
        erdict_err("bad pattern: %s", o->pattern ? o->pattern : "(null)");
        return 2;
    }

    multi_ctx_t mc = {0};
    mc.pat = p;
    mc.o = o;
    mc.first = 1;
    mc.first_json = 1;

    const char *const suffixes[] = { ".c", ".h", NULL };

    if (o->json) printf("{\"files\":[");

    for (size_t i = 0; i < o->n_files; i++) {
        const char *path = o->files[i];
        if (o->recurse) {
            erdict_walk(path, suffixes, run_one_file, &mc);
        } else {
            run_one_file(path, &mc);
        }
    }

    if (o->json) printf("]}");
    if (!o->json && !o->brief && !o->count_only) {
        const char *C = COL.cyan, *Z = COL.reset;
        printf("\n  %zu %smatch%s%s in %zu %sfile%s%s · "
               "%zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n",
               mc.total_matches, C, mc.total_matches == 1 ? "" : "es", Z,
               mc.total_files_with_matches, C, mc.total_files_with_matches == 1 ? "" : "s", Z,
               mc.total_tabs, C, Z, mc.total_tw, C, Z, mc.total_cr, C, Z);
    } else if (o->count_only) {
        printf("%zu\n", mc.total_matches);
    }

    erdict_pattern_free(p);
    return mc.total_matches ? 0 : 1;
}
