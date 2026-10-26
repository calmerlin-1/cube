/** search.c — pattern search mode.
 * Picks substring vs regex based on the pattern's delimiters. */

#include "sear.h"
#include <stdio.h>
#include <string.h>

/* If pattern looks like /.../ treat as regex, else substring. */
sear_pattern_t *sear_make_pattern(const sear_opts_t *o) {
    if (!o->pattern) return NULL;
    size_t n = strlen(o->pattern);
    if (n >= 2 && o->pattern[0] == '/' && o->pattern[n-1] == '/') {
        char *re = sear_xstrndup(o->pattern + 1, n - 2);
        sear_pattern_t *p = sear_pattern_regex(re);
        free(re);
        return p;
    }
    return sear_pattern_substring(o->pattern, o->icase);
}

int sear_mode_search(const sear_file_t *f, const sear_opts_t *o) {
    sear_pattern_t *p = sear_make_pattern(o);
    if (!p) {
        sear_err("bad pattern: %s", o->pattern ? o->pattern : "(null)");
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
        sear_line_t *l = &f->lines[i];
        size_t off = sear_pattern_find(p, l->p, l->len);
        if (off == SIZE_MAX) continue;

        sear_ws_classify(f, l);
        matches++;
        if (l->trail) tw++;
        if (l->cr) cr++;
        tabs += l->lead_tab;

        if (o->json) {
            if (!first) printf(",");
            first = 0;
            printf("{\"line\":%zu,\"col\":%zu",
                   l->line_no, sear_col_of_match(l->p, l->len, off));
            printf(",\"text\":\"");
            /* minimal JSON escape for the common cases */
            for (size_t k = 0; k < l->len; k++) {
                unsigned char c = (unsigned char)l->p[k];
                if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
                else if (c == '\n' || c == '\r' || c == '\t') {
                    putchar('\\');
                    putchar(c == '\n' ? 'n' : c == '\r' ? 'r' : 't');
                } else if (c < 0x20) printf("\\u%04x", c);
                else putchar(c);
            }
            printf("\"}");
        } else if (o->brief) {
            printf("  L%-4zu C%-3zu  ",
                   l->line_no, sear_col_of_match(l->p, l->len, off));
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
        } else if (o->count_only) {
            /* print only at the end */
        } else {
            sear_print_line_detail(stdout, l, off, 1);
        }
    }

    if (o->json) printf("],\"count\":%zu}\n", matches);

    if (!o->json && !o->brief) {
        printf("\n  %zu match%s in 1 file · %zu line%s · %zu tab%s · %zu trailing-ws · %zu CR\n",
               matches, matches == 1 ? "" : "es",
               matches, matches == 1 ? "" : "s",
               tabs, tabs == 1 ? "" : "s",
               tw, cr);
    } else if (o->count_only) {
        printf("%zu\n", matches);
    }

    sear_pattern_free(p);
    return matches ? 0 : 2;
}


/* Multi-file search: iterate over o->files, one sear_mode_search per file, then a combined summary at the end. */

typedef struct {
    sear_pattern_t *pat;
    const sear_opts_t *o;
    size_t  total_matches;
    size_t  total_files_with_matches;
    size_t  total_tabs;
    size_t  total_tw;
    size_t  total_cr;
    int     first;
} multi_ctx_t;

static int run_one_file(const char *path, void *ud) {
    multi_ctx_t *mc = ud;

    sear_file_t f;
    if (sear_file_load(path, &f) != 0) return 0;

    size_t matches = 0, tw = 0, cr = 0, tabs = 0;
    for (size_t i = 0; i < f.n_lines; i++) {
        sear_line_t *l = &f.lines[i];
        size_t off = sear_pattern_find(mc->pat, l->p, l->len);
        if (off == SIZE_MAX) continue;
        sear_ws_classify(&f, l);
        matches++;
        if (l->trail) tw++;
        if (l->cr) cr++;
        tabs += l->lead_tab;

        if (!mc->o->json && !mc->o->brief && !mc->o->count_only) {
            if (matches == 1) {
                if (!mc->first) putchar('\n');
                mc->first = 0;
                printf("  %s%s%s\n", COL.bold, path, COL.reset);
            }
            sear_print_line_detail(stdout, l, off, 1);
        } else if (mc->o->brief && !mc->o->json) {
            printf("  %s%s%s:%zu:%zu  ",
                   COL.cyan, path, COL.reset,
                   l->line_no, sear_col_of_match(l->p, l->len, off));
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
        }
    }

    if (matches > 0) {
        mc->total_matches += matches;
        mc->total_files_with_matches++;
        mc->total_tabs += tabs;
        mc->total_tw += tw;
        mc->total_cr += cr;
    }

    sear_file_free(&f);
    return 0;
}

int sear_mode_search_multi(const sear_opts_t *o) {
    sear_pattern_t *p = sear_make_pattern(o);
    if (!p) {
        sear_err("bad pattern: %s", o->pattern ? o->pattern : "(null)");
        return 2;
    }

    multi_ctx_t mc = {0};
    mc.pat = p;
    mc.o = o;
    mc.first = 1;

    const char *const suffixes[] = { ".c", ".h", NULL };

    if (o->json) printf("{\"files\":[");

    int first_json = 1;
    for (size_t i = 0; i < o->n_files; i++) {
        const char *path = o->files[i];
        /* if it's a directory and -r was passed, walk it */
        if (o->recurse) {
            if (o->json) {
                /* JSON path also walks, we just call the same cb */
                sear_walk(path, suffixes, run_one_file, &mc);
            } else {
                sear_walk(path, suffixes, run_one_file, &mc);
            }
        } else {
            run_one_file(path, &mc);
        }
        (void)first_json;
    }

    if (o->json) printf("]}");
    if (!o->json && !o->brief && !o->count_only) {
        printf("\n  %zu match%s in %zu file%s · %zu tab%s · %zu trailing-ws · %zu CR\n",
               mc.total_matches, mc.total_matches == 1 ? "" : "es",
               mc.total_files_with_matches,
               mc.total_files_with_matches == 1 ? "" : "s",
               mc.total_tabs, mc.total_tabs == 1 ? "" : "s",
               mc.total_tw, mc.total_cr);
    } else if (o->count_only) {
        printf("%zu\n", mc.total_matches);
    }

    sear_pattern_free(p);
    return mc.total_matches ? 0 : 2;
}
