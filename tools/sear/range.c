/** range.c — print a line range.
 * Supports:
 *   10,20      lines 10 through 20
 *   10+5       line 10 and the next 5 (lines 10-15)
 *   /pat/      lines matching pattern
 *   /s/,/e/    between start and end patterns
 *   10,/e/     from 10 to next end pattern
 */

#include "sear.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Parse o->range_str into (start, end). Returns 0 on success. */
int sear_parse_range(const sear_file_t *f, const sear_opts_t *o,
                     size_t *out_start, size_t *out_end)
{
    const char *s = o->range_str;
    if (!s || !*s) return -1;

    /* N+K shorthand */
    if (s[0] >= '0' && s[0] <= '9') {
        char *end = NULL;
        long n1 = strtol(s, &end, 10);
        if (*end == '+') {
            long k = strtol(end + 1, NULL, 10);
            *out_start = (size_t)(n1 > 0 ? n1 - 1 : 0);
            *out_end   = *out_start + (size_t)k;
            return 0;
        }
        if (*end == ',' || *end == '-') {
            long n2 = strtol(end + 1, NULL, 10);
            *out_start = (size_t)(n1 > 0 ? n1 - 1 : 0);
            *out_end   = (size_t)(n2 > 0 ? n2 - 1 : 0);
            return 0;
        }
    }

    /* /pat/,/pat/ or /pat/ */
    if (s[0] == '/') {
        const char *e1 = strchr(s + 1, '/');
        if (!e1) return -1;
        char *p1 = sear_xstrndup(s + 1, (size_t)(e1 - s - 1));
        sear_pattern_t *pa = sear_pattern_regex(p1);
        free(p1);
        if (!pa) return -1;

        size_t start = SIZE_MAX;
        for (size_t i = 0; i < f->n_lines; i++) {
            if (sear_pattern_find(pa, f->lines[i].p, f->lines[i].len) != SIZE_MAX) {
                start = i; break;
            }
        }
        sear_pattern_free(pa);
        if (start == SIZE_MAX) return -1;

        if (e1[1] == ',') {
            const char *s2 = e1 + 2;
            if (s2[0] == '/') {
                const char *e2 = strrchr(s2 + 1, '/');
                if (!e2) return -1;
                char *p2 = sear_xstrndup(s2 + 1, (size_t)(e2 - s2 - 1));
                sear_pattern_t *pb = sear_pattern_regex(p2);
                free(p2);
                if (!pb) return -1;
                size_t end = start;
                for (size_t i = start + 1; i < f->n_lines; i++) {
                    if (sear_pattern_find(pb, f->lines[i].p, f->lines[i].len) != SIZE_MAX) {
                        end = i; break;
                    }
                }
                sear_pattern_free(pb);
                *out_start = start;
                *out_end   = end;
                return 0;
            }
        }
        *out_start = start;
        *out_end   = start;
        return 0;
    }
    return -1;
}

int sear_mode_range(const sear_file_t *f, const sear_opts_t *o) {
    size_t s = 0, e = 0;
    if (sear_parse_range(f, o, &s, &e) != 0) {
        sear_err("bad range: %s", o->range_str ? o->range_str : "(null)");
        return 2;
    }
    if (s >= f->n_lines) { sear_err("start beyond EOF"); return 2; }
    if (e >= f->n_lines) e = f->n_lines - 1;

    size_t blank = 0, comment = 0, tw = 0, cr = 0;
    printf("  %s   lines %zu-%zu  (%zu line%s)\n",
           f->path, s + 1, e + 1, e - s + 1, e == s ? "" : "s");

    for (size_t i = s; i <= e; i++) {
        sear_line_t *l = &f->lines[i];
        sear_ws_classify(f, l);
        if (l->len == 0) blank++;
        else {
            const char *p = l->p;
            while (*p == ' ' || *p == '\t') p++;
            if (p[0] == '/' && p[1] == '/') comment++;
            else if (p[0] == '/' && p[1] == '*') comment++;
        }
        if (l->trail) tw++;
        if (l->cr) cr++;
        sear_print_line_plain(stdout, l);
    }

    printf("\n  %zu lines · %zu blank · %zu comment · %zu TW · %zu CR\n",
           e - s + 1, blank, comment, tw, cr);
    return 0;
}
