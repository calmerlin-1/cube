/** stats.c — file summary. */

#include "sear.h"
#include <stdio.h>
#include <string.h>

int sear_mode_stats(const sear_file_t *f, const sear_opts_t *o) {
    (void)o;
    size_t blank = 0, comment = 0, code = 0;
    size_t tw = 0, cr = 0, tabs = 0;
    size_t maxcol = 0, totalcol = 0;

    for (size_t i = 0; i < f->n_lines; i++) {
        sear_line_t *l = &f->lines[i];
        sear_ws_classify(f, l);
        if (l->trail) tw++;
        if (l->cr)    cr++;
        if (l->lead_tab) tabs++;
        if (l->len > maxcol) maxcol = l->len;
        totalcol += l->len;
        if (l->len == 0) blank++;
        else {
            const char *p = l->p;
            while (*p == ' ' || *p == '\t') p++;
            if (p[0] == '/' && (p[1] == '/' || p[1] == '*')) comment++;
            else code++;
        }
    }

    printf("  %s\n", f->path);
    printf("  lines       %zu\n", f->n_lines);
    printf("  bytes       %zu\n", f->buf_len);
    printf("  blank       %zu\n", blank);
    printf("  comment     %zu\n", comment);
    printf("  code        %zu\n", code);
    printf("  max col     %zu\n", maxcol);
    printf("  avg col     %.1f\n", f->n_lines ? (double)totalcol / (double)f->n_lines : 0.0);
    printf("  trailing    %zu\n", tw);
    printf("  tab lines   %zu\n", tabs);
    printf("  CR lines    %zu\n", cr);
    printf("  line ending %s\n", f->crlf ? "CRLF" : "LF");
    return 0;
}
