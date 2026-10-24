/** stats.c — file summary. */

#include "erdict.h"
#include <stdio.h>
#include <string.h>

int erdict_mode_stats(const erdict_file_t *f, const erdict_opts_t *o) {
    (void)o;
    size_t blank = 0, comment = 0, code = 0;
    size_t tw = 0, cr = 0, tabs = 0;
    size_t maxcol = 0, totalcol = 0;

    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
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

    const char *C = COL.cyan, *Z = COL.reset, *B = COL.bold;

    printf("  %s%s%s\n", B, f->path, Z);
    printf("  %slines%s       %zu\n",  C, Z, f->n_lines);
    printf("  %sbytes%s       %zu\n",  C, Z, f->buf_len);
    printf("  %sblank%s       %zu\n",  C, Z, blank);
    printf("  %scomment%s     %zu\n",  C, Z, comment);
    printf("  %scode%s        %zu\n",  C, Z, code);
    printf("  %smax col%s     %zu\n",  C, Z, maxcol);
    printf("  %savg col%s     %.1f\n", C, Z,
           f->n_lines ? (double)totalcol / (double)f->n_lines : 0.0);
    printf("  %sline ending%s %s\n",  C, Z, f->crlf ? "CRLF" : "LF");

    printf("\n  %zu %slines%s · %zu %stabs%s · %zu %sTW%s · %zu %sCR%s\n",
           f->n_lines, C, Z, tabs, C, Z, tw, C, Z, cr, C, Z);
    return 0;
}
