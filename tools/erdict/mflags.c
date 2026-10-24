/** mflags.c — extract -I flags by running make -n on the default target.
 * The default target compiles every source file, so its -I set covers
 * all sources in the module. Falls back to specific .o target if default
 * produces no compile commands (already built or unusual Makefile). */

#include "erdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_and_extract(const char *dir, const char *target,
                           char *out_buf, size_t out_len) {
    char cmd[2048];
    if (target && *target) {
        snprintf(cmd, sizeof cmd,
                 "cd '%s' 2>/dev/null && "
                 "make -n '%s' 2>/dev/null | "
                 "grep -oE '\\-I[^ ]+' | sort -u | tr '\\n' ' '",
                 dir, target);
    } else {
        snprintf(cmd, sizeof cmd,
                 "cd '%s' 2>/dev/null && "
                 "make -n 2>/dev/null | "
                 "grep -oE '\\-I[^ ]+' | sort -u | tr '\\n' ' '",
                 dir);
    }
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    size_t n = 0;
    int ch;
    while ((ch = fgetc(p)) != EOF && n + 1 < out_len) {
        out_buf[n++] = (char)ch;
    }
    out_buf[n] = 0;
    pclose(p);
    return n > 0 ? 0 : -1;
}

int erdict_make_incs(const char *dir, const char *target,
                     char *out_buf, size_t out_len) {
    if (!dir || !out_buf || out_len < 64) return -1;
    out_buf[0] = 0;

    /* First: try specific target names for the file */
    if (target && *target) {
        const char *suffixes[] = { ".o", "build/%s.o", "src/%s.o", NULL };
        char tbuf[512];
        for (int i = 0; suffixes[i]; i++) {
            if (strchr(suffixes[i], '%')) {
                snprintf(tbuf, sizeof tbuf, suffixes[i], target);
            } else {
                snprintf(tbuf, sizeof tbuf, "%s%s", target, suffixes[i]);
            }
            if (run_and_extract(dir, tbuf, out_buf, out_len) == 0) {
                return 0;
            }
        }
    }

    /* Fallback: run make -n on default target — gets -I for all sources */
    if (run_and_extract(dir, NULL, out_buf, out_len) == 0) {
        return 0;
    }

    /* Final fallback: grep the Makefile directly for -I... lines
     * (covers already-built case where make -n shows nothing) */
    char path[1024];
    snprintf(path, sizeof path, "%s/Makefile", dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char line[2048];
    size_t w = 0;
    while (fgets(line, sizeof line, f) && w + 4 < out_len) {
        const char *p = line;
        while ((p = strstr(p, "-I")) != NULL) {
            p += 2;
            if (*p == 0 || *p == ' ' || *p == '\n' || *p == '\\') continue;
            const char *q = p;
            while (*q && *q != ' ' && *q != '\n' && *q != '\\' && *q != '\t') q++;
            size_t tl = (size_t)(q - p);
            if (tl == 0 || tl > 400) { p = q; continue; }
            /* Emit as -I<path> token */
            if (w > 0 && w + 3 < out_len) out_buf[w++] = ' ';
            if (w + tl + 3 < out_len) {
                out_buf[w++] = '-'; out_buf[w++] = 'I';
                memcpy(out_buf + w, p, tl);
                w += tl;
                out_buf[w] = 0;
            }
            p = q;
        }
    }
    fclose(f);
    return w > 0 ? 0 : -1;
}
