/** css_color.c — ANSI colorizer for CSS source. */
#include "css.h"
#include <stdio.h>
#include <string.h>

#define C_RESET   "\033[0m"
#define C_SEL     "\033[36m"    /* selector: cyan */
#define C_PROP    "\033[33m"    /* property: yellow */
#define C_VAL     "\033[32m"    /* value: green */
#define C_PUNCT   "\033[1m"     /* punctuation: bold */
#define C_COMMENT "\033[2m"     /* comment: dim */

int css_colorize(const char *src, size_t len, FILE *out) {
    if (!src || !out) return -1;
    size_t i = 0;
    int in_block = 0;
    while (i < len) {
        char c = src[i];
        /* comment */
        if (c == '/' && i + 1 < len && src[i+1] == '*') {
            size_t k = i + 2;
            while (k + 1 < len && !(src[k] == '*' && src[k+1] == '/')) k++;
            if (k + 1 < len) k += 2;
            fputs(C_COMMENT, out); fwrite(src + i, 1, k - i, out); fputs(C_RESET, out);
            i = k; continue;
        }
        /* block open */
        if (c == '{') {
            fputs(C_PUNCT, out); fputc('{', out); fputs(C_RESET, out);
            in_block = 1; i++; continue;
        }
        /* block close */
        if (c == '}') {
            fputs(C_PUNCT, out); fputc('}', out); fputs(C_RESET, out);
            in_block = 0; i++; continue;
        }
        /* semicolon */
        if (c == ';') {
            fputs(C_PUNCT, out); fputc(';', out); fputs(C_RESET, out);
            i++; continue;
        }
        /* whitespace passthrough */
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            fputc(c, out); i++; continue;
        }
        /* colon */
        if (c == ':' && in_block) {
            fputs(C_PUNCT, out); fputc(':', out); fputs(C_RESET, out);
            i++; continue;
        }
        /* selector (before any ':') or property (before ':') or value (after) */
        /* determine current segment */
        if (!in_block) {
            /* selector: colorize the whole run until { */
            size_t k = i;
            while (k < len && src[k] != '{' && src[k] != '/' ) k++;
            if (k > i) {
                fputs(C_SEL, out); fwrite(src + i, 1, k - i, out); fputs(C_RESET, out);
                i = k; continue;
            }
        } else {
            /* inside block: we alternate prop : value ; */
            /* scan current token until : ; } */
            size_t k = i;
            while (k < len && src[k] != ':' && src[k] != ';' && src[k] != '}') k++;
            int is_prop = (k < len && src[k] == ':');
            if (k > i) {
                fputs(is_prop ? C_PROP : C_VAL, out);
                fwrite(src + i, 1, k - i, out);
                fputs(C_RESET, out);
                i = k; continue;
            }
        }
        fputc(c, out); i++;
    }
    return 0;
}
