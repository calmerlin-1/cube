/** html_color.c — ANSI colorizer for HTML source.
 *
 * Byte-level state machine. No parse, no allocation. Safe on any input.
 * Colors: tags yellow, attribute names cyan, values green, comments dim,
 * entities magenta.
 */
#include "html.h"
#include "css.h"
#include <stdio.h>
#include <string.h>

#define C_RESET   "\033[0m"
#define C_TAG     "\033[33m"
#define C_ATTR    "\033[36m"
#define C_VALUE   "\033[32m"
#define C_COMMENT "\033[2m"
#define C_ENTITY  "\033[35m"

int html_colorize(const char *src, size_t len, FILE *out) {
    if (!src || !out) return -1;
    size_t i = 0;
    while (i < len) {
        char c = src[i];

        /* <style>...</style> → delegate to css_colorize */
        if (c == '<' && i + 6 < len && src[i+1] == 's' &&
            src[i+2] == 't' && src[i+3] == 'y' && src[i+4] == 'l' && src[i+5] == 'e') {
            size_t tag_end = i;
            while (tag_end < len && src[tag_end] != '>') tag_end++;
            if (tag_end < len) tag_end++;
            /* Emit opening tag with normal HTML coloring */
            fputs("\033[33m", out);
            fwrite(src + i, 1, tag_end - i, out);
            fputs("\033[0m", out);
            fputc('\n', out);
            /* Find </style> */
            size_t close = tag_end;
            while (close + 7 < len &&
                   !(src[close] == '<' && src[close+1] == '/' &&
                     src[close+2] == 's' && src[close+3] == 't' &&
                     src[close+4] == 'y' && src[close+5] == 'l' &&
                     src[close+6] == 'e')) close++;
            if (close + 7 < len) {
                css_colorize(src + tag_end, close - tag_end, out);
                fputs("\033[33m", out);
                fputs("</style>", out);
                fputs("\033[0m", out);
                i = close + 8;
                continue;
            }
        }

        if (c == '<' && i + 3 < len && !memcmp(src + i, "<!--", 4)) {
            const char *end = NULL;
            for (size_t k = i + 4; k + 2 < len; k++) {
                if (src[k] == '-' && src[k+1] == '-' && src[k+2] == '>') {
                    end = src + k + 3;
                    break;
                }
            }
            size_t clen = end ? (size_t)(end - (src + i)) : (len - i);
            fputs(C_COMMENT, out);
            fwrite(src + i, 1, clen, out);
            fputs(C_RESET, out);
            i += clen;
            continue;
        }

        if (c == '<' && i + 1 < len && src[i+1] == '!') {
            size_t k = i;
            while (k < len && src[k] != '>') k++;
            if (k < len) k++;
            fputs(C_COMMENT, out);
            fwrite(src + i, 1, k - i, out);
            fputs(C_RESET, out);
            i = k;
            continue;
        }

        if (c == '<') {
            size_t k = i;
            fputs(C_TAG, out);
            putc(src[k++], out);
            if (k < len && src[k] == '/') putc(src[k++], out);
            while (k < len && src[k] != '>' && src[k] != ' ' && src[k] != '\t' &&
                   src[k] != '\n' && src[k] != '\r' && src[k] != '/')
                putc(src[k++], out);
            while (k < len && src[k] != '>' && src[k] != '/') {
                if (src[k] == '"' || src[k] == '\'') {
                    char q = src[k];
                    fputs(C_VALUE, out);
                    putc(src[k++], out);
                    while (k < len && src[k] != q) putc(src[k++], out);
                    if (k < len) putc(src[k++], out);
                    fputs(C_TAG, out);
                    continue;
                }
                if (src[k] == '=') { putc(src[k++], out); continue; }
                if (src[k] == '/') { putc(src[k++], out); continue; }
                if (src[k] == ' ' || src[k] == '\t' || src[k] == '\n' || src[k] == '\r') {
                    putc(src[k++], out);
                    continue;
                }
                fputs(C_ATTR, out);
                while (k < len && src[k] != '=' && src[k] != '>' && src[k] != ' ' &&
                       src[k] != '\t' && src[k] != '\n' && src[k] != '\r' &&
                       src[k] != '/' && src[k] != '"' && src[k] != '\'')
                    putc(src[k++], out);
                fputs(C_TAG, out);
            }
            if (k < len && src[k] == '/') putc(src[k++], out);
            if (k < len && src[k] == '>') putc(src[k++], out);
            fputs(C_RESET, out);
            i = k;
            continue;
        }

        if (c == '&') {
            size_t k = i;
            while (k < len && src[k] != ';' && k - i < 12) k++;
            if (k < len && src[k] == ';') {
                k++;
                fputs(C_ENTITY, out);
                fwrite(src + i, 1, k - i, out);
                fputs(C_RESET, out);
                i = k;
                continue;
            }
        }

        putc(c, out);
        i++;
    }
    return 0;
}
