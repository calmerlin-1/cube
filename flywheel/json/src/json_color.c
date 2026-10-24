/** json_color.c — ANSI colorizer for JSON source. */
#include "json.h"
#include <string.h>

#define C_RESET  "\033[0m"
#define C_KEY    "\033[36m"
#define C_STR    "\033[32m"
#define C_NUM    "\033[33m"
#define C_BOOL   "\033[35m"
#define C_PUNCT  "\033[2m"

int json_colorize(const char *src, size_t len, FILE *out) {
    if (!src || !out) return -1;
    size_t i = 0;
    int in_string = 0, esc = 0, is_key = 0;

    while (i < len) {
        char c = src[i];

        if (in_string) {
            if (esc) { putc(c, out); esc = 0; i++; continue; }
            if (c == '\\') { putc(c, out); esc = 1; i++; continue; }
            if (c == '"') {
                putc(c, out);
                in_string = 0;
                size_t k = i + 1;
                while (k < len && (src[k] == ' ' || src[k] == '\t' ||
                                   src[k] == '\n' || src[k] == '\r')) k++;
                fputs(C_RESET, out);
                if (k < len && src[k] == ':') is_key = 1;
                i++;
                continue;
            }
            putc(c, out);
            i++;
            continue;
        }

        if (c == '"') {
            fputs(is_key ? C_KEY : C_STR, out);
            putc(c, out);
            in_string = 1;
            is_key = 0;
            i++;
            continue;
        }

        if (c == ':' || c == ',' || c == '{' || c == '}' ||
            c == '[' || c == ']') {
            fputs(C_PUNCT, out);
            putc(c, out);
            fputs(C_RESET, out);
            i++;
            continue;
        }

        if ((c >= '0' && c <= '9') || c == '-') {
            fputs(C_NUM, out);
            while (i < len && ((src[i] >= '0' && src[i] <= '9') ||
                               src[i] == '-' || src[i] == '+' ||
                               src[i] == '.' || src[i] == 'e' ||
                               src[i] == 'E')) {
                putc(src[i++], out);
            }
            fputs(C_RESET, out);
            continue;
        }

        if (!strncmp(src + i, "true",  4)) { fputs(C_BOOL "true" C_RESET, out);  i += 4; continue; }
        if (!strncmp(src + i, "false", 5)) { fputs(C_BOOL "false" C_RESET, out); i += 5; continue; }
        if (!strncmp(src + i, "null",  4)) { fputs(C_BOOL "null" C_RESET, out);  i += 4; continue; }

        putc(c, out);
        i++;
    }
    return 0;
}
