/** colorize.c — lightweight ANSI colorizer for JavaScript responses. */

#include "js_colorize.h"
#include <string.h>
#include <ctype.h>

#define C_RESET  "\033[0m"
#define C_KEY    "\033[34;1m"
#define C_STR    "\033[32m"
#define C_NUM    "\033[33m"
#define C_COMM   "\033[2m"

static int is_keyword(const char *s, size_t n) {
    static const char *kw[] = {
        "break","case","catch","class","const","continue","debugger","default",
        "delete","do","else","export","extends","finally","for","function","if",
        "import","in","instanceof","let","new","return","super","switch","this",
        "throw","try","typeof","var","void","while","with","yield","async","await",
        "of","static","get","set","true","false","null","undefined","NaN",
        "Infinity","typeof","interface","enum","implements","package","private",
        "protected","public", NULL
    };
    for (int i = 0; kw[i]; i++)
        if (strlen(kw[i]) == n && !strncmp(kw[i], s, n)) return 1;
    return 0;
}

static void put_range(FILE *out, const char *s, size_t n) {
    if (n) fwrite(s, 1, n, out);
}

int js_colorize(const char *src, size_t len, FILE *out) {
    if (!src || !out) return -1;
    size_t i = 0;
    while (i < len) {
        char c = src[i];
        char n = i + 1 < len ? src[i + 1] : 0;

        if (c == '/' && n == '/') {
            size_t s = i;
            while (i < len && src[i] != '\n') i++;
            fputs(C_COMM, out);
            put_range(out, src + s, i - s);
            fputs(C_RESET, out);
            continue;
        }
        if (c == '/' && n == '*') {
            size_t s = i;
            i += 2;
            while (i + 1 < len && !(src[i] == '*' && src[i + 1] == '/')) i++;
            if (i + 1 < len) i += 2;
            fputs(C_COMM, out);
            put_range(out, src + s, i - s);
            fputs(C_RESET, out);
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') {
            char q = c;
            size_t s = i++;
            while (i < len) {
                if (src[i] == '\\' && i + 1 < len) { i += 2; continue; }
                if (src[i] == q) { i++; break; }
                if (q != '`' && src[i] == '\n') break;
                i++;
            }
            fputs(C_STR, out);
            put_range(out, src + s, i - s);
            fputs(C_RESET, out);
            continue;
        }
        if (isdigit((unsigned char)c) ||
            (c == '.' && i + 1 < len && isdigit((unsigned char)src[i + 1]))) {
            size_t s = i++;
            while (i < len && (isalnum((unsigned char)src[i]) ||
                               src[i] == '.' || src[i] == '_')) i++;
            fputs(C_NUM, out);
            put_range(out, src + s, i - s);
            fputs(C_RESET, out);
            continue;
        }
        if (isalpha((unsigned char)c) || c == '_' || c == '$') {
            size_t s = i++;
            while (i < len && (isalnum((unsigned char)src[i]) ||
                               src[i] == '_' || src[i] == '$')) i++;
            if (is_keyword(src + s, i - s)) {
                fputs(C_KEY, out);
                put_range(out, src + s, i - s);
                fputs(C_RESET, out);
            } else {
                put_range(out, src + s, i - s);
            }
            continue;
        }
        if (fputc(c, out) == EOF) return -1;
        i++;
    }
    return ferror(out) ? -1 : 0;
}
