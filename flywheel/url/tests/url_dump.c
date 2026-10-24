/**
 * url_dump.c — parse one URL and print every field.
 *
 * Not a test. Not a benchmark. A magnifying glass.
 * Input:  URL on the command line
 * Output: each parsed field, one per line, colored
 *
 * Use this to answer:
 *   - did it parse my URL at all?
 *   - which scheme / host / path / query did it find?
 *   - did it decode the percent escapes? (no — parser keeps them)
 *   - did it treat data: URLs correctly?
 *
 * Empty fields are hidden. Only fields that have content are printed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "url_parser.h"
#include "color.h"

static void field(const char *name, const char *s, size_t n) {
    if (!s || n == 0) return;
    printf("  %s%-9s%s ", col_dim(), name, col_reset());
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <url> [<url> ...]\n", argv[0]);
        return 1;
    }

    col_enable();

    for (int i = 1; i < argc; i++) {
        const char *raw = argv[i];
        size_t rawlen = strlen(raw);

        printf("%s%s%s\n", col_bold(), raw, col_reset());

        url_view v;
        url_err e = url_parse(raw, rawlen, &v);

        if (e != URL_OK) {
            printf("  %sERR%s  %s\n\n",
                   col_red(), col_reset(), url_err_name(e));
            continue;
        }

        field("scheme",   v.scheme,   v.scheme_len);
        field("user",     v.userinfo, v.userinfo_len);
        field("host",     v.host,     v.host_len);
        if (v.port)
            printf("  %s%-9s%s %u\n", col_dim(), "port", col_reset(),
                   (unsigned)v.port);
        field("path",     v.path,     v.path_len);
        field("query",    v.query,    v.query_len);
        field("fragment", v.fragment, v.fragment_len);

        char out[4096];
        size_t n = 0;
        url_err ce = url_canonicalize(&v, out, sizeof(out), &n);
        if (ce == URL_OK) {
            out[n] = 0;
            printf("  %s%-9s%s %s%s%s\n",
                   col_dim(), "canonical", col_reset(),
                   col_cyan(), out, col_reset());
        } else {
            printf("  %s%-9s%s %s%s%s\n",
                   col_dim(), "canonical", col_reset(),
                   col_red(), url_err_name(ce), col_reset());
        }
        printf("  %sOK%s\n\n", col_green(), col_reset());
    }
    return 0;
}
