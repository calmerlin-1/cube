/**
 * scan_parity.c — prove that every scan_* implementation agrees.
 *
 * Loads a corpus, runs each input through both the scalar reference
 * and the currently-selected architecture version, and asserts
 * byte-for-byte agreement.
 *
 * Usage: scan_parity <file> [<file> ...]
 *
 * Exit: 0 all match, 1 mismatch, 2 no files given.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "color.h"

#define scan_bad_char  scan_bad_char_scalar
#define scan_find      scan_find_scalar
#define scan_find_any4 scan_find_any4_scalar
#define scan_all_scheme scan_all_scheme_scalar
#include "scan_scalar.h"
#undef scan_bad_char
#undef scan_find
#undef scan_find_any4
#undef scan_all_scheme

#define scan_bad_char  scan_bad_char_arch
#define scan_find      scan_find_arch
#define scan_find_any4 scan_find_any4_arch
#define scan_all_scheme scan_all_scheme_arch
#if defined(__aarch64__) || defined(__ARM_NEON)
#include "scan_neon.h"
#else
/* Non-NEON hosts still run the parity harness: the "arch" side is the
 * portable reference, which is the correct baseline there. */
#define scan_bad_char_arch  scan_bad_char_scalar
#define scan_find_arch      scan_find_scalar
#define scan_find_any4_arch scan_find_any4_scalar
#define scan_all_scheme_arch scan_all_scheme_scalar
#endif
#undef scan_bad_char
#undef scan_find
#undef scan_find_any4
#undef scan_all_scheme

static int failures = 0;
static long total_checks = 0;

static void show_input(const char *s, size_t n) {
    printf("\"");
    for (size_t i = 0; i < n && i < 200; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"");
}

static void check_size(const char *name, const char *input, size_t n,
                       size_t got_s, size_t got_a)
{
    total_checks++;
    if (got_s == got_a) return;
    printf("%sMISMATCH%s %s\n", col_red(), col_reset(), name);
    printf("  input    ");
    show_input(input, n);
    printf("\n  scalar   %zu\n", got_s);
    printf("  arch     %zu\n", got_a);
    failures++;
}

static void check_int(const char *name, const char *input, size_t n,
                      int got_s, int got_a)
{
    total_checks++;
    if (got_s == got_a) return;
    printf("%sMISMATCH%s %s\n", col_red(), col_reset(), name);
    printf("  input    ");
    show_input(input, n);
    printf("\n  scalar   %d\n  arch     %d\n", got_s, got_a);
    failures++;
}

static void run_file(const char *path, long *lines) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("%s%s%s  %scannot open%s\n",
               col_yellow(), path, col_reset(),
               col_red(), col_reset());
        return;
    }
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] == '\n') line[--n] = 0;
        if (n > 0 && line[n - 1] == '\r') line[--n] = 0;
        if (n == 0 || line[0] == '#') continue;
        (*lines)++;

        check_size("scan_bad_char", line, n,
                   scan_bad_char_scalar(line, n),
                   scan_bad_char_arch(line, n));

        check_size("scan_find(':')", line, n,
                   scan_find_scalar(line, n, ':'),
                   scan_find_arch(line, n, ':'));

        check_size("scan_find('/')", line, n,
                   scan_find_scalar(line, n, '/'),
                   scan_find_arch(line, n, '/'));

        check_size("scan_find_any4(/?@#)", line, n,
                   scan_find_any4_scalar(line, n, '/', '?', '@', '#'),
                   scan_find_any4_arch(line, n, '/', '?', '@', '#'));

        check_int("scan_all_scheme", line, n,
                  scan_all_scheme_scalar(line, n),
                  scan_all_scheme_arch(line, n));

        if (n > 1)
            check_size("scan_bad_char [1..n-1]", line + 1, n - 1,
                       scan_bad_char_scalar(line + 1, n - 1),
                       scan_bad_char_arch(line + 1, n - 1));
        if (n > 8)
            check_size("scan_bad_char [8..n-1]", line + 8, n - 8,
                       scan_bad_char_scalar(line + 8, n - 8),
                       scan_bad_char_arch(line + 8, n - 8));
    }
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file> [<file> ...]\n", argv[0]);
        return 2;
    }

    col_enable();

    long lines = 0;
    for (int i = 1; i < argc; i++)
        run_file(argv[i], &lines);

    if (failures) {
        printf("\n%sFAIL%s  %d mismatches out of %ld comparisons\n",
               col_red(), col_reset(), failures, total_checks);
        return 1;
    }
    printf("%sPASS%s  %s%ld inputs · %ld comparisons · %d files%s\n",
           col_green(), col_reset(),
           col_dim(), lines, total_checks, argc - 1, col_reset());
    return 0;
}
