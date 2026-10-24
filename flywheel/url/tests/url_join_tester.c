/**
 * url_join_tester.c — RFC 3986 §5.4 reference resolution tests.
 *
 * Base URI: http://a/b/c/d;p?q
 *
 * Each row: (base_relative_path_we_vary, relative_ref, expected_result)
 * We test with a fixed base of "http://a/b/c/d;p?q" plus a few variations
 * that exercise scheme/fragment edge cases.
 *
 * Exit 0 if all pass, 1 if any fail.
 */

#include <stdio.h>
#include <string.h>
#include "url_parser.h"
#include "color.h"

static int pass = 0;
static int fail = 0;

static void test(const char *base_url, const char *rel, const char *expected) {
    url_view base;
    url_err e = url_parse(base_url, strlen(base_url), &base);
    if (e != URL_OK) {
        printf("  %sFAIL%s base parse: %s -> %s\n",
               col_red(), col_reset(), base_url, url_err_name(e));
        fail++;
        return;
    }

    char out[4096];
    size_t n = 0;
    e = url_join(&base, rel, strlen(rel), out, sizeof(out), &n);
    if (e != URL_OK) {
        printf("  %sFAIL%s %s + %s -> %s (expected %s)\n",
               col_red(), col_reset(), base_url, rel, url_err_name(e), expected);
        fail++;
        return;
    }
    out[n] = 0;

    if (strcmp(out, expected) == 0) {
        printf("  %sPASS%s  %s + %s  ->  %s\n",
               col_green(), col_reset(), base_url, rel, out);
        pass++;
    } else {
        printf("  %sFAIL%s  %s + %s\n", col_red(), col_reset(), base_url, rel);
        printf("        got      %s\n", out);
        printf("        expected %s\n", expected);
        fail++;
    }
}

int main(void) {
    col_enable();

    const char *base = "http://a/b/c/d;p?q";

    printf("%sRFC 3986 §5.4.1 — normal examples%s\n", col_bold(), col_reset());
    test(base, "g:h",       "g:h");
    test(base, "g",         "http://a/b/c/g");
    test(base, "./g",       "http://a/b/c/g");
    test(base, "g/",        "http://a/b/c/g/");
    test(base, "/g",        "http://a/g");
    test(base, "//g",       "http://g");
    test(base, "?y",        "http://a/b/c/d;p?y");
    test(base, "g?y",       "http://a/b/c/g?y");
    test(base, "#s",        "http://a/b/c/d;p?q#s");
    test(base, "g#s",       "http://a/b/c/g#s");
    test(base, "g?y#s",     "http://a/b/c/g?y#s");
    test(base, ";x",        "http://a/b/c/;x");
    test(base, "g;x",       "http://a/b/c/g;x");
    test(base, "g;x?y#s",   "http://a/b/c/g;x?y#s");
    test(base, "",          "http://a/b/c/d;p?q");
    test(base, ".",         "http://a/b/c/");
    test(base, "./",        "http://a/b/c/");
    test(base, "..",        "http://a/b/");
    test(base, "../",       "http://a/b/");
    test(base, "../g",      "http://a/b/g");
    test(base, "../..",     "http://a/");
    test(base, "../../",    "http://a/");
    test(base, "../../g",   "http://a/g");

    printf("\n%sRFC 3986 §5.4.2 — abnormal examples%s\n", col_bold(), col_reset());
    test(base, "../../../g",    "http://a/g");
    test(base, "../../../../g", "http://a/g");
    test(base, "/./g",          "http://a/g");
    test(base, "/../g",         "http://a/g");
    test(base, "g.",            "http://a/b/c/g.");
    test(base, ".g",            "http://a/b/c/.g");
    test(base, "g..",           "http://a/b/c/g..");
    test(base, "..g",           "http://a/b/c/..g");
    test(base, "./../g",        "http://a/b/g");
    test(base, "./g/.",         "http://a/b/c/g/");
    test(base, "g/./h",         "http://a/b/c/g/h");
    test(base, "g/../h",        "http://a/b/c/h");
    test(base, "g;x=1/./y",     "http://a/b/c/g;x=1/y");
    test(base, "g;x=1/../y",    "http://a/b/c/y");
    test(base, "g?y/./x",       "http://a/b/c/g?y/./x");
    test(base, "g?y/../x",      "http://a/b/c/g?y/../x");
    test(base, "g#s/./x",       "http://a/b/c/g#s/./x");
    test(base, "g#s/../x",      "http://a/b/c/g#s/../x");

    printf("\n%sExtra — fragment clearing, base with/without authority%s\n",
           col_bold(), col_reset());
    test("http://a/b#old",  "c",   "http://a/c");
    test("http://a/b#old",  "?q",  "http://a/b?q");
    test("http://a/b#old",  "/c",  "http://a/c");
    test("http://a/b#old",  "#new","http://a/b#new");

    printf("\n%s%s%d passed, %d failed%s\n",
           col_bold(), fail ? col_red() : col_green(),
           pass, fail, col_reset());

    return fail ? 1 : 0;
}
