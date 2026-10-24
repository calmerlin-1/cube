/** test_format.c — html_format() output shape.
 * Tests that block-level elements get indented and inline elements
 * stay inline within their block. Each case asserts on exact bytes. */
#include "../include/html.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int passed = 0, failed = 0;

static void fmt_to_buf(const char *src, char *out, size_t cap) {
    FILE *f = fmemopen(out, cap, "w");
    html_format(src, strlen(src), f);
    fclose(f);
}

static void check_fmt(const char *msg, const char *src, const char *want) {
    char got[4096];
    fmt_to_buf(src, got, sizeof(got));
    if (strcmp(got, want) == 0) {
        passed++;
        printf("  PASS  %s\n", msg);
    } else {
        failed++;
        printf("  FAIL  %s\n", msg);
        printf("        want: %s\n", want);
        printf("        got : %s\n", got);
    }
}

int main(void) {
    printf("=== html_format test ===\n");

    check_fmt("single block, plain text",
        "<p>hello</p>\n",
        "<p>hello</p>\n");

    check_fmt("inline <a> inside <p> stays inline",
        "<p>see <a href=\"x\">A</a> and <a href=\"y\">B</a>.</p>\n",
        "<p>see <a href=\"x\">A</a> and <a href=\"y\">B</a>.</p>\n");

    check_fmt("inline <b> inside <p>",
        "<p>hello <b>world</b></p>\n",
        "<p>hello <b>world</b></p>\n");

    check_fmt("two blocks, indented",
        "<div><p>a</p><p>b</p></div>\n",
        "<div>\n  <p>a</p>\n  <p>b</p>\n</div>\n");

    check_fmt("nested blocks with inline",
        "<div><p>see <a href=\"x\">A</a></p><p>plain</p></div>\n",
        "<div>\n  <p>see <a href=\"x\">A</a></p>\n  <p>plain</p>\n</div>\n");

    printf("\n=== summary ===\n");
    printf("  passed: %d\n", passed);
    printf("  failed: %d\n", failed);
    return failed ? 1 : 0;
}
