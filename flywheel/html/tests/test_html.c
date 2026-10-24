/** test_html.c — minimal HTML parse test. */

#include "../include/html.h"
#include <stdio.h>
#include <string.h>

static int passed = 0, failed = 0;

static void check(int cond, const char *msg) {
    if (cond) { passed++; printf("  PASS  %s\n", msg); }
    else      { failed++; printf("  FAIL  %s\n", msg); }
}

static const char *SRC =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>Test</title></head>\n"
    "<body>\n"
    "  <div class=\"x\" id=\"y\">\n"
    "    <p>Hello <b>world</b></p>\n"
    "    <img src=\"a.png\" alt=\"pic\">\n"
    "  </div>\n"
    "</body>\n"
    "</html>\n";

int main(void) {
    printf("=== HTML parser test ===\n");
    html_document_t *doc = html_parse(SRC, strlen(SRC));
    check(doc != NULL, "parse succeeds");
    if (!doc) return 1;

    check(doc->n_nodes > 5, "at least 5 nodes");
    printf("  node count: %d\n", doc->n_nodes);

    /* Find the div */
    const html_node_t *div = html_find_tag(doc->root, "div");
    check(div != NULL, "found <div>");
    if (div) {
        const char *cls = html_get_attr(div, "class");
        check(cls && cls[0] == 'x', "class attr = x");
        const char *id = html_get_attr(div, "id");
        check(id && id[0] == 'y', "id attr = y");
    }

    const html_node_t *p = html_find_tag(doc->root, "p");
    check(p != NULL, "found <p>");

    html_free(doc);

    printf("\n=== summary ===\n");
    printf("  passed: %d\n", passed);
    printf("  failed: %d\n", failed);
    return failed ? 1 : 0;
}
