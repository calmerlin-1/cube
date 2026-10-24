#include "html.h"
#include "css.h"
#include "dom.h"
#include "dom_style.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); fails++; } \
} while (0)

static void walk(html_node_t *root, html_node_t **out, int *n, int cap) {
    html_node_t *stack[256]; int top = 0;
    stack[top++] = root;
    while (top) {
        html_node_t *x = stack[--top];
        if (*n < cap) out[(*n)++] = x;
        html_node_t *kids[64]; int nk = 0;
        for (html_node_t *c = x->first_child; c && nk < 64; c = c->next_sibling)
            kids[nk++] = c;
        for (int i = nk - 1; i >= 0; i--) if (top < 256) stack[top++] = kids[i];
    }
}

int main(void) {
    const char *html_src =
        "<div class=\"a\" style=\"color: #00ff00\">"
        "  <span id=\"x\">hi</span>"
        "  <span class=\"a\">bye</span>"
        "</div>";
    const char *css_src =
        ".a { color: #ff0000; }"
        "#x { color: #0000ff; }"
        "span { color: #123456 !important; }";

    html_document_t *doc = html_parse(html_src, strlen(html_src));
    css_stylesheet_t *ss = css_parse(css_src, strlen(css_src));
    if (!doc || !ss) { printf("parse failed\n"); return 1; }

    html_node_t *nodes[64]; int nn = 0;
    walk(doc->root, nodes, &nn, 64);

    html_node_t *x = NULL, *sp_a = NULL, *div_a = NULL;
    for (int i = 0; i < nn; i++) {
        html_node_t *n = nodes[i];
        if (n->kind != HTML_NODE_ELEMENT) continue;
        const char *id  = html_get_attr(n, "id");
        const char *cls = html_get_attr(n, "class");
        if (id && strcmp(id, "x") == 0) x = n;
        if (cls && strcmp(cls, "a") == 0) {
            if (strncmp(n->tag, "span", 4) == 0) sp_a = n;
            else if (strncmp(n->tag, "div", 3) == 0) div_a = n;
        }
    }
    if (!x || !sp_a || !div_a) { printf("node lookup failed\n"); return 1; }

    computed_style_t cs;

    dom_compute_style(ss, div_a, &cs);
    CHECK("inline beats .a (#00ff00)", cs.has_color && cs.color_rgb == 0x00ff00);

    dom_compute_style(ss, x, &cs);
    CHECK("!important beats #id (#123456)", cs.has_color && cs.color_rgb == 0x123456);

    dom_compute_style(ss, sp_a, &cs);
    CHECK("span.a gets !important (#123456)", cs.has_color && cs.color_rgb == 0x123456);

    dom_compute_style(ss, div_a, &cs);
    CHECK("div display:block (UA)", strcmp(cs.display, "block") == 0);

    {
        const char *h2 = "<div style=\"color: #abcdef\"><span id=\"y\">hi</span></div>";
        html_document_t *d2 = html_parse(h2, strlen(h2));
        html_node_t *y = dom_get_element_by_id(d2->root, "y");
        computed_style_t child, parent;
        int r = dom_compute_style_inherited(NULL, y, &child, &parent);
        CHECK("child inherits #abcdef",
              r == 0 && child.has_color && child.color_rgb == 0xabcdef);
        html_free(d2);
    }

    dom_style_shutdown();
    css_free(ss);
    html_free(doc);

    printf("\n%s\n", fails ? "FAILED" : "ALL PASS");
    return fails ? 1 : 0;
}
