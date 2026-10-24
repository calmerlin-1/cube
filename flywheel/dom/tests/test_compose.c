/** test_compose.c — HTML → DOM → CSS composition test on a real page.
 * Reads example.com.html from flywheel/html/corpus, parses to DOM,
 * extracts <style> contents, parses CSS, applies via dom_apply_stylesheet,
 * then asserts computed style on <body>. */
#include "html.h"
#include "css.h"
#include "dom.h"
#include "dom_style.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;
#define CHECK(name, cond) do { \
    if (cond) { passed++; printf("  PASS  %s\n", name); } \
    else      { failed++; printf("  FAIL  %s\n", name); } \
} while (0)

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

int main(int argc, char **argv) {
    printf("=== composition test (HTML -> DOM -> CSS) ===\n");
    const char *path = (argc > 1) ? argv[1]
                                  : "../html/corpus/html/example.com.html";
    printf("  input: %s\n", path);

    size_t hlen = 0;
    char *html_src = read_file(path, &hlen);
    if (!html_src) { printf("  FATAL: cannot read %s\n", path); return 1; }

    html_document_t *doc = html_parse(html_src, hlen);
    CHECK("html_parse returns doc", doc != NULL);
    if (!doc) { free(html_src); return 1; }
    CHECK("doc has nodes", doc->n_nodes > 0);

    /* Find <style> and pull its text into a buffer. */
    const html_node_t *style = html_find_tag(doc->root, "style");
    CHECK("found <style>", style != NULL);

    char css_buf[8192] = {0};
    int css_len = 0;
    if (style) css_len = html_raw_text(style, css_buf, sizeof(css_buf));
    CHECK("style has content", css_len > 0);
    printf("  style content: %d bytes\n", css_len);

    css_stylesheet_t *ss = css_len > 0 ? css_parse(css_buf, (size_t)css_len) : NULL;
    CHECK("css_parse returns stylesheet", ss != NULL);
    if (ss) printf("  css rules: %d\n", ss->n_rules);

    int applied = dom_apply_stylesheet(doc, ss);
    CHECK("dom_apply_stylesheet returned > 0", applied > 0);
    printf("  elements styled: %d\n", applied);

    const html_node_t *body = dom_get_element_by_tag(doc->root, "body");
    CHECK("found <body>", body != NULL);

    if (body) {
        computed_style_t cs;
        int r = dom_compute_style(ss, (html_node_t *)body, &cs);
        CHECK("dom_compute_style(body) returns 0", r == 0);

        /* example.com CSS: body{font:16px/1.6 system-ui,sans-serif;...} */
        printf("  body font-size:   '%s'\n", cs.font_size);
        printf("  body font-family: '%s'\n", cs.font_family);
        printf("  body display:     '%s'\n", cs.display);
        printf("  body has_color:   %d\n", cs.has_color);
        printf("  body has_bg:      %d\n", cs.has_bg);

        CHECK("body is block (UA)", strcmp(cs.display, "block") == 0);
        CHECK("body font-size = 16px (author)", strcmp(cs.font_size, "16px") == 0);
        CHECK("body font-family mentions system-ui or sans-serif",
              strstr(cs.font_family, "system-ui") != NULL ||
              strstr(cs.font_family, "sans-serif") != NULL);
    }

    /* Query a paragraph and check it also gets computed styles. */
    const html_node_t *p = dom_query_selector(doc->root, "body p");
    CHECK("querySelector('body p') finds <p>", p != NULL);
    if (p) {
        computed_style_t pcs, pparent;
        int r = dom_compute_style_inherited(ss, (html_node_t *)p, &pcs, &pparent);
        CHECK("dom_compute_style_inherited(p) returns 0", r == 0);
        CHECK("p inherits body font-size", strcmp(pcs.font_size, "16px") == 0);
    /* example.com: body { padding: 25vh 2em 2em; margin: auto; } */
    if (body) {
        computed_style_t bcs;
        dom_compute_style(ss, (html_node_t *)body, &bcs);
        char pad_top[32] = "", pad_left[32] = "", mar_top[32] = "";
        for (int i = 0; i < bcs.n_decls; i++) {
            if (strcmp(bcs.decls[i].prop, "padding-top") == 0)
                snprintf(pad_top, sizeof pad_top, "%s", bcs.decls[i].value);
            if (strcmp(bcs.decls[i].prop, "padding-left") == 0)
                snprintf(pad_left, sizeof pad_left, "%s", bcs.decls[i].value);
            if (strcmp(bcs.decls[i].prop, "margin-top") == 0)
                snprintf(mar_top, sizeof mar_top, "%s", bcs.decls[i].value);
        }
        printf("  body padding-top: '%s'  padding-left: '%s'  margin-top: '%s'\n",
               pad_top, pad_left, mar_top);
        CHECK("body padding-top = 25vh (shorthand)", strcmp(pad_top, "25vh") == 0);
        CHECK("body padding-left = 2em (shorthand)", strcmp(pad_left, "2em") == 0);
        CHECK("body margin-top = auto (shorthand)",  strcmp(mar_top, "auto") == 0);
    }
    }


    /* Synthetic border shorthand test */
    {
        const char *bhtml = "<div id=\"b1\" style=\"border: 2px solid #ff00ff\">x</div>";
        html_document_t *bdoc = html_parse(bhtml, strlen(bhtml));
        const html_node_t *bnode = dom_get_element_by_id(bdoc->root, "b1");
        if (bnode) {
            computed_style_t bcs;
            dom_compute_style(NULL, (html_node_t *)bnode, &bcs);
            const char *bw = "", *bs = "", *bc = "";
            for (int i = 0; i < bcs.n_decls; i++) {
                if (strcmp(bcs.decls[i].prop, "border-top-width") == 0) bw = bcs.decls[i].value;
                if (strcmp(bcs.decls[i].prop, "border-top-style") == 0) bs = bcs.decls[i].value;
                if (strcmp(bcs.decls[i].prop, "border-top-color") == 0) bc = bcs.decls[i].value;
            }
            printf("  border-top: width='%s' style='%s' color='%s'\n", bw, bs, bc);
            CHECK("border-top-width = 2px (shorthand)",  strcmp(bw, "2px") == 0);
            CHECK("border-top-style = solid (shorthand)", strcmp(bs, "solid") == 0);
            CHECK("border-top-color = ff00ff (shorthand)", strcmp(bc, "#ff00ff") == 0);
        }
        html_free(bdoc);
    }


    /* Synthetic background + border-radius shorthand tests */
    {
        const char *bhtml =
            "<div id=\"bg1\" style=\"background: #1f1f23\">x</div>"
            "<div id=\"br1\" style=\"border-radius: .25rem\">y</div>"
            "<div id=\"br2\" style=\"border-radius: 4px 8px\">z</div>";
        html_document_t *bdoc = html_parse(bhtml, strlen(bhtml));
        const html_node_t *bg1 = dom_get_element_by_id(bdoc->root, "bg1");
        const html_node_t *br1 = dom_get_element_by_id(bdoc->root, "br1");
        const html_node_t *br2 = dom_get_element_by_id(bdoc->root, "br2");

        if (bg1) {
            computed_style_t bcs;
            dom_compute_style(NULL, (html_node_t *)bg1, &bcs);
            printf("  bg1: has_bg=%d bg_rgb=#%06x\n", bcs.has_bg, bcs.bg_rgb);
            CHECK("background: #1f1f23 -> has_bg", bcs.has_bg == 1);
            CHECK("background: #1f1f23 -> bg_rgb = 0x1f1f23",
                  bcs.bg_rgb == 0x1f1f23);
        }

        if (br1) {
            computed_style_t rcs;
            dom_compute_style(NULL, (html_node_t *)br1, &rcs);
            const char *tl = "";
            for (int i = 0; i < rcs.n_decls; i++)
                if (strcmp(rcs.decls[i].prop, "border-top-left-radius") == 0)
                    tl = rcs.decls[i].value;
            printf("  br1: border-top-left-radius='%s'\n", tl);
            CHECK("border-radius: .25rem -> tl=.25rem",
                  strcmp(tl, ".25rem") == 0);
        }

        if (br2) {
            computed_style_t rcs;
            dom_compute_style(NULL, (html_node_t *)br2, &rcs);
            const char *tl = "", *tr = "";
            for (int i = 0; i < rcs.n_decls; i++) {
                if (strcmp(rcs.decls[i].prop, "border-top-left-radius") == 0)
                    tl = rcs.decls[i].value;
                if (strcmp(rcs.decls[i].prop, "border-top-right-radius") == 0)
                    tr = rcs.decls[i].value;
            }
            printf("  br2: tl='%s' tr='%s'\n", tl, tr);
            CHECK("border-radius: 4px 8px -> tl=4px", strcmp(tl, "4px") == 0);
            CHECK("border-radius: 4px 8px -> tr=8px", strcmp(tr, "8px") == 0);
        }

        html_free(bdoc);
    }

    dom_style_shutdown();
    if (ss) css_free(ss);
    html_free(doc);
    free(html_src);

    printf("\n=== summary ===\n");
    printf("  passed: %d\n", passed);
    printf("  failed: %d\n", failed);
    return failed ? 1 : 0;
}
