/** dump_dom.c — parse an HTML file, run its inline scripts, dump the DOM.
 *  Prints BEFORE and AFTER so we can see JS mutations. */

#include "html.h"
#include "interp.h"
#include "dom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void indent(int n) { for (int i = 0; i < n; i++) fputs("  ", stdout); }

static void dump(const html_node_t *n, int depth) {
    if (!n) return;
    if (n->kind == HTML_NODE_ELEMENT) {
        indent(depth);
        printf("<%.*s", n->tag_len, n->tag);
        for (int i = 0; i < n->attr_count; i++) {
            if (n->attrs[i].has_value)
                printf(" %.*s=%.*s", n->attrs[i].name_len, n->attrs[i].name,
                       n->attrs[i].value_len, n->attrs[i].value);
            else
                printf(" %.*s", n->attrs[i].name_len, n->attrs[i].name);
        }
        printf(">\n");
    } else if (n->kind == HTML_NODE_TEXT) {
        indent(depth);
        printf("\"%.*s\"\n", n->text_len, n->text);
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        dump(c, depth + 1);
    if (n->kind == HTML_NODE_ELEMENT) {
        indent(depth);
        printf("</%.*s>\n", n->tag_len, n->tag);
    }
}

static const html_node_t *find_by_tag(const html_node_t *n, const char *tag) {
    if (!n) return NULL;
    if (n->kind == HTML_NODE_ELEMENT &&
        n->tag_len == (int)strlen(tag) &&
        strncmp(n->tag, tag, n->tag_len) == 0) return n;
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        const html_node_t *r = find_by_tag(c, tag);
        if (r) return r;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.html>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc((size_t)sz + 1);
    if (!src) return 1;
    fread(src, 1, (size_t)sz, f);
    src[sz] = 0;
    fclose(f);

    html_document_t *doc = html_parse(src, (size_t)sz);
    if (!doc) { fprintf(stderr, "html parse failed\n"); free(src); return 1; }

    printf("=== BEFORE scripts ===\n");
    dump(doc->root, 0);

    Interp *I = flywheel_new();
    if (!I) { fprintf(stderr, "interp alloc failed\n"); html_free(doc); free(src); return 1; }
    flywheel_load_natives(I);
    dom_js_install(I, doc);

    /* Find first <script> and run it (loop over siblings of same tag) */
    const html_node_t *s = find_by_tag(doc->root, "script");
    if (s) {
        char code[65536];
        int cl = html_text_content(s, code, sizeof(code));
        if (cl > 0) {
            FlyResult r = flywheel_eval(I, code, "<inline>");
            if (r.status != FLY_OK)
                fprintf(stderr, "script error: %s (line %d)\n",
                        r.error_msg, r.error_line);
        }
    }

    printf("\n=== AFTER scripts ===\n");
    dump(doc->root, 0);

    flywheel_free(I);
    html_free(doc);
    free(src);
    return 0;
}
