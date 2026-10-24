/** debug_script.c — see if we can find and extract the <script>. */

#include "html.h"
#include "interp.h"
#include "dom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void walk(const html_node_t *n, int depth) {
    if (!n) return;
    for (int i = 0; i < depth; i++) fputs("  ", stdout);
    if (n->kind == HTML_NODE_ELEMENT)
        printf("ELEM <%.*s> attrs=%d\n", n->tag_len, n->tag, n->attr_count);
    else if (n->kind == HTML_NODE_TEXT)
        printf("TEXT (%d bytes): '%.30s%s'\n",
               n->text_len, n->text, n->text_len > 30 ? "..." : "");
    else
        printf("KIND %d\n", n->kind);
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        walk(c, depth + 1);
}

static const html_node_t *find_tag(const html_node_t *n, const char *tag) {
    if (!n) return NULL;
    if (n->kind == HTML_NODE_ELEMENT &&
        n->tag_len == (int)strlen(tag) &&
        strncmp(n->tag, tag, n->tag_len) == 0) return n;
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        const html_node_t *r = find_tag(c, tag);
        if (r) return r;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc((size_t)sz + 1);
    fread(src, 1, (size_t)sz, f);
    src[sz] = 0;
    fclose(f);

    html_document_t *doc = html_parse(src, (size_t)sz);
    printf("=== full tree ===\n");
    walk(doc->root, 0);

    const html_node_t *s = find_tag(doc->root, "script");
    printf("\n=== script node ===\n");
    if (!s) { printf("NOT FOUND\n"); return 1; }

    printf("script node: kind=%d tag='%.*s' tag_len=%d attr_count=%d\n",
           s->kind, s->tag_len, s->tag, s->tag_len, s->attr_count);
    printf("script children:\n");
    for (const html_node_t *c = s->first_child; c; c = c->next_sibling)
        printf("  kind=%d text_len=%d text='%.30s%s'\n",
               c->kind, c->text_len, c->text, c->text_len > 30 ? "..." : "");

    char code[65536];
    int cl = html_text_content(s, code, sizeof(code));
    printf("html_text_content returned %d\n", cl);
    if (cl > 0) {
        printf("--- code ---\n");
        fwrite(code, 1, (size_t)cl, stdout);
        printf("\n--- end ---\n");
    }

    /* Now run it */
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    dom_js_install(I, doc);

    if (cl > 0) {
        printf("\n=== running script ===\n");
        FlyResult r = flywheel_eval(I, code, "<inline>");
        printf("status=%d line=%d msg='%s'\n",
               r.status, r.error_line, r.error_msg);
    }

    flywheel_free(I);
    html_free(doc);
    free(src);
    return 0;
}
