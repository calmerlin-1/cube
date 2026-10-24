/** verify_mutations.c — targeted verification of JS→DOM mutations. */

#include "html.h"
#include "interp.h"
#include "dom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const html_node_t *find_by_id(const html_node_t *n, const char *id) {
    if (!n) return NULL;
    if (n->kind == HTML_NODE_ELEMENT) {
        for (int i = 0; i < n->attr_count; i++) {
            if (n->attrs[i].name_len == 2 &&
                strncmp(n->attrs[i].name, "id", 2) == 0 &&
                n->attrs[i].has_value &&
                n->attrs[i].value_len == (int)strlen(id) &&
                strncmp(n->attrs[i].value, id, n->attrs[i].value_len) == 0)
                return n;
        }
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        const html_node_t *r = find_by_id(c, id);
        if (r) return r;
    }
    return NULL;
}

static int check(const char *label, int cond) {
    printf("  %-40s %s\n", label, cond ? "OK" : "FAIL");
    return cond;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <file.html>\n", argv[0]); return 1; }

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
    if (!doc) { fprintf(stderr, "parse failed\n"); return 1; }

    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    dom_js_install(I, doc);

    /* Find first script */
    const html_node_t *script = NULL;
    const html_node_t *stack[1024];
    int top = 0;
    stack[top++] = doc->root;
    while (top) {
        const html_node_t *n = stack[--top];
        if (n->kind == HTML_NODE_ELEMENT && n->tag_len == 6 &&
            strncmp(n->tag, "script", 6) == 0) { script = n; break; }
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
            if (top < 1024) stack[top++] = c;
    }

    if (script) {
        char code[65536];
        int cl = html_raw_text(script, code, sizeof(code));
        fprintf(stderr, "[verify] script found, html_raw_text returned %d\n", cl);
        if (cl > 0) {
            fprintf(stderr, "[verify] script source: '%.200s%s'\n",
                    code, cl > 200 ? "..." : "");
            FlyResult r = flywheel_eval(I, code, "<inline>");
            fprintf(stderr, "[verify] flywheel_eval status=%d line=%d msg='%s'\n",
                    r.status, r.error_line, r.error_msg);
        } else {
            fprintf(stderr, "[verify] html_text_content returned <= 0 — nothing to run\n");
        }
    } else {
        fprintf(stderr, "[verify] no <script> node found at all\n");
    }

    int ok = 1;
    printf("=== after script ===\n");

    /* Check #target got data-x=42 */
    const html_node_t *t = find_by_id(doc->root, "target");
    ok &= check("#target exists", t != NULL);
    if (t) {
        const char *dx = dom_get_attribute(t, "data-x");
        ok &= check("  data-x == '42'", dx && strcmp(dx, "42") == 0);

        /* Check #target's text is "mutated" */
        char text[256] = {0};
        html_text_content(t, text, sizeof(text));
        ok &= check("  text == 'mutated'", strcmp(text, "mutated") == 0);
    }

    /* Check #list got 2 li children */
    const html_node_t *ul = find_by_id(doc->root, "list");
    ok &= check("#list exists", ul != NULL);
    if (ul) {
        int li_count = 0;
        for (const html_node_t *c = ul->first_child; c; c = c->next_sibling)
            if (c->kind == HTML_NODE_ELEMENT && c->tag_len == 2 &&
                strncmp(c->tag, "li", 2) == 0) li_count++;
        printf("  #list children: %d <li> elements\n", li_count);
        ok &= check("  has 2 <li> children", li_count == 2);

        /* Check first li text */
        if (li_count == 2) {
            const html_node_t *li1 = ul->first_child;
            char t1[64] = {0};
            html_text_content(li1, t1, sizeof(t1));
            ok &= check("  first li text == 'first'", strcmp(t1, "first") == 0);
        }
    }

    printf("\n%s\n", ok ? "ALL MUTATIONS VERIFIED" : "SOME CHECKS FAILED");

    flywheel_free(I);
    html_free(doc);
    free(src);
    return ok ? 0 : 1;
}
