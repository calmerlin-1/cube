/** core.c — flywheel engine CLI.
 *  Dispatches HTML to the HTML, CSS, JS, URL engines.
 *  Single-file entry point. */

#include "html/include/html.h"
#include "js/include/interp.h"
#include "js/include/value.h"
#include "dom/include/dom.h"
#include "css/include/css.h"
#include "css/src/runtime/arena.h"
#include "html/src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- modes ---- */
typedef enum {
    MODE_HUMAN = 0,
    MODE_JSON,
    MODE_STATS,
    MODE_TEXT,
} core_mode_t;

/* ---- file I/O ---- */
static char *read_all(FILE *f, size_t *out_len) {
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    size_t got;
    while ((got = fread(buf + len, 1, cap - len, f)) > 0) {
        len += got;
        if (len == cap) {
            cap *= 2;
            char *big = realloc(buf, cap);
            if (!big) { free(buf); return NULL; }
            buf = big;
        }
    }
    buf[len] = 0;
    *out_len = len;
    return buf;
}

/* ---- traversal helpers ---- */
typedef struct {
    const html_node_t **items;
    int count, cap;
    css_arena_t *ar;
} nlist_t;

static void nlist_push(nlist_t *l, const html_node_t *n) {
    if (l->count >= l->cap) {
        int nc = l->cap ? l->cap * 2 : 16;
        const html_node_t **big = (const html_node_t **)
            css_arena_alloc(l->ar, sizeof(*big) * (size_t)nc);
        if (!big) return;
        if (l->items) memcpy(big, l->items, sizeof(*big) * (size_t)l->count);
        l->items = big;
        l->cap = nc;
    }
    l->items[l->count++] = n;
}

static int tag_eq(const char *tag, int tag_len, const char *lit) {
    int ll = (int)strlen(lit);
    if (tag_len != ll) return 0;
    for (int i = 0; i < ll; i++) {
        char a = tag[i], b = lit[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static void collect(const html_node_t *n, const char *tag, nlist_t *out) {
    if (!n) return;
    if (n->kind == HTML_NODE_ELEMENT && tag_eq(n->tag, n->tag_len, tag))
        nlist_push(out, n);
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        collect(c, tag, out);
}

static int direct_text(const html_node_t *n, const char **out, int *out_len) {
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        if (c->kind == HTML_NODE_TEXT) {
            *out = c->text;
            *out_len = c->text_len;
            return 1;
        }
    }
    *out = NULL;
    *out_len = 0;
    return 0;
}

/* ---- JSON string escape ---- */
static void json_str(const char *s, int n) {
    putchar('"');
    for (int i = 0; i < n; i++) {
        char c = s[i];
        switch (c) {
            case '"': fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if ((unsigned char)c < 0x20) printf("\\u%04x", (unsigned char)c);
                else putchar(c);
        }
    }
    putchar('"');
}

/* ---- main pipeline ---- */
int main(int argc, char **argv) {
    core_mode_t mode = MODE_HUMAN;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json"))        mode = MODE_JSON;
        else if (!strcmp(argv[i], "--stats"))  mode = MODE_STATS;
        else if (!strcmp(argv[i], "--text"))   mode = MODE_TEXT;
        else if (argv[i][0] != '-')            path = argv[i];
        else {
            fprintf(stderr, "usage: %s [--json|--stats|--text] [FILE|-]\n",
                    argv[0]);
            return 1;
        }
    }

    /* Read source — file or stdin */
    size_t src_len = 0;
    char *src = NULL;
    if (!path || !strcmp(path, "-")) {
        src = read_all(stdin, &src_len);
    } else {
        FILE *f = fopen(path, "rb");
        if (!f) { perror("core"); return 1; }
        src = read_all(f, &src_len);
        fclose(f);
    }
    if (!src) { fprintf(stderr, "core: read failed\n"); return 1; }
    if (!path) path = "<stdin>";

    /* ---- HTML parse ---- */
    uint64_t t0 = plat_now_ns();
    html_document_t *doc = html_parse(src, src_len);
    uint64_t html_ns = plat_now_ns() - t0;
    if (!doc) { fprintf(stderr, "core: html parse failed\n"); free(src); return 1; }

    /* ---- collect embedded content ---- */
    css_arena_t *ar = css_arena_pool_acquire();
    nlist_t styles  = {0}; styles.ar  = ar;
    nlist_t scripts = {0}; scripts.ar = ar;
    nlist_t links   = {0}; links.ar   = ar;

    collect(doc->root, "style",  &styles);
    collect(doc->root, "script", &scripts);
    collect(doc->root, "link",   &links);

    /* ---- CSS dispatch ---- */
    int css_rules = 0, css_blocks = 0;
    uint64_t css_ns = 0;
    for (int i = 0; i < styles.count; i++) {
        const char *body; int blen;
        if (!direct_text(styles.items[i], &body, &blen)) continue;
        uint64_t t = plat_now_ns();
        css_stylesheet_t *ss = css_parse(body, (size_t)blen);
        css_ns += plat_now_ns() - t;
        if (ss) {
            css_rules += ss->n_rules;
            css_blocks++;
            css_free(ss);
        }
    }

    /* ---- external CSS/JS URLs ---- */
    int css_ext = 0, js_inline = 0, js_ext = 0;
    for (int i = 0; i < links.count; i++) {
        const char *rel = html_get_attr(links.items[i], "rel");
        if (rel && (strcmp(rel, "stylesheet") == 0 ||
                    strcmp(rel, "STYLESHEET") == 0)) css_ext++;
    }
    for (int i = 0; i < scripts.count; i++) {
        if (html_get_attr(scripts.items[i], "src")) js_ext++;
        else js_inline++;
    }

    /* ---- Execute scripts through the DOM-aware interpreter ---- */
    int js_ok = 0, js_err = 0;
    char *code_buf = malloc(src_len + 1);
    Interp *I = flywheel_new();
    if (I) {
        flywheel_load_natives(I);
        dom_js_install(I, doc);

        for (int i = 0; i < scripts.count; i++) {
            const html_node_t *sn = scripts.items[i];
            const char *src_attr = html_get_attr(sn, "src");
            if (src_attr) {
                /* external script — skipped for now (no fetch) */
                continue;
            }
            /* inline script: extract its text */
            int cl = html_raw_text(sn, code_buf, src_len + 1);
            if (cl <= 0) continue;
            code_buf[cl] = '\0';
            const char *code = code_buf;

            FlyResult r = flywheel_eval(I, code, "<inline>");
            if (r.status == FLY_OK) {
                js_ok++;
            } else {
                js_err++;
                if (mode == MODE_HUMAN) {
                    fprintf(stderr,
                        "core: script error at %s:%d:%d: %s\n",
                        r.status == FLY_PARSE_ERROR ? "parse" : "runtime",
                        r.error_line, r.error_column,
                        r.error_msg[0] ? r.error_msg : "?");
                }
            }
        }
        flywheel_free(I);
    }
    free(code_buf);

    /* ---- text extraction ---- */
    size_t text_cap = src_len + 4096;
    char *text = malloc(text_cap);
    int text_len = 0;
    uint64_t text_ns = 0;
    if (text) {
        uint64_t t = plat_now_ns();
        text_len = html_text_content(doc->root, text, text_cap);
        text_ns = plat_now_ns() - t;
    }

    /* ---- output ---- */
    switch (mode) {
        case MODE_TEXT:
            if (text && text_len > 0) fwrite(text, 1, (size_t)text_len, stdout);
            break;

        case MODE_STATS:
            printf("%s: %zu bytes, %d nodes, %d css-blocks/%d rules, "
                   "%d css-links, %d js-inline, %d js-ext, %d text-bytes\n",
                   path, src_len, doc->n_nodes,
                   css_blocks, css_rules, css_ext,
                   js_inline, js_ext, text_len);
            break;

        case MODE_JSON:
            printf("{\n");
            printf("  \"file\": ");
            json_str(path, (int)strlen(path));
            printf(",\n");
            printf("  \"size\": %zu,\n", src_len);
            printf("  \"html\": {\"nodes\": %d, \"parse_ns\": %llu},\n",
                   doc->n_nodes, (unsigned long long)html_ns);
            printf("  \"css\": {\"blocks\": %d, \"rules\": %d, "
                   "\"external\": %d, \"parse_ns\": %llu},\n",
                   css_blocks, css_rules, css_ext,
                   (unsigned long long)css_ns);
            printf("  \"js\": {\"inline\": %d, \"external\": %d},\n",
                   js_inline, js_ext);
            printf("  \"text\": {\"bytes\": %d, \"extract_ns\": %llu}\n",
                   text_len, (unsigned long long)text_ns);
            printf("}\n");
            break;

        case MODE_HUMAN:
        default:
            printf("=== %s ===\n", path);
            printf("  size:         %zu bytes\n", src_len);
            printf("  HTML:         %d nodes  (%llu us)\n",
                   doc->n_nodes, (unsigned long long)(html_ns / 1000));
            printf("  CSS inline:   %d block(s) -> %d rules  (%llu us)\n",
                   css_blocks, css_rules,
                   (unsigned long long)(css_ns / 1000));
            printf("  CSS external: %d <link rel=stylesheet>\n", css_ext);
            printf("  JS inline:    %d <script>\n", js_inline);
            printf("  JS external:  %d <script src=...>\n", js_ext);
            printf("  Text:         %d bytes  (%llu us)\n",
                   text_len, (unsigned long long)(text_ns / 1000));
            break;
    }

    free(text);
    css_arena_pool_release(ar);
    html_free(doc);
    free(src);
    return 0;
}
