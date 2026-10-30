/** browser_native.c — native page pipeline: HTML -> DOM -> CSS -> JS -> text. */

#include "browser_native.h"
#include "html.h"
#include "html_types.h"
#include "css.h"
#include "dom.h"
#include "dom_style.h"
#include "interp.h"
#include "value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char  *p;
    size_t len, cap;
    int    oom;
} buf_t;

static void b_reserve(buf_t *b, size_t extra) {
    if (b->oom) return;
    if (b->len + extra + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra + 1) cap *= 2;
    char *np = (char *)realloc(b->p, cap);
    if (!np) { b->oom = 1; return; }
    b->p = np; b->cap = cap;
}

static void b_put(buf_t *b, const char *s, size_t n) {
    b_reserve(b, n);
    if (b->oom) return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void b_puts(buf_t *b, const char *s) { b_put(b, s, strlen(s)); }

static void b_escape(buf_t *b, const char *s, size_t n, int attr) {
    for (size_t i = 0; i < n; i++) {
        switch (s[i]) {
        case '&': b_puts(b, "&amp;"); break;
        case '<': b_puts(b, "&lt;"); break;
        case '>': b_puts(b, "&gt;"); break;
        case '"': if (attr) b_puts(b, "&quot;"); else b_put(b, &s[i], 1); break;
        default:  b_put(b, &s[i], 1); break;
        }
    }
}

static int tag_eq(const html_node_t *n, const char *tag) {
    size_t tl = strlen(tag);
    if (!n->tag || (size_t)n->tag_len != tl) return 0;
    for (size_t i = 0; i < tl; i++)
        if (tolower((unsigned char)n->tag[i]) != (unsigned char)tag[i]) return 0;
    return 1;
}

static int is_void_tag(const char *t, int n) {
    static const char *voids[] = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr", NULL
    };
    for (int i = 0; voids[i]; i++) {
        size_t vl = strlen(voids[i]);
        if ((size_t)n != vl) continue;
        int same = 1;
        for (size_t j = 0; j < vl; j++)
            if (tolower((unsigned char)t[j]) != voids[i][j]) { same = 0; break; }
        if (same) return 1;
    }
    return 0;
}

static void serialize(buf_t *b, const html_node_t *n, int root) {
    if (!n) return;
    switch (n->kind) {
    case HTML_NODE_ROOT:
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
            serialize(b, c, 0);
        break;
    case HTML_NODE_ELEMENT: {
        if (root) { for (const html_node_t *c = n->first_child; c; c = c->next_sibling) serialize(b, c, 0); break; }
        b_puts(b, "<");
        b_put(b, n->tag, (size_t)n->tag_len);
        for (int i = 0; i < n->attr_count; i++) {
            b_puts(b, " ");
            b_put(b, n->attrs[i].name, (size_t)n->attrs[i].name_len);
            if (n->attrs[i].has_value) {
                b_puts(b, "=\"");
                b_escape(b, n->attrs[i].value ? n->attrs[i].value : "",
                         (size_t)n->attrs[i].value_len, 1);
                b_puts(b, "\"");
            }
        }
        b_puts(b, ">");
        if (is_void_tag(n->tag, n->tag_len)) break;
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
            serialize(b, c, 0);
        b_puts(b, "</");
        b_put(b, n->tag, (size_t)n->tag_len);
        b_puts(b, ">");
        break;
    }
    case HTML_NODE_TEXT:
        b_escape(b, n->text ? n->text : "", (size_t)n->text_len, 0);
        break;
    case HTML_NODE_COMMENT:
        b_puts(b, "<!--");
        b_put(b, n->text ? n->text : "", (size_t)n->text_len);
        b_puts(b, "-->");
        break;
    case HTML_NODE_DOCTYPE:
        b_puts(b, "<!DOCTYPE");
        if (n->text_len) { b_puts(b, " "); b_put(b, n->text, (size_t)n->text_len); }
        b_puts(b, ">");
        break;
    }
}

static void collect_text(const html_node_t *n, buf_t *b) {
    if (!n) return;
    if (n->kind == HTML_NODE_TEXT) {
        b_put(b, n->text ? n->text : "", (size_t)n->text_len);
        return;
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        collect_text(c, b);
}

static void collect_styles(const html_node_t *n, buf_t *css) {
    if (!n) return;
    if (n->kind == HTML_NODE_ELEMENT && tag_eq(n, "style")) {
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
            if (c->kind == HTML_NODE_TEXT && c->text)
                b_put(css, c->text, (size_t)c->text_len);
        b_puts(css, "\n");
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        collect_styles(c, css);
}

static int script_is_js(const html_node_t *n) {
    for (int i = 0; i < n->attr_count; i++) {
        if (n->attrs[i].name_len != 4) continue;
        if (strncasecmp(n->attrs[i].name, "type", 4) != 0) continue;
        if (!n->attrs[i].has_value || !n->attrs[i].value) return 1;
        const char *v = n->attrs[i].value;
        int vl = n->attrs[i].value_len;
        if (vl == 0) return 1;
        if (strstr(v, "javascript") || strstr(v, "ecmascript") || strstr(v, "module"))
            return 1;
        return 0;
    }
    return 1;
}

static int script_has_src(const html_node_t *n) {
    for (int i = 0; i < n->attr_count; i++)
        if (n->attrs[i].name_len == 3 &&
            strncasecmp(n->attrs[i].name, "src", 3) == 0)
            return 1;
    return 0;
}

static void run_scripts(const html_node_t *n, Interp *I,
                        buf_t *logger, char *err, size_t cap, int *failed) {
    if (!n) return;
    if (n->kind == HTML_NODE_ELEMENT && tag_eq(n, "script") &&
        script_is_js(n) && !script_has_src(n)) {
        buf_t src = { 0 };
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
            if (c->kind == HTML_NODE_TEXT && c->text)
                b_put(&src, c->text, (size_t)c->text_len);
        if (src.len) {
            FlyResult r = flywheel_eval(I, src.p ? src.p : "", "<inline>");
            if (r.status != FLY_OK) {
                if (err && cap && !*failed)
                    snprintf(err, cap, "script error: %s",
                             r.error_msg[0] ? r.error_msg : "unknown");
                *failed = 1;
            }
            (void)logger;
        }
        free(src.p);
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        run_scripts(c, I, logger, err, cap, failed);
}

static void value_to_text(const Value *v, buf_t *b) {
    char tmp[64];
    switch (v->kind) {
    case VAL_STRING:    b_puts(b, v->as.string ? v->as.string : ""); break;
    case VAL_NUMBER:    snprintf(tmp, sizeof tmp, "%g", v->as.number); b_puts(b, tmp); break;
    case VAL_BOOL:      b_puts(b, v->as.boolean ? "true" : "false"); break;
    case VAL_NULL:      b_puts(b, "null"); break;
    case VAL_UNDEFINED: b_puts(b, "undefined"); break;
    default:            b_puts(b, "[object]"); break;
    }
}

int browser_native_run(const char *html, size_t len,
                       const browser_native_opts_t *opts,
                       char **out, size_t *out_len,
                       char *err, size_t err_cap) {
    if (!html || !out || !out_len) {
        if (err && err_cap) snprintf(err, err_cap, "native browser: bad args");
        return -1;
    }
    *out = NULL; *out_len = 0;
    if (err && err_cap) err[0] = 0;

    /* Non-markup bodies pass straight through. */
    if (!memchr(html, '<', len)) {
        char *copy = (char *)malloc(len + 1);
        if (!copy) return -1;
        memcpy(copy, html, len);
        copy[len] = 0;
        *out = copy; *out_len = len;
        return 0;
    }

    html_document_t *doc = html_parse(html, len);
    if (!doc) {
        if (err && err_cap) snprintf(err, err_cap, "native browser: HTML parse failed");
        return -1;
    }

    buf_t css_src = { 0 };
    collect_styles(doc->root, &css_src);
    css_stylesheet_t *ss = css_src.len ? css_parse(css_src.p, css_src.len) : NULL;
    if (ss) dom_apply_stylesheet(doc, ss);

    Interp *I = flywheel_new();
    if (I) {
        flywheel_load_natives(I);
        dom_js_install(I, doc);
        if (ss) dom_js_set_stylesheet(I, ss);
        int failed = 0;
        run_scripts(doc->root, I, NULL, err, err_cap, &failed);
    }

    buf_t result = { 0 };
    if (opts && opts->eval && I) {
        FlyResult r = flywheel_eval(I, opts->eval, "<eval>");
        if (r.status == FLY_OK) value_to_text(&r.value, &result);
        else if (err && err_cap && !err[0])
            snprintf(err, err_cap, "eval error: %s",
                     r.error_msg[0] ? r.error_msg : "unknown");
    } else if (opts && opts->query) {
        html_node_t *n = dom_query_selector(doc->root, opts->query);
        if (n) collect_text(n, &result);
        else if (err && err_cap)
            snprintf(err, err_cap, "query matched nothing: %s", opts->query);
    } else {
        serialize(&result, doc->root, 1);
    }

    if (I) flywheel_free(I);
    if (ss) css_free(ss);
    free(css_src.p);
    html_free(doc);

    if (result.oom) {
        free(result.p);
        if (err && err_cap) snprintf(err, err_cap, "native browser: out of memory");
        return -1;
    }
    if (!result.p) {
        result.p = (char *)malloc(1);
        if (!result.p) return -1;
        result.p[0] = 0;
        result.len = 0;
    }
    *out = result.p;
    *out_len = result.len;
    return 0;
}
