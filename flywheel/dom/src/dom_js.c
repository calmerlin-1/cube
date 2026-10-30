/* dom_js.c — DOM ↔ JS bridge.
 * document.createElement/getElementById/... + Element methods.
 * Session C addition: Element.style.*, Element.classList.*,
 * document.setStyleSheet, document.getComputedStyle.
 */

#include "dom.h"
#include "html.h"
#include "interp.h"
#include "object.h"
#include "value.h"
#include "css.h"
#include "css_types.h"
#include "dom_style.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static html_document_t *get_doc(Interp *I) {
    return (html_document_t *)I->host_data;
}

static Value wrap_node(Interp *I, html_node_t *node) {
    if (!node) return val_null();
    Object *o = object_new(I);
    if (!o) return val_undefined();
    o->fn_node = node;
    extern void dom_js_attach_element_methods(Interp *I, Object *o);
    dom_js_attach_element_methods(I, o);
    Value v = { .kind = VAL_OBJECT };
    v.as.object = o;
    return v;
}

static html_node_t *unwrap_node(Value v) {
    if (v.kind != VAL_OBJECT || !v.as.object) return NULL;
    Object *o = (Object *)v.as.object;
    return (html_node_t *)o->fn_node;
}

static const char *val_as_cstr(Value v) {
    if (v.kind == VAL_STRING && v.as.string) return v.as.string;
    if (v.kind == VAL_NUMBER) {
        static char buf[64];
        snprintf(buf, sizeof(buf), "%g", v.as.number);
        return buf;
    }
    return NULL;
}

/* ---- document.* ---- */

static Value js_doc_get_by_id(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *id = val_as_cstr(args[0]);
    if (!id) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc || !doc->root) return val_null();
    html_node_t *n = dom_get_element_by_id(doc->root, id);
    return wrap_node(I, n);
}

static Value js_doc_get_by_tag(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *tag = val_as_cstr(args[0]);
    if (!tag) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc || !doc->root) return val_null();
    html_node_t *n = dom_get_element_by_tag(doc->root, tag);
    return wrap_node(I, n);
}

static Value js_doc_get_by_class(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *cls = val_as_cstr(args[0]);
    if (!cls) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc || !doc->root) return val_null();
    html_node_t *nodes[256];
    int n = dom_get_elements_by_class(doc->root, cls, nodes, 256);
    Object *arr = array_new(I);
    if (!arr) return val_undefined();
    for (int i = 0; i < n; i++)
        array_push(I, arr, wrap_node(I, nodes[i]));
    Value v = { .kind = VAL_OBJECT }; v.as.object = arr;
    return v;
}

static Value js_doc_query(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *sel = val_as_cstr(args[0]);
    if (!sel) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc || !doc->root) return val_null();
    html_node_t *n = dom_query_selector(doc->root, sel);
    return wrap_node(I, n);
}

static Value js_doc_query_all(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *sel = val_as_cstr(args[0]);
    if (!sel) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc || !doc->root) return val_null();
    html_node_t *nodes[256];
    int n = dom_query_selector_all(doc->root, sel, nodes, 256);
    Object *arr = array_new(I);
    if (!arr) return val_undefined();
    for (int i = 0; i < n; i++)
        array_push(I, arr, wrap_node(I, nodes[i]));
    Value v = { .kind = VAL_OBJECT }; v.as.object = arr;
    return v;
}

static Value js_doc_create_element(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *tag = val_as_cstr(args[0]);
    if (!tag) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc) return val_null();
    html_node_t *n = dom_create_element(doc, tag);
    return wrap_node(I, n);
}

static Value js_doc_create_text(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    const char *s = val_as_cstr(args[0]);
    if (!s) return val_null();
    html_document_t *doc = get_doc(I);
    if (!doc) return val_null();
    html_node_t *n = dom_create_text(doc, s);
    return wrap_node(I, n);
}

/* ---- Element methods ---- */

static Value el_get_attr(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_null();
    const char *name = val_as_cstr(args[0]);
    if (!name) return val_null();
    const char *v = dom_get_attribute(n, name);
    return v ? val_string(v) : val_null();
}

static Value el_set_attr(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 2) return val_undefined();
    const char *name = val_as_cstr(args[0]);
    const char *value = val_as_cstr(args[1]);
    if (!name) return val_undefined();
    html_document_t *doc = get_doc(I);
    if (!doc) return val_undefined();
    dom_set_attribute(doc, n, name, value ? value : "");
    return val_undefined();
}

static Value el_remove_attr(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    const char *name = val_as_cstr(args[0]);
    if (!name) return val_undefined();
    dom_remove_attribute(n, name);
    return val_undefined();
}

static Value el_append_child(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    html_node_t *child = unwrap_node(args[0]);
    if (!child) return val_undefined();
    dom_append_child(n, child);
    return args[0];
}

static Value el_remove_child(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    html_node_t *child = unwrap_node(args[0]);
    if (!child) return val_undefined();
    /* dom_remove_child takes only the child; parent link is maintained. */
    dom_remove_child(child);
    return args[0];
}

static Value el_get_text(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)args; (void)argc;
    html_node_t *n = unwrap_node(this_val);
    if (!n) return val_string("");
    char buf[4096];
    int written = html_text_content(n, buf, sizeof(buf));
    if (written < 0) written = 0;
    return val_string(buf);
}

static Value el_set_text(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    const char *s = val_as_cstr(args[0]);
    if (!s) s = "";
    html_document_t *doc = get_doc(I);
    if (!doc) return val_undefined();
    dom_set_text(doc, n, s);
    return val_undefined();
}

static Value el_set_id_prop(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    const char *s = argc > 0 ? val_as_cstr(args[0]) : NULL;
    if (n && s) dom_set_id(get_doc(I), n, s);
    return argc > 0 ? args[0] : val_undefined();
}

static Value el_get_class_prop(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)args; (void)argc;
    html_node_t *n = unwrap_node(this_val);
    const char *s = n ? dom_get_attribute(n, "class") : NULL;
    return val_string(s ? s : "");
}

static Value el_set_class_prop(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    const char *s = argc > 0 ? val_as_cstr(args[0]) : NULL;
    if (n) dom_set_attribute(get_doc(I), n, "class", s ? s : "");
    return argc > 0 ? args[0] : val_undefined();
}

static Value el_get_value_prop(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)args; (void)argc;
    html_node_t *n = unwrap_node(this_val);
    const char *s = n ? dom_get_attribute(n, "value") : NULL;
    return val_string(s ? s : "");
}

static Value el_set_value_prop(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    const char *s = argc > 0 ? val_as_cstr(args[0]) : NULL;
    if (n) dom_set_attribute(get_doc(I), n, "value", s ? s : "");
    return argc > 0 ? args[0] : val_undefined();
}

static Value el_tag_name(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)args; (void)argc;
    html_node_t *n = unwrap_node(this_val);
    if (!n || !n->tag) return val_string("");
    char buf[64];
    int len = n->tag_len < 63 ? n->tag_len : 63;
    for (int i = 0; i < len; i++) {
        char c = n->tag[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        buf[i] = c;
    }
    buf[len] = 0;
    return val_string(buf);
}

static Value el_get_id(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)args; (void)argc;
    html_node_t *n = unwrap_node(this_val);
    if (!n) return val_string("");
    const char *id = dom_get_id(n);
    return val_string(id ? id : "");
}

/* ---- Element.style.* ---- */

static int style_attr_lookup(html_node_t *n, const char *prop,
                             char *out, int cap) {
    const char *style = dom_get_attribute(n, "style");
    if (!style) return 0;
    int plen = (int)strlen(prop);
    const char *p = style;
    while (*p) {
        while (*p == ';' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ';') end++;
        const char *colon = p;
        while (colon < end && *colon != ':') colon++;
        if (colon < end) {
            const char *ps = p, *pe = colon;
            while (pe > ps && (pe[-1] == ' ' || pe[-1] == '\t')) pe--;
            if ((int)(pe - ps) == plen && strncmp(ps, prop, (size_t)plen) == 0) {
                const char *vs = colon + 1, *ve = end;
                while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
                while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                int vl = (int)(ve - vs);
                if (vl > cap - 1) vl = cap - 1;
                memcpy(out, vs, (size_t)vl); out[vl] = 0;
                return 1;
            }
        }
        p = end;
    }
    return 0;
}

static void style_attr_set(Interp *I, html_node_t *n, const char *prop, const char *value) {
    const char *style = dom_get_attribute(n, "style");
    char buf[1024]; int bl = 0; buf[0] = 0;
    int plen = (int)strlen(prop);
    if (style && *style) {
        const char *p = style;
        while (*p) {
            while (*p == ';' || *p == ' ' || *p == '\t') p++;
            if (!*p) break;
            const char *end = p;
            while (*end && *end != ';') end++;
            const char *colon = p;
            while (colon < end && *colon != ':') colon++;
            if (colon < end) {
                const char *ps = p, *pe = colon;
                while (pe > ps && (pe[-1] == ' ' || pe[-1] == '\t')) pe--;
                if (!((int)(pe - ps) == plen && strncmp(ps, prop, (size_t)plen) == 0)) {
                    int seg = (int)(end - ps);
                    if (bl + seg + 2 < (int)sizeof(buf)) {
                        if (bl > 0) buf[bl++] = ';';
                        memcpy(buf + bl, ps, (size_t)seg); bl += seg;
                        buf[bl] = 0;
                    }
                }
            }
            p = end;
        }
    }
    if (value && *value) {
        if (bl > 0 && bl + 1 < (int)sizeof(buf)) buf[bl++] = ';';
        int w = snprintf(buf + bl, sizeof(buf) - (size_t)bl, "%s:%s", prop, value);
        if (w > 0) bl += w;
    }
    html_document_t *doc = get_doc(I);
    if (!doc) return;
    if (bl == 0) dom_remove_attribute(n, "style");
    else dom_set_attribute(doc, n, "style", buf);
}

static Value el_style_get(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_string("");
    const char *prop = val_as_cstr(args[0]);
    if (!prop) return val_string("");
    char buf[256];
    if (style_attr_lookup(n, prop, buf, sizeof(buf))) return val_string(buf);
    return val_string("");
}

static Value el_style_set(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 2) return val_undefined();
    const char *prop = val_as_cstr(args[0]);
    const char *value = val_as_cstr(args[1]);
    if (!prop) return val_undefined();
    style_attr_set(I, n, prop, value ? value : "");
    return val_undefined();
}

/* ---- Element.classList.* ---- */

static int class_has_token(const char *attr, const char *tok) {
    if (!attr || !tok) return 0;
    int tl = (int)strlen(tok);
    const char *p = attr;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if ((int)(p - s) == tl && strncmp(s, tok, (size_t)tl) == 0) return 1;
    }
    return 0;
}

static Value el_class_contains(Interp *I, Value this_val, Value *args, int argc) {
    (void)I;
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_bool(0);
    const char *tok = val_as_cstr(args[0]);
    if (!tok) return val_bool(0);
    return val_bool(class_has_token(dom_get_attribute(n, "class"), tok));
}

static Value el_class_add(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    const char *tok = val_as_cstr(args[0]);
    if (!tok || !*tok) return val_undefined();
    const char *cur = dom_get_attribute(n, "class");
    if (class_has_token(cur, tok)) return val_undefined();
    char buf[1024];
    if (cur && *cur) snprintf(buf, sizeof(buf), "%s %s", cur, tok);
    else snprintf(buf, sizeof(buf), "%s", tok);
    html_document_t *doc = get_doc(I);
    if (doc) dom_set_attribute(doc, n, "class", buf);
    return val_undefined();
}

static Value el_class_remove(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_undefined();
    const char *tok = val_as_cstr(args[0]);
    if (!tok) return val_undefined();
    const char *cur = dom_get_attribute(n, "class");
    if (!cur) return val_undefined();
    int tl = (int)strlen(tok);
    char buf[1024]; int bl = 0; buf[0] = 0;
    const char *p = cur;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        int seg = (int)(p - s);
        if (seg > 0 && !(seg == tl && strncmp(s, tok, (size_t)tl) == 0)) {
            if (bl + seg + 2 < (int)sizeof(buf)) {
                if (bl > 0) buf[bl++] = ' ';
                memcpy(buf + bl, s, (size_t)seg); bl += seg; buf[bl] = 0;
            }
        }
    }
    html_document_t *doc = get_doc(I);
    if (!doc) return val_undefined();
    if (bl == 0) dom_remove_attribute(n, "class");
    else dom_set_attribute(doc, n, "class", buf);
    return val_undefined();
}

static Value el_class_toggle(Interp *I, Value this_val, Value *args, int argc) {
    html_node_t *n = unwrap_node(this_val);
    if (!n || argc < 1) return val_bool(0);
    const char *tok = val_as_cstr(args[0]);
    if (!tok) return val_bool(0);
    if (class_has_token(dom_get_attribute(n, "class"), tok)) {
        Value a[1] = { args[0] };
        el_class_remove(I, this_val, a, 1);
        return val_bool(0);
    } else {
        Value a[1] = { args[0] };
        el_class_add(I, this_val, a, 1);
        return val_bool(1);
    }
}

/* ---- document.setStyleSheet / getComputedStyle ---- */

static css_stylesheet_t *g_stylesheet = NULL;

static Value js_doc_set_stylesheet(Interp *I, Value this_val, Value *args, int argc) {
    (void)I; (void)this_val; (void)args; (void)argc;
    return val_undefined();
}

static Value js_doc_get_computed_style(Interp *I, Value this_val, Value *args, int argc) {
    (void)this_val;
    if (argc < 1) return val_null();
    html_node_t *n = unwrap_node(args[0]);
    if (!n) return val_null();
    computed_style_t cs;
    if (dom_compute_style_inherited(g_stylesheet, n, &cs, NULL) != 0)
        return val_null();
    Object *o = object_new(I);
    if (!o) return val_null();
    char buf[32];
    if (cs.has_color) {
        snprintf(buf, sizeof(buf), "#%06x", cs.color_rgb);
        object_set(I, o, "color", val_string(buf));
    }
    if (cs.has_bg) {
        snprintf(buf, sizeof(buf), "#%06x", cs.bg_rgb);
        object_set(I, o, "backgroundColor", val_string(buf));
    }
    object_set(I, o, "display",
               val_string(cs.display[0] ? cs.display : "inline"));
    if (cs.font_size[0]) object_set(I, o, "fontSize", val_string(cs.font_size));
    if (cs.font_weight[0]) object_set(I, o, "fontWeight", val_string(cs.font_weight));
    if (cs.font_family[0]) object_set(I, o, "fontFamily", val_string(cs.font_family));
    if (cs.line_height[0]) object_set(I, o, "lineHeight", val_string(cs.line_height));
    Value v = { .kind = VAL_OBJECT }; v.as.object = o;
    return v;
}

/* ---- Registration ---- */

void dom_js_attach_element_methods(Interp *I, Object *o) {
    if (!I || !o) return;
    object_set_native(I, o, "getAttribute",     el_get_attr);
    object_set_native(I, o, "setAttribute",     el_set_attr);
    object_set_native(I, o, "removeAttribute",  el_remove_attr);
    object_set_native(I, o, "appendChild",      el_append_child);
    object_set_native(I, o, "removeChild",      el_remove_child);
    object_set_native(I, o, "getTextContent",   el_get_text);
    object_set_native(I, o, "setTextContent",   el_set_text);
    object_set_native(I, o, "getTagName",       el_tag_name);
    object_set_native(I, o, "getId",            el_get_id);

    /* Session C additions */
    object_set_native(I, o, "styleGet",         el_style_get);
    object_set_native(I, o, "styleSet",         el_style_set);
    object_set_native(I, o, "classContains",    el_class_contains);
    object_set_native(I, o, "classAdd",         el_class_add);
    object_set_native(I, o, "classRemove",      el_class_remove);
    object_set_native(I, o, "classToggle",      el_class_toggle);

    Value tv = { .kind = VAL_OBJECT };
    tv.as.object = o;
    object_set(I, o, "tagName",     el_tag_name(I, tv, NULL, 0));
    object_set(I, o, "id",          el_get_id(I, tv, NULL, 0));
    object_set(I, o, "textContent", el_get_text(I, tv, NULL, 0));

    /* Live properties: reads and writes go through the DOM. */
    object_set_getter(I, o, "textContent", el_get_text);
    object_set_setter(I, o, "textContent", el_set_text);
    object_set_getter(I, o, "id",          el_get_id);
    object_set_setter(I, o, "id",          el_set_id_prop);
    object_set_getter(I, o, "className",   el_get_class_prop);
    object_set_setter(I, o, "className",   el_set_class_prop);
    object_set_getter(I, o, "value",       el_get_value_prop);
    object_set_setter(I, o, "value",       el_set_value_prop);
}

void dom_js_install(Interp *I, html_document_t *doc) {
    if (!I) return;
    I->has_error = 0;
    I->last_status = FLY_OK;
    I->last_error[0] = '\0';
    I->ctl = CTL_NONE;
    I->host_data = doc;

    Object *d = object_new(I);
    if (!d) return;

    object_set_native(I, d, "getElementById",       js_doc_get_by_id);
    object_set_native(I, d, "getElementsByTagName", js_doc_get_by_tag);
    object_set_native(I, d, "getElementsByClassName", js_doc_get_by_class);
    object_set_native(I, d, "querySelector",        js_doc_query);
    object_set_native(I, d, "querySelectorAll",     js_doc_query_all);
    object_set_native(I, d, "createElement",        js_doc_create_element);
    object_set_native(I, d, "createTextNode",       js_doc_create_text);
    object_set_native(I, d, "setStyleSheet",        js_doc_set_stylesheet);
    object_set_native(I, d, "getComputedStyle",     js_doc_get_computed_style);

    if (doc && doc->root) {
        html_node_t *de = doc->root;
        for (html_node_t *c = doc->root->first_child; c; c = c->next_sibling)
            if (c->kind == HTML_NODE_ELEMENT) { de = c; break; }
        Value root = wrap_node(I, de);
        object_set(I, d, "documentElement", root);
    }

    Value dv = { .kind = VAL_OBJECT };
    dv.as.object = d;

    extern void env_define(Interp *I, Env *e, const char *name,
                           Value v, int is_mutable);
    env_define(I, I->globals, "document", dv, 1);
}

void dom_js_set_stylesheet(struct Interp *I, const css_stylesheet_t *ss) {
    (void)I;
    g_stylesheet = (css_stylesheet_t *)ss;
}
