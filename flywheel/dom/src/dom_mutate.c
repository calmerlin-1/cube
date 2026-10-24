/** dom_mutate.c — DOM mutation on top of html_node_t. */

#include "dom.h"
#include "html.h"
#include <string.h>
#include <stdlib.h>

/* The HTML tree is arena-allocated. We can allocate from the same
 * arena via the public document handle. The arena is opaque to us,
 * but html_arena_alloc is exported through html internals. */
extern void *html_arena_alloc(void *arena, size_t n);

/* Get the arena out of a document. */
static void *doc_arena(const html_document_t *doc) {
    return doc ? doc->arena : NULL;
}

/* ---- create ---- */

html_node_t *dom_create_element(html_document_t *doc, const char *tag) {
    if (!doc || !tag) return NULL;
    void *ar = doc_arena(doc);
    if (!ar) return NULL;

    html_node_t *n = html_arena_alloc(ar, sizeof(html_node_t));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->kind = HTML_NODE_ELEMENT;

    size_t tlen = strlen(tag);
    char *tcopy = html_arena_alloc(ar, tlen + 1);
    if (!tcopy) return NULL;
    memcpy(tcopy, tag, tlen + 1);
    n->tag = tcopy;
    n->tag_len = (int)tlen;

    doc->n_nodes++;
    return n;
}

html_node_t *dom_create_text(html_document_t *doc, const char *text) {
    if (!doc || !text) return NULL;
    void *ar = doc_arena(doc);
    if (!ar) return NULL;

    html_node_t *n = html_arena_alloc(ar, sizeof(html_node_t));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->kind = HTML_NODE_TEXT;

    size_t len = strlen(text);
    char *tcopy = html_arena_alloc(ar, len + 1);
    if (!tcopy) return NULL;
    memcpy(tcopy, text, len + 1);
    n->text = tcopy;
    n->text_len = (int)len;

    doc->n_nodes++;
    return n;
}

/* ---- tree ops ---- */

void dom_append_child(html_node_t *parent, html_node_t *child) {
    if (!parent || !child) return;
    if (child == parent) return;

    /* Detach from old parent */
    if (child->parent) dom_remove_child(child);

    child->parent = parent;
    child->next_sibling = NULL;

    if (!parent->first_child) {
        parent->first_child = child;
        parent->last_child = child;
    } else {
        parent->last_child->next_sibling = child;
        parent->last_child = child;
    }
}

void dom_insert_before(html_node_t *parent, html_node_t *child,
                        html_node_t *ref) {
    if (!parent || !child) return;
    if (!ref) { dom_append_child(parent, child); return; }
    if (child->parent) dom_remove_child(child);

    child->parent = parent;
    child->next_sibling = ref;

    if (parent->first_child == ref) {
        parent->first_child = child;
    } else {
        html_node_t *prev = parent->first_child;
        while (prev && prev->next_sibling != ref) prev = prev->next_sibling;
        if (prev) prev->next_sibling = child;
    }
}

static html_node_t *prev_or_null(html_node_t *parent, html_node_t *target);

void dom_remove_child(html_node_t *child) {
    if (!child || !child->parent) return;
    html_node_t *parent = child->parent;

    if (parent->first_child == child) {
        parent->first_child = child->next_sibling;
    } else {
        html_node_t *prev = parent->first_child;
        while (prev && prev->next_sibling != child) prev = prev->next_sibling;
        if (prev) prev->next_sibling = child->next_sibling;
    }
    if (parent->last_child == child) {
        parent->last_child = prev_or_null(parent, child);
    }
    child->parent = NULL;
    child->next_sibling = NULL;
}

/* Helper: find the node before `target` under `parent`, or NULL. */
static html_node_t *prev_or_null(html_node_t *parent, html_node_t *target) {
    if (!parent || !target) return NULL;
    html_node_t *cur = parent->first_child;
    html_node_t *last = NULL;
    while (cur) {
        if (cur == target) return last;
        last = cur;
        cur = cur->next_sibling;
    }
    return NULL;
}

/* ---- attributes ---- */

const char *dom_get_attribute(const html_node_t *node, const char *name) {
    if (!node || !name) return NULL;
    for (int i = 0; i < node->attr_count; i++) {
        if (node->attrs[i].name_len == (int)strlen(name) &&
            strncmp(node->attrs[i].name, name, node->attrs[i].name_len) == 0)
            return node->attrs[i].has_value ? node->attrs[i].value : "";
    }
    return NULL;
}

void dom_set_attribute(html_document_t *doc, html_node_t *node,
                       const char *name, const char *value) {
    if (!doc || !node || !name) return;
    void *ar = doc_arena(doc);
    if (!ar) return;

    size_t nlen = strlen(name);

    /* Find existing */
    for (int i = 0; i < node->attr_count; i++) {
        if (node->attrs[i].name_len == (int)nlen &&
            strncmp(node->attrs[i].name, name, nlen) == 0) {
            /* Update in place — allocate new value string */
            if (value) {
                size_t vlen = strlen(value);
                char *vc = html_arena_alloc(ar, vlen + 1);
                if (!vc) return;
                memcpy(vc, value, vlen + 1);
                node->attrs[i].value = vc;
                node->attrs[i].value_len = (int)vlen;
                node->attrs[i].has_value = 1;
            } else {
                node->attrs[i].value = NULL;
                node->attrs[i].value_len = 0;
                node->attrs[i].has_value = 0;
            }
            return;
        }
    }

    /* Grow attrs array. Original was allocated in the arena; we can't
     * realloc arena memory. Allocate a new array in the arena, copy. */
    int new_count = node->attr_count + 1;
    html_attr_t *new_attrs = html_arena_alloc(ar, sizeof(html_attr_t) * (size_t)new_count);
    if (!new_attrs) return;
    if (node->attrs && node->attr_count > 0)
        memcpy(new_attrs, node->attrs, sizeof(html_attr_t) * (size_t)node->attr_count);

    html_attr_t *a = &new_attrs[node->attr_count];
    memset(a, 0, sizeof(*a));
    char *nc = html_arena_alloc(ar, nlen + 1);
    if (!nc) return;
    memcpy(nc, name, nlen + 1);
    a->name = nc;
    a->name_len = (int)nlen;
    if (value) {
        size_t vlen = strlen(value);
        char *vc = html_arena_alloc(ar, vlen + 1);
        if (!vc) return;
        memcpy(vc, value, vlen + 1);
        a->value = vc;
        a->value_len = (int)vlen;
        a->has_value = 1;
    }

    node->attrs = new_attrs;
    node->attr_count = new_count;
}

void dom_remove_attribute(html_node_t *node, const char *name) {
    if (!node || !name) return;
    size_t nlen = strlen(name);
    for (int i = 0; i < node->attr_count; i++) {
        if (node->attrs[i].name_len == (int)nlen &&
            strncmp(node->attrs[i].name, name, nlen) == 0) {
            /* Shift down */
            for (int j = i; j < node->attr_count - 1; j++)
                node->attrs[j] = node->attrs[j + 1];
            node->attr_count--;
            return;
        }
    }
}

/* ---- text ---- */

void dom_set_text(html_document_t *doc, html_node_t *node, const char *text) {
    if (!doc || !node) return;
    /* Remove all children */
    html_node_t *c = node->first_child;
    while (c) {
        html_node_t *next = c->next_sibling;
        c->parent = NULL;
        c->next_sibling = NULL;
        c = next;
    }
    node->first_child = NULL;
    node->last_child = NULL;

    if (text) {
        html_node_t *tn = dom_create_text(doc, text);
        if (tn) dom_append_child(node, tn);
    }
}

/* ---- id shortcuts ---- */

void dom_set_id(html_document_t *doc, html_node_t *node, const char *id) {
    dom_set_attribute(doc, node, "id", id);
}

const char *dom_get_id(const html_node_t *node) {
    return dom_get_attribute(node, "id");
}
