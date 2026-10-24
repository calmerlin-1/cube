/** dom_query.c — DOM query + CSS selector matching against html_node_t.
 *
 * Parses a selector with css_parse_selector, then walks the HTML tree
 * checking matches. Supports:
 *   - tag, .class, #id, [attr], [attr=val]
 *   - compound (tag.class#id[attr=val])
 *   - descendant (space), child (>)
 *   - :not(...) pseudo-class
 *
 * Pseudo-classes like :hover, :focus are treated as always-false (they
 * depend on user interaction).
 */

#include "dom.h"
#include "css.h"
#include "css_types.h"
#include <string.h>
#include <ctype.h>

/* ---- node matching (single compound selector) ---- */

/* Compare a length-bounded slice `a[0..alen)` against `b[0..blen)` exactly.
 * Neither side is assumed NUL-terminated. Used to compare selector name
 * slices (arena-backed, not NUL-terminated) against node fields. */
static int str_eq_n(const char *a, int alen, const char *b, int blen) {
    if (!a || !b) return 0;
    if (alen != blen) return 0;
    return strncmp(a, b, (size_t)alen) == 0;
}

/* Case-insensitive, length-bounded. */
static int str_eq_n_case(const char *a, int alen, const char *b, int blen) {
    if (!a || !b) return 0;
    if (alen != blen) return 0;
    for (int i = 0; i < alen; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return 1;
}

/* Does the class attribute contain `cls` as a whitespace-separated token? */
static int has_class(const html_node_t *node, const char *cls, int cls_len) {
    const char *attr = dom_get_attribute(node, "class");
    if (!attr) return 0;
    const char *p = attr;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        int tok_len = (int)(p - start);
        if (tok_len == cls_len && strncmp(start, cls, cls_len) == 0) return 1;
    }
    return 0;
}

/* Attribute value matching per CSS operators. */
static int attr_matches(const html_node_t *node, const css_selector_part_t *p) {
    /* Get attribute value */
    char name[128];
    int nl = p->name_len < 127 ? p->name_len : 127;
    memcpy(name, p->name, (size_t)nl);
    name[nl] = 0;

    const char *val = dom_get_attribute(node, name);

    /* Attribute presence check: no operator */
    if (p->attr_op_len == 0 && p->attr_value_len == 0) {
        return val != NULL;
    }
    if (!val) return 0;

    size_t vlen = strlen(val);
    if (p->attr_op_len == 1 && p->attr_op[0] == '=') {
        return vlen == (size_t)p->attr_value_len &&
               strncmp(val, p->attr_value, vlen) == 0;
    }
    if (p->attr_op_len == 2) {
        if (p->attr_op[0] == '^' && p->attr_op[1] == '=') {
            return vlen >= (size_t)p->attr_value_len &&
                   strncmp(val, p->attr_value, (size_t)p->attr_value_len) == 0;
        }
        if (p->attr_op[0] == '$' && p->attr_op[1] == '=') {
            return vlen >= (size_t)p->attr_value_len &&
                   strncmp(val + vlen - (size_t)p->attr_value_len,
                           p->attr_value, (size_t)p->attr_value_len) == 0;
        }
        if (p->attr_op[0] == '*' && p->attr_op[1] == '=') {
            if (p->attr_value_len == 0) return 1;
            for (size_t i = 0; i + (size_t)p->attr_value_len <= vlen; i++) {
                if (strncmp(val + i, p->attr_value, (size_t)p->attr_value_len) == 0)
                    return 1;
            }
            return 0;
        }
        if (p->attr_op[0] == '~' && p->attr_op[1] == '=') {
            /* whitespace-separated word match */
            const char *q = val;
            while (*q) {
                while (*q == ' ' || *q == '\t') q++;
                const char *st = q;
                while (*q && *q != ' ' && *q != '\t') q++;
                int tl = (int)(q - st);
                if (tl == p->attr_value_len &&
                    strncmp(st, p->attr_value, (size_t)tl) == 0)
                    return 1;
            }
            return 0;
        }
    }
    return 0;
}

/* Forward decl for :not() recursion */
static int matches_simple(html_node_t *node,
                          const struct css_selector_list *list);

/* Does `node` match this single selector part? */
static int match_part(html_node_t *node, const css_selector_part_t *p) {
    if (!node || !p) return 0;

    switch (p->kind) {
        case SEL_UNIVERSAL:
            return node->kind == HTML_NODE_ELEMENT;

        case SEL_ELEMENT:
            if (node->kind != HTML_NODE_ELEMENT) return 0;
            /* p->name is an arena slice, NOT NUL-terminated. Must use name_len. */
            return str_eq_n_case(node->tag, node->tag_len, p->name, p->name_len);

        case SEL_CLASS:
            if (node->kind != HTML_NODE_ELEMENT) return 0;
            return has_class(node, p->name, p->name_len);

        case SEL_ID: {
            if (node->kind != HTML_NODE_ELEMENT) return 0;
            const char *id = dom_get_id(node);
            return id && str_eq_n(p->name, p->name_len, id, (int)strlen(id));
        }

        case SEL_ATTR:
            if (node->kind != HTML_NODE_ELEMENT) return 0;
            return attr_matches(node, p);

        case SEL_PSEUDO_CLASS: {
            if (node->kind != HTML_NODE_ELEMENT) return 0;
            /* :not(...) — recurse */
            if (p->name_len == 3 && strncmp(p->name, "not", 3) == 0 && p->inner) {
                return !matches_simple(node, p->inner);
            }
            /* :first-child */
            if (p->name_len == 11 && strncmp(p->name, "first-child", 11) == 0) {
                return node->parent && node->parent->first_child == node;
            }
            /* :last-child */
            if (p->name_len == 10 && strncmp(p->name, "last-child", 10) == 0) {
                return node->parent && node->parent->last_child == node;
            }
            /* Others (:hover, :focus, :nth-child without arg) — false */
            return 0;
        }

        case SEL_PSEUDO_ELEM:
            return 0;

        default:
            return 0;
    }
}

/* Does `node` match all the compound parts of a single selector? */
static int match_compound(html_node_t *node, const css_selector_t *sel,
                          int start, int end) {
    for (int i = start; i < end; i++) {
        if (!match_part(node, &sel->parts[i])) return 0;
    }
    return 1;
}

/* Match a full selector (with combinators) against `node`.
 * Recursive from right to left. */
static int match_selector_rec(html_node_t *node, const css_selector_t *sel,
                              int idx) {
    if (idx < 0) return 1;   /* consumed all parts */

    if (!match_part(node, &sel->parts[idx])) return 0;

    if (idx == 0) return 1;   /* no more combinators */

    css_combinator_t comb = sel->combinators[idx - 1];
    switch (comb) {
        case COMB_DESCENDANT: {
            html_node_t *p = node->parent;
            while (p) {
                if (match_selector_rec(p, sel, idx - 1)) return 1;
                p = p->parent;
            }
            return 0;
        }
        case COMB_CHILD: {
            if (!node->parent) return 0;
            return match_selector_rec(node->parent, sel, idx - 1);
        }
        case COMB_ADJACENT: {
            if (!node->parent) return 0;
            html_node_t *prev = NULL;
            html_node_t *c = node->parent->first_child;
            while (c && c != node) { prev = c; c = c->next_sibling; }
            return prev && match_selector_rec(prev, sel, idx - 1);
        }
        case COMB_SIBLING: {
            if (!node->parent) return 0;
            html_node_t *c = node->parent->first_child;
            while (c && c != node) {
                if (match_selector_rec(c, sel, idx - 1)) return 1;
                c = c->next_sibling;
            }
            return 0;
        }
        default:
            return 0;
    }
}

/* Public match on a string */
int dom_matches(html_node_t *node, const char *selector) {
    if (!node || !selector) return 0;
    css_selector_t sel;
    memset(&sel, 0, sizeof(sel));
    if (css_parse_selector(selector, strlen(selector), &sel) != 0)
        return 0;
    int r = match_selector_rec(node, &sel, sel.n_parts - 1);
    return r;
}

/* Simple list matcher used by :not() */
static int matches_simple(html_node_t *node,
                          const struct css_selector_list *list) {
    if (!node || !list) return 0;
    for (int i = 0; i < list->n; i++) {
        if (match_selector_rec(node, &list->items[i],
                                list->items[i].n_parts - 1))
            return 1;
    }
    return 0;
}

/* ---- public query API ---- */

html_node_t *dom_get_element_by_id(html_node_t *root, const char *id) {
    if (!root || !id) return NULL;
    if (root->kind == HTML_NODE_ELEMENT) {
        const char *i = dom_get_id(root);
        if (i && strcmp(i, id) == 0) return root;
    }
    for (html_node_t *c = root->first_child; c; c = c->next_sibling) {
        html_node_t *r = dom_get_element_by_id(c, id);
        if (r) return r;
    }
    return NULL;
}

html_node_t *dom_get_element_by_tag(html_node_t *root, const char *tag) {
    if (!root || !tag) return NULL;
    if (root->kind == HTML_NODE_ELEMENT &&
        str_eq_n_case(root->tag, root->tag_len, tag, (int)strlen(tag)))
        return root;
    for (html_node_t *c = root->first_child; c; c = c->next_sibling) {
        html_node_t *r = dom_get_element_by_tag(c, tag);
        if (r) return r;
    }
    return NULL;
}

static int collect_tag(html_node_t *root, const char *tag,
                        html_node_t **out, int cap, int *n) {
    if (!root) return 0;
    if (root->kind == HTML_NODE_ELEMENT &&
        str_eq_n_case(root->tag, root->tag_len, tag, (int)strlen(tag))) {
        if (*n < cap) out[(*n)++] = root;
    }
    for (html_node_t *c = root->first_child; c; c = c->next_sibling) {
        collect_tag(c, tag, out, cap, n);
    }
    return 1;
}

int dom_get_elements_by_tag(html_node_t *root, const char *tag,
                             html_node_t **out, int cap) {
    int n = 0;
    collect_tag(root, tag, out, cap, &n);
    return n;
}

static int collect_class(html_node_t *root, const char *cls,
                          html_node_t **out, int cap, int *n) {
    if (!root) return 0;
    if (root->kind == HTML_NODE_ELEMENT &&
        has_class(root, cls, (int)strlen(cls))) {
        if (*n < cap) out[(*n)++] = root;
    }
    for (html_node_t *c = root->first_child; c; c = c->next_sibling) {
        collect_class(c, cls, out, cap, n);
    }
    return 1;
}

int dom_get_elements_by_class(html_node_t *root, const char *cls,
                               html_node_t **out, int cap) {
    int n = 0;
    collect_class(root, cls, out, cap, &n);
    return n;
}

html_node_t *dom_query_selector(html_node_t *root, const char *selector) {
    if (!root || !selector) return NULL;
    css_selector_t sel;
    memset(&sel, 0, sizeof(sel));
    if (css_parse_selector(selector, strlen(selector), &sel) != 0)
        return NULL;

    /* Preorder walk */
    /* We use an explicit stack */
    html_node_t *stack[4096];
    int top = 0;
    stack[top++] = root;
    while (top > 0) {
        html_node_t *n = stack[--top];
        if (n->kind == HTML_NODE_ELEMENT &&
            match_selector_rec(n, &sel, sel.n_parts - 1))
            return n;
        /* Push children in reverse order so leftmost is visited first */
        html_node_t *kids[256];
        int nk = 0;
        for (html_node_t *c = n->first_child; c && nk < 256;
             c = c->next_sibling)
            kids[nk++] = c;
        for (int i = nk - 1; i >= 0; i--)
            if (top < 4096) stack[top++] = kids[i];
    }
    return NULL;
}

int dom_query_selector_all(html_node_t *root, const char *selector,
                            html_node_t **out, int cap) {
    if (!root || !selector || !out) return 0;
    css_selector_t sel;
    memset(&sel, 0, sizeof(sel));
    if (css_parse_selector(selector, strlen(selector), &sel) != 0)
        return 0;

    int n = 0;
    html_node_t *stack[4096];
    int top = 0;
    stack[top++] = root;
    while (top > 0) {
        html_node_t *node = stack[--top];
        if (node->kind == HTML_NODE_ELEMENT &&
            match_selector_rec(node, &sel, sel.n_parts - 1)) {
            if (n < cap) out[n++] = node;
        }
        html_node_t *kids[256];
        int nk = 0;
        for (html_node_t *c = node->first_child; c && nk < 256;
             c = c->next_sibling)
            kids[nk++] = c;
        for (int i = nk - 1; i >= 0; i--)
            if (top < 4096) stack[top++] = kids[i];
    }
    return n;
}

/* Public match against an already-parsed selector (no string re-parse).
 * Mirrors dom_matches but skips css_parse_selector. Used by the style
 * cascade, where the selector was parsed once from the stylesheet. */
int dom_match_parsed(html_node_t *node, const css_selector_t *sel) {
    if (!node || !sel || sel->n_parts <= 0) return 0;
    if (node->kind != HTML_NODE_ELEMENT) return 0;
    return match_selector_rec(node, sel, sel->n_parts - 1);
}
