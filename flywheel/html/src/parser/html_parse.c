/** html_parse.c — HTML tree builder. Tokens → tree. */

#include "../../include/html.h"
#include "../tokenizer/html_token.h"
#include "../entity/html_entity.h"
#include "../runtime/arena.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/* Void elements — never have children, never need </close>. */
static const char *VOID_ELEMENTS[] = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr", NULL
};


/* Skip raw text in the lexer from current position to </tag>.
 * Returns the raw body slice and advances past the closing tag. */
static void skip_raw_body(html_lexer_t *lx, const char *tag, int tag_len,
                           const char **out_body, int *out_len) {
    const char *body = lx->cur;
    while (lx->cur + 1 < lx->end) {
        if (lx->cur[0] == '<' && lx->cur[1] == '/') {
            const char *p = lx->cur + 2;
            const char *e = lx->end;
            int i = 0;
            while (p < e && i < tag_len) {
                char a = *p;
                char b = tag[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) break;
                p++; i++;
            }
            if (i == tag_len) {
                *out_body = body;
                *out_len = (int)(lx->cur - body);
                return;
            }
        }
        if (*lx->cur == '\n') { lx->line++; lx->column = 1; }
        else lx->column++;
        lx->cur++;
    }
    *out_body = body;
    *out_len = (int)(lx->cur - body);
}

static int is_raw_text_tag(const char *tag, int len) {
    if (len == 6 && (strncmp(tag, "script", 6) == 0 || strncmp(tag, "SCRIPT", 6) == 0)) return 1;
    if (len == 5 && (strncmp(tag, "style", 5) == 0 || strncmp(tag, "STYLE", 5) == 0)) return 1;
    return 0;
}

int is_void_element(const char *tag, int len) {
    for (int i = 0; VOID_ELEMENTS[i]; i++) {
        int vl = (int)strlen(VOID_ELEMENTS[i]);
        if (vl == len) {
            int match = 1;
            for (int j = 0; j < len; j++) {
                char a = tag[j];
                char b = VOID_ELEMENTS[i][j];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (a != b) { match = 0; break; }
            }
            if (match) return 1;
        }
    }
    return 0;
}

/* Case-insensitive slice compare with C string. */
/* Auto-close rules: does opening `new_tag` close an open `open_tag`? */
static int slice_eq_ci(const char *s, int n, const char *lit) {
    int ll = (int)strlen(lit);
    if (n != ll) return 0;
    for (int i = 0; i < n; i++) {
        char a = s[i], b = lit[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static int should_auto_close(const char *open_tag, int open_len,
                             const char *new_tag, int new_len) {
    /* <p> closes on block-level elements */
    if (slice_eq_ci(open_tag, open_len, "p")) {
        const char *blocks[] = {"div","p","h1","h2","h3","h4","h5","h6",
                                "ul","ol","li","table","tr","td","th",
                                "section","article","header","footer",
                                "nav","aside","main","blockquote","pre",
                                "form","fieldset","hr", NULL};
        for (int i = 0; blocks[i]; i++) {
            if (slice_eq_ci(new_tag, new_len, blocks[i])) return 1;
        }
    }
    /* <li> closes on <li> */
    if (slice_eq_ci(open_tag, open_len, "li") &&
        slice_eq_ci(new_tag, new_len, "li")) return 1;
    /* <tr> closes on <tr> */
    if (slice_eq_ci(open_tag, open_len, "tr") &&
        slice_eq_ci(new_tag, new_len, "tr")) return 1;
    /* <td>/<th> close on <td>/<th>/<tr> */
    if ((slice_eq_ci(open_tag, open_len, "td") ||
         slice_eq_ci(open_tag, open_len, "th")) &&
        (slice_eq_ci(new_tag, new_len, "td") ||
         slice_eq_ci(new_tag, new_len, "th") ||
         slice_eq_ci(new_tag, new_len, "tr"))) return 1;
    /* <option> closes on <option> or <optgroup> */
    if (slice_eq_ci(open_tag, open_len, "option") &&
        (slice_eq_ci(new_tag, new_len, "option") ||
         slice_eq_ci(new_tag, new_len, "optgroup"))) return 1;
    /* <dt>/<dd> close on each other */
    if ((slice_eq_ci(open_tag, open_len, "dt") ||
         slice_eq_ci(open_tag, open_len, "dd")) &&
        (slice_eq_ci(new_tag, new_len, "dt") ||
         slice_eq_ci(new_tag, new_len, "dd"))) return 1;
    return 0;
}


/* Extract attributes from a START_TAG token body.
 * Body is `<tag attr1="v" attr2 attr3='v3'>`. We know tag_len.
 * Allocates html_attr_t array in the arena. */
static html_attr_t *parse_attrs(html_arena_t *ar, const char *body, int body_len,
                                 int tag_len, int *out_count) {
    *out_count = 0;
    /* Skip `<` and tag name. */
    const char *p = body + 1 + tag_len;
    const char *end = body + body_len;

    int cap = 4;
    html_attr_t *attrs = (html_attr_t *)html_arena_alloc(ar, sizeof(html_attr_t) * cap);
    if (!attrs) return NULL;
    int n = 0;

    while (p < end) {
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p >= end) break;
        if (*p == '>' || *p == '/') break;

        const char *name_start = p;
        while (p < end && !isspace((unsigned char)*p) && *p != '=' && *p != '>' && *p != '/') p++;
        int name_len = (int)(p - name_start);
        if (name_len == 0) { p++; continue; }

        /* Skip whitespace */
        while (p < end && isspace((unsigned char)*p)) p++;

        const char *val = NULL;
        int val_len = 0;
        int has_val = 0;

        if (p < end && *p == '=') {
            p++;
            while (p < end && isspace((unsigned char)*p)) p++;
            if (p < end && (*p == '"' || *p == '\'')) {
                char q = *p++;
                val = p;
                while (p < end && *p != q) p++;
                val_len = (int)(p - val);
                if (p < end) p++;
                has_val = 1;
            } else {
                /* Unquoted value */
                val = p;
                while (p < end && !isspace((unsigned char)*p) && *p != '>') p++;
                val_len = (int)(p - val);
                has_val = 1;
            }
        }

        if (n >= cap) {
            int nc = cap * 2;
            html_attr_t *big = (html_attr_t *)html_arena_alloc(ar, sizeof(html_attr_t) * nc);
            if (!big) break;
            memcpy(big, attrs, sizeof(html_attr_t) * n);
            attrs = big;
            cap = nc;
        }
        attrs[n].name = name_start;
        attrs[n].name_len = name_len;
        if (has_val && val) {
            char *vc = (char *)html_arena_alloc(ar, (size_t)val_len + 1);
            if (vc) { memcpy(vc, val, (size_t)val_len); vc[val_len] = '\0'; attrs[n].value = vc; }
            else attrs[n].value = val;
        } else attrs[n].value = val;
        attrs[n].value_len = val_len;
        attrs[n].has_value = (uint8_t)has_val;
        n++;
    }

    *out_count = n;
    return attrs;
}

/* Node constructor. */
static html_node_t *new_node(html_arena_t *ar, html_node_kind_t kind) {
    html_node_t *n = (html_node_t *)html_arena_alloc(ar, sizeof(*n));
    if (n) n->kind = kind;
    return n;
}

/* Append child to parent. */
static void append_child(html_node_t *parent, html_node_t *child) {
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

html_document_t *html_parse(const char *source, size_t len) {
    if (!source) return NULL;

    html_arena_t *ar = html_arena_pool_acquire();
    if (!ar) return NULL;

    html_document_t *doc = (html_document_t *)html_arena_alloc(ar, sizeof(*doc));
    if (!doc) { html_arena_pool_release(ar); return NULL; }
    doc->arena = ar;

    html_node_t *root = new_node(ar, HTML_NODE_ROOT);
    if (!root) { html_arena_pool_release(ar); return NULL; }
    doc->root = root;

    html_node_t *current = root;   /* stack of open elements */
    html_lexer_t lx;
    html_lexer_init(&lx, source, len);

    for (;;) {
        html_token_t tok = html_lexer_next(&lx);
        if (tok.kind == HTMLT_EOF) break;

        switch (tok.kind) {
            case HTMLT_TEXT: {
                /* Skip pure whitespace at top level? No — keep for fidelity. */
                html_node_t *n = new_node(ar, HTML_NODE_TEXT);
                if (n) {
                    n->text = tok.start;
                    n->text_len = tok.length;
                    append_child(current, n);
                    doc->n_nodes++;
                }
                break;
            }
            case HTMLT_COMMENT:
            case HTMLT_DOCTYPE:
            case HTMLT_CDATA: {
                html_node_t *n = new_node(ar, 
                    tok.kind == HTMLT_COMMENT ? HTML_NODE_COMMENT : HTML_NODE_DOCTYPE);
                if (n) {
                    n->text = tok.start;
                    n->text_len = tok.length;
                    append_child(current, n);
                    doc->n_nodes++;
                }
                break;
            }
            case HTMLT_START_TAG:
            case HTMLT_SELF_CLOSING: {
                html_node_t *n = new_node(ar, HTML_NODE_ELEMENT);
                if (!n) break;
                n->tag = tok.tag;
                n->tag_len = tok.tag_len;
                n->self_closing = (tok.kind == HTMLT_SELF_CLOSING) ? 1 : 0;

                /* Parse attributes */
                int ac = 0;
                n->attrs = parse_attrs(ar, tok.start, tok.length, tok.tag_len, &ac);
                n->attr_count = ac;

                append_child(current, n);
                doc->n_nodes++;

                /* Raw text elements: <script>, <style>. Skip body
                 * as raw text and attach as a single text child. */
                if (!n->self_closing && is_raw_text_tag(n->tag, n->tag_len)) {
                    const char *body;
                    int blen;
                    skip_raw_body(&lx, n->tag, n->tag_len, &body, &blen);
                    if (blen > 0) {
                        html_node_t *txt = new_node(ar, HTML_NODE_TEXT);
                        if (txt) {
                            txt->text = body;
                            txt->text_len = blen;
                            append_child(n, txt);
                            doc->n_nodes++;
                        }
                    }
                    /* Now consume the closing </script> or </style> */
                    html_token_t ct = html_lexer_next(&lx);
                    (void)ct;
                    break;
                }

                /* Auto-close ancestors whose tags this new tag preempts. */
                while (current && current->kind == HTML_NODE_ELEMENT &&
                       should_auto_close(current->tag, current->tag_len,
                                          n->tag, n->tag_len)) {
                    current = current->parent;
                }
                if (!current) current = root;

                /* Push unless void or self-closing */
                if (!n->self_closing && !is_void_element(n->tag, n->tag_len)) {
                    current = n;
                }
                break;
            }
            case HTMLT_END_TAG: {
                /* Find matching open ancestor and pop to it. */
                html_node_t *walker = current;
                while (walker != root) {
                    if (walker->kind == HTML_NODE_ELEMENT &&
                        slice_eq_ci(walker->tag, walker->tag_len, "") == 0 &&
                        walker->tag_len == tok.tag_len) {
                        /* Compare tag names case-insensitively */
                        int match = 1;
                        for (int i = 0; i < tok.tag_len; i++) {
                            char a = walker->tag[i], b = tok.tag[i];
                            if (a >= 'A' && a <= 'Z') a += 32;
                            if (b >= 'A' && b <= 'Z') b += 32;
                            if (a != b) { match = 0; break; }
                        }
                        if (match) {
                            current = walker->parent;
                            break;
                        }
                    }
                    walker = walker->parent;
                }
                break;
            }
            default: break;
        }
    }

    return doc;
}

void html_free(html_document_t *doc) {
    if (!doc) return;
    html_arena_t *ar = (html_arena_t *)doc->arena;
    if (ar) html_arena_pool_release(ar);
}

/* Recursive traversal helper. */
static const html_node_t *find_tag_rec(const html_node_t *n, const char *tag) {
    if (!n) return NULL;
    if (n->kind == HTML_NODE_ELEMENT) {
        int tl = (int)strlen(tag);
        if (n->tag_len == tl) {
            int match = 1;
            for (int i = 0; i < tl; i++) {
                char a = n->tag[i];
                char b = tag[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { match = 0; break; }
            }
            if (match) return n;
        }
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        const html_node_t *r = find_tag_rec(c, tag);
        if (r) return r;
    }
    return NULL;
}

const html_node_t *html_find_tag(const html_node_t *root, const char *tag) {
    if (!root || !tag) return NULL;
    return find_tag_rec(root, tag);
}

const html_node_t *html_find_attr(const html_node_t *root,
                                   const char *name, const char *value) {
    if (!root || !name) return NULL;
    for (const html_node_t *c = root; c; c = c->next_sibling) {
        if (c->kind == HTML_NODE_ELEMENT) {
            const char *v = html_get_attr(c, name);
            if (v && value && strcmp(v, value) == 0) return c;
            if (v && !value) return c;
            const html_node_t *r = html_find_attr(c->first_child, name, value);
            if (r) return r;
        } else if (c->first_child) {
            const html_node_t *r = html_find_attr(c->first_child, name, value);
            if (r) return r;
        }
    }
    return NULL;
}

/* Recursive text extraction. */
/* Check for hidden/non-visible elements — script, style, head.
 * These should not contribute to extracted text. */
static int is_hidden_tag(const char *tag, int len) {
    if (len == 6 && (strncmp(tag, "script", 6) == 0 || strncmp(tag, "SCRIPT", 6) == 0)) return 1;
    if (len == 5 && (strncmp(tag, "style", 5) == 0  || strncmp(tag, "STYLE", 5)  == 0)) return 1;
    if (len == 4 && (strncmp(tag, "head", 4) == 0   || strncmp(tag, "HEAD", 4)   == 0)) return 1;
    if (len == 5 && (strncmp(tag, "title", 5) == 0  || strncmp(tag, "TITLE", 5)  == 0)) return 1;
    if (len == 4 && (strncmp(tag, "meta", 4) == 0   || strncmp(tag, "META", 4)   == 0)) return 1;
    if (len == 4 && (strncmp(tag, "link", 4) == 0   || strncmp(tag, "LINK", 4)   == 0)) return 1;
    if (len == 3 && (strncmp(tag, "svg", 3) == 0    || strncmp(tag, "SVG", 3)    == 0)) return 1;
    if (len == 6 && (strncmp(tag, "canvas", 6) == 0 || strncmp(tag, "CANVAS", 6) == 0)) return 1;
    if (len == 6 && (strncmp(tag, "iframe", 6) == 0 || strncmp(tag, "IFRAME", 6) == 0)) return 1;
    if (len == 8 && (strncmp(tag, "noscript", 8) == 0 || strncmp(tag, "NOSCRIPT", 8) == 0)) return 1;
    return 0;
}
/* Track whether previous output ended in whitespace. */
static int g_last_was_ws = 1;

static int is_preformatted(const char *tag, int len) {
    if (len == 3 && (strncmp(tag, "pre", 3) == 0 || strncmp(tag, "PRE", 3) == 0)) return 1;
    if (len == 4 && (strncmp(tag, "code", 4) == 0 || strncmp(tag, "CODE", 4) == 0)) return 1;
    if (len == 8 && (strncmp(tag, "textarea", 8) == 0 || strncmp(tag, "TEXTAREA", 8) == 0)) return 1;
    return 0;
}

static int normalize_and_emit(const char *in, int in_len,
                               char *out, size_t cap,
                               int trim_leading, int at_line_start) {
    size_t w = 0;
    int last_was_ws = at_line_start || trim_leading;
    int i = 0;
    if (trim_leading) {
        while (i < in_len && (in[i] == ' ' || in[i] == '\t' ||
                               in[i] == '\n' || in[i] == '\r')) i++;
    }
    while (i < in_len) {
        char c = in[i++];
        int is_ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f');
        if (is_ws) {
            if (last_was_ws) continue;
            if (w + 1 >= cap) break;
            out[w++] = ' ';
            last_was_ws = 1;
        } else {
            if (w + 1 >= cap) break;
            out[w++] = c;
            last_was_ws = 0;
        }
    }
    return (int)w;
}

static int append_text(const html_node_t *n, char *out, size_t cap, int w) {
    if (!n) return w;
    if (n->kind == HTML_NODE_TEXT) {
        /* Decode entities first (into a scratch stack buffer), then
         * normalize whitespace from the decoded text. */
        char scratch[8192];
        int scratch_cap = n->text_len * 4 + 16;   /* worst-case: all entity refs */
        char *decoded = scratch;
        char *heap = NULL;
        if (scratch_cap > (int)sizeof(scratch)) {
            heap = (char *)malloc((size_t)scratch_cap);
            if (!heap) {
                /* Fallback: emit raw normalized */
                int wrote = normalize_and_emit(n->text, n->text_len,
                                                out + w, cap - (size_t)w,
                                                1, g_last_was_ws);
                if (wrote > 0) g_last_was_ws = (out[w + wrote - 1] == ' ');
                return w + wrote;
            }
            decoded = heap;
        }
        int dlen = html_entity_decode(n->text, n->text_len,
                                       decoded, (size_t)scratch_cap);
        int wrote = normalize_and_emit(decoded, dlen,
                                        out + w, cap - (size_t)w,
                                        1, g_last_was_ws);
        if (heap) free(heap);
        if (wrote > 0) g_last_was_ws = (out[w + wrote - 1] == ' ');
        return w + wrote;
    }
    if (n->kind == HTML_NODE_ELEMENT && is_hidden_tag(n->tag, n->tag_len)) {
        return w;
    }
    if (n->kind == HTML_NODE_ELEMENT && is_preformatted(n->tag, n->tag_len)) {
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
            if (c->kind == HTML_NODE_TEXT) {
                int copy = c->text_len;
                if ((size_t)(w + copy) >= cap) copy = (int)(cap - w - 1);
                if (copy > 0) {
                    memcpy(out + w, c->text, (size_t)copy);
                    w += copy;
                    g_last_was_ws = 0;
                }
            }
        }
        return w;
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        w = append_text(c, out, cap, w);
    }
    if (n->kind == HTML_NODE_ELEMENT && !g_last_was_ws && w < (int)cap - 1) {
        if (slice_eq_ci(n->tag, n->tag_len, "p") ||
            slice_eq_ci(n->tag, n->tag_len, "div") ||
            slice_eq_ci(n->tag, n->tag_len, "br") ||
            slice_eq_ci(n->tag, n->tag_len, "li") ||
            slice_eq_ci(n->tag, n->tag_len, "tr") ||
            slice_eq_ci(n->tag, n->tag_len, "h1") ||
            slice_eq_ci(n->tag, n->tag_len, "h2") ||
            slice_eq_ci(n->tag, n->tag_len, "h3") ||
            slice_eq_ci(n->tag, n->tag_len, "h4") ||
            slice_eq_ci(n->tag, n->tag_len, "h5") ||
            slice_eq_ci(n->tag, n->tag_len, "h6")) {
            out[w++] = '\n';
            g_last_was_ws = 1;
        }
    }
    return w;
}


static int append_raw_text(const html_node_t *n, char *out, size_t cap, int w) {
    if (!n) return w;
    if (n->kind == HTML_NODE_TEXT) {
        /* Decode entities first (into a scratch stack buffer), then
         * normalize whitespace from the decoded text. */
        char scratch[8192];
        int scratch_cap = n->text_len * 4 + 16;   /* worst-case: all entity refs */
        char *decoded = scratch;
        char *heap = NULL;
        if (scratch_cap > (int)sizeof(scratch)) {
            heap = (char *)malloc((size_t)scratch_cap);
            if (!heap) {
                /* Fallback: emit raw normalized */
                int wrote = normalize_and_emit(n->text, n->text_len,
                                                out + w, cap - (size_t)w,
                                                1, g_last_was_ws);
                if (wrote > 0) g_last_was_ws = (out[w + wrote - 1] == ' ');
                return w + wrote;
            }
            decoded = heap;
        }
        int dlen = html_entity_decode(n->text, n->text_len,
                                       decoded, (size_t)scratch_cap);
        int wrote = normalize_and_emit(decoded, dlen,
                                        out + w, cap - (size_t)w,
                                        1, g_last_was_ws);
        if (heap) free(heap);
        if (wrote > 0) g_last_was_ws = (out[w + wrote - 1] == ' ');
        return w + wrote;
    }
    /* (raw variant: no is_hidden_tag check) */
    if (n->kind == HTML_NODE_ELEMENT && is_preformatted(n->tag, n->tag_len)) {
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
            if (c->kind == HTML_NODE_TEXT) {
                int copy = c->text_len;
                if ((size_t)(w + copy) >= cap) copy = (int)(cap - w - 1);
                if (copy > 0) {
                    memcpy(out + w, c->text, (size_t)copy);
                    w += copy;
                    g_last_was_ws = 0;
                }
            }
        }
        return w;
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        w = append_raw_text(c, out, cap, w);
    }
    if (n->kind == HTML_NODE_ELEMENT && !g_last_was_ws && w < (int)cap - 1) {
        if (slice_eq_ci(n->tag, n->tag_len, "p") ||
            slice_eq_ci(n->tag, n->tag_len, "div") ||
            slice_eq_ci(n->tag, n->tag_len, "br") ||
            slice_eq_ci(n->tag, n->tag_len, "li") ||
            slice_eq_ci(n->tag, n->tag_len, "tr") ||
            slice_eq_ci(n->tag, n->tag_len, "h1") ||
            slice_eq_ci(n->tag, n->tag_len, "h2") ||
            slice_eq_ci(n->tag, n->tag_len, "h3") ||
            slice_eq_ci(n->tag, n->tag_len, "h4") ||
            slice_eq_ci(n->tag, n->tag_len, "h5") ||
            slice_eq_ci(n->tag, n->tag_len, "h6")) {
            out[w++] = '\n';
            g_last_was_ws = 1;
        }
    }
    return w;
}

/* html_raw_text — like html_text_content but does NOT suppress hidden
 * tags (script/style/head/...). Used by the DOM to extract script bodies. */
int html_raw_text(const html_node_t *node, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    int w = append_raw_text(node, out, cap, 0);
    if ((size_t)w < cap) out[w] = '\0';
    return w;
}



int html_text_content(const html_node_t *node, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    int w = append_text(node, out, cap, 0);
    if ((size_t)w < cap) out[w] = '\0';
    return w;
}

/* Recursive dump. */
static void dump_rec(const html_node_t *n, int depth) {
    if (!n) return;
    for (int i = 0; i < depth; i++) printf("  ");
    switch (n->kind) {
        case HTML_NODE_ELEMENT:
            printf("<%.*s>", n->tag_len, n->tag);
            for (int i = 0; i < n->attr_count; i++) {
                printf(" %.*s", n->attrs[i].name_len, n->attrs[i].name);
                if (n->attrs[i].has_value) {
                    printf("=\"%.*s\"", n->attrs[i].value_len,
                           n->attrs[i].value ? n->attrs[i].value : "");
                }
            }
            printf("\n");
            break;
        case HTML_NODE_TEXT:
            printf("\"%.*s\"\n", n->text_len, n->text);
            break;
        case HTML_NODE_COMMENT:
            printf("<!-- %.*s -->\n", n->text_len, n->text);
            break;
        case HTML_NODE_DOCTYPE:
            printf("<!DOCTYPE %.*s>\n", n->text_len, n->text);
            break;
        case HTML_NODE_ROOT:
            printf("(root)\n");
            break;
    }
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        dump_rec(c, depth + 1);
    }
}

void html_dump(const html_document_t *doc) {
    if (!doc || !doc->root) { printf("(null document)\n"); return; }
    printf("=== document: %d nodes ===\n", doc->n_nodes);
    dump_rec(doc->root, 0);
}

const char *html_get_attr(const html_node_t *node, const char *name) {
    if (!node || !name) return NULL;
    int nl = (int)strlen(name);
    for (int i = 0; i < node->attr_count; i++) {
        if (node->attrs[i].name_len == nl) {
            int match = 1;
            for (int j = 0; j < nl; j++) {
                char a = node->attrs[i].name[j];
                char b = name[j];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { match = 0; break; }
            }
            if (match) return node->attrs[i].value;
        }
    }
    return NULL;
}
