/** html_format.c — HTML pretty-printer. AST → indented text. */
#include "html.h"
#include "html_types.h"
#include <stdio.h>
#include <string.h>

/* Tags whose contents are emitted verbatim (no reflow, no indent). */
static int is_verbatim(const char *tag, int tag_len) {
    static const char *V[] = { "pre", "code", "script", "style", "textarea", NULL };
    for (int i = 0; V[i]; i++) {
        int vl = (int)strlen(V[i]);
        if (tag_len == vl && !memcmp(tag, V[i], (size_t)vl)) return 1;
    }
    return 0;
}

/* Tags that never have children or closing tag. */
static int is_void(const char *tag, int tag_len) {
    static const char *V[] = {
        "area","base","br","col","embed","hr","img","input","link",
        "meta","param","source","track","wbr", NULL
    };
    for (int i = 0; V[i]; i++) {
        int vl = (int)strlen(V[i]);
        if (tag_len == vl && !memcmp(tag, V[i], (size_t)vl)) return 1;
    }
    return 0;
}

static int is_inline(const char *tag, int tag_len) {
    static const char *V[] = {
        "a","abbr","b","bdi","bdo","cite","code","data","dfn","em",
        "i","kbd","mark","q","s","samp","small","span","strong",
        "sub","sup","time","u","var","wbr", NULL
    };
    for (int i = 0; V[i]; i++) {
        int vl = (int)strlen(V[i]);
        if (tag_len == vl && !memcmp(tag, V[i], (size_t)vl)) return 1;
    }
    return 0;
}

static void indent(FILE *out, int depth) {
    for (int i = 0; i < depth; i++) fputs("  ", out);
}

/* Emit tag name lowercased. HTML is case-insensitive; a browser
 * treats <HTML>, <Html>, <html> identically. We normalize on output
 * so rendered source is consistent regardless of source casing. */
static void emit_tag_lower(FILE *out, const char *tag, int tag_len) {
    for (int i = 0; i < tag_len; i++) {
        char c = tag[i];
        if (c >= 'A' && c <= 'Z') c = c + ('a' - 'A');
        fputc(c, out);
    }
}

static void emit_attrs(FILE *out, const html_node_t *n) {
    for (int i = 0; i < n->attr_count; i++) {
        fputc(' ', out);
        fwrite(n->attrs[i].name, 1, (size_t)n->attrs[i].name_len, out);
        if (n->attrs[i].has_value) {
            fputs("=\"", out);
            if (n->attrs[i].value_len > 0 && n->attrs[i].value)
                fwrite(n->attrs[i].value, 1, (size_t)n->attrs[i].value_len, out);
            fputc('"', out);
        }
    }
}

static int subtree_inline_only(const html_node_t *n);
static void emit_inline_subtree(const html_node_t *n, FILE *out);

static int subtree_inline_only(const html_node_t *n) {
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        if (c->kind == HTML_NODE_TEXT || c->kind == HTML_NODE_COMMENT) continue;
        if (c->kind != HTML_NODE_ELEMENT) continue;
        if (!is_inline(c->tag, c->tag_len)) return 0;
        if (!subtree_inline_only(c)) return 0;
    }
    return 1;
}

static void emit_inline_subtree(const html_node_t *n, FILE *out) {
    fputc('<', out);
    emit_tag_lower(out, n->tag, n->tag_len);
    emit_attrs(out, n);
    if (n->self_closing || is_void(n->tag, n->tag_len)) {
        fputc('>', out);
        return;
    }
    fputc('>', out);
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
        if (c->kind == HTML_NODE_TEXT && c->text && c->text_len > 0) {
            fwrite(c->text, 1, (size_t)c->text_len, out);
        } else if (c->kind == HTML_NODE_ELEMENT) {
            emit_inline_subtree(c, out);
        }
    }
    fputs("</", out);
    emit_tag_lower(out, n->tag, n->tag_len);
    fputc('>', out);
}
static void walk(const html_node_t *n, FILE *out, int depth, int verbatim);

static void emit_element(const html_node_t *n, FILE *out, int depth) {
    if (is_verbatim(n->tag, n->tag_len)) {
        /* Verbatim: open tag on own line, raw children, close tag */
        indent(out, depth);
        fputc('<', out);
        emit_tag_lower(out, n->tag, n->tag_len);
        emit_attrs(out, n);
        fputc('>', out);
        if (!n->self_closing && !is_void(n->tag, n->tag_len)) {
            int is_script = (n->tag_len == 6 && memcmp(n->tag, "script", 6) == 0);
            if (!is_script) {
                for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
                    if (c->kind == HTML_NODE_TEXT && c->text)
                        fwrite(c->text, 1, (size_t)c->text_len, out);
                }
            }
            fputs("</", out);
            emit_tag_lower(out, n->tag, n->tag_len);
            fputc('>', out);
        }
        fputc('\n', out);
        return;
    }
    if (is_inline(n->tag, n->tag_len) || subtree_inline_only(n)) {
        indent(out, depth);
        emit_inline_subtree(n, out);
        fputc('\n', out);
        return;
    }

    int inline_ = is_inline(n->tag, n->tag_len);
    int has_elem_child = 0;
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        if (c->kind == HTML_NODE_ELEMENT) { has_elem_child = 1; break; }

    if (!inline_ || has_elem_child) indent(out, depth);
    fputc('<', out);
    emit_tag_lower(out, n->tag, n->tag_len);
    emit_attrs(out, n);
    if (n->self_closing || is_void(n->tag, n->tag_len)) {
        fputs(">\n", out);
        return;
    }
    fputc('>', out);

    if (!has_elem_child) {
        /* Only text/comment children — emit inline, close inline.
         * Strip trailing whitespace from text so <title>X</title>
         * doesn't become <title>X\n</title> */
        for (const html_node_t *c = n->first_child; c; c = c->next_sibling) {
            if (c->kind == HTML_NODE_TEXT && c->text && c->text_len > 0) {
                int len = c->text_len;
                while (len > 0 && (c->text[len-1] == '\n' || c->text[len-1] == '\r' ||
                                   c->text[len-1] == ' '  || c->text[len-1] == '\t')) len--;
                fwrite(c->text, 1, (size_t)len, out);
            } else {
                walk(c, out, 0, 0);
            }
        }
        fputs("</", out);
        emit_tag_lower(out, n->tag, n->tag_len);
        fputs(">\n", out);
        return;
    }

    fputc('\n', out);
    for (const html_node_t *c = n->first_child; c; c = c->next_sibling)
        walk(c, out, depth + 1, 0);
    indent(out, depth);
    fputs("</", out);
    emit_tag_lower(out, n->tag, n->tag_len);
    fputs(">\n", out);
}

static void walk(const html_node_t *n, FILE *out, int depth, int verbatim) {
    (void)verbatim;
    switch (n->kind) {
        case HTML_NODE_ELEMENT:  emit_element(n, out, depth); break;
        case HTML_NODE_TEXT:
            if (n->text && n->text_len > 0) {
                /* Trim leading/trailing whitespace-only text */
                int has_nonws = 0;
                for (int i = 0; i < n->text_len; i++) {
                    char c = n->text[i];
                    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') { has_nonws = 1; break; }
                }
                if (has_nonws) {
                    if (depth > 0) indent(out, depth);
                    fwrite(n->text, 1, (size_t)n->text_len, out);
                    fputc('\n', out);
                }
            }
            break;
        case HTML_NODE_COMMENT:
            if (depth > 0) indent(out, depth);
            fputs("<!--", out);
            if (n->text) fwrite(n->text, 1, (size_t)n->text_len, out);
            fputs("-->\n", out);
            break;
        case HTML_NODE_DOCTYPE:
            fputs("<!", out);
            if (n->text) fwrite(n->text, 1, (size_t)n->text_len, out);
            fputs(">\n", out);
            break;
        default: break;
    }
}

int html_format(const char *src, size_t len, FILE *out) {
    if (!src || !out) return -1;
    html_document_t *doc = html_parse(src, len);
    if (!doc) return -1;
    for (const html_node_t *n = doc->root->first_child; n; n = n->next_sibling)
        walk(n, out, 0, 0);
    html_free(doc);
    return 0;
}
