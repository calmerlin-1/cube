/** css_selector.c — selector parser (CSS Selectors Level 4 subset). */

#include "css_selector.h"
const css_selector_t *css_selector_intern(const char *text, int len, css_arena_t *ar);
void css_selector_intern_put(const char *text, int len, css_selector_t *sel);
#include <string.h>
#include <stdlib.h>

typedef struct {
    css_lexer_t *lx;
    css_arena_t *ar;
    css_token_t  cur;
    int          has_cur;
} sel_ctx_t;

static void next(sel_ctx_t *c) {
    do {
        c->cur = css_lexer_next(c->lx);
    } while (c->cur.kind == CSST_WHITESPACE);
    c->has_cur = 1;
}

static void peek_next(sel_ctx_t *c) {
    /* Look ahead one token, ignoring whitespace, into cur.
     * Not deeply integrated — we do a save/restore of the lexer. */
    (void)c;
}

/* Slice comparison: does slice [s, s+n) equal the C-string lit? */
static int slice_eq(const char *s, int n, const char *lit) {
    int lit_n = (int)strlen(lit);
    if (n != lit_n) return 0;
    return memcmp(s, lit, (size_t)n) == 0;
}

static void part_push(css_selector_t *sel, css_arena_t *ar,
                      css_selector_part_t part,
                      css_combinator_t comb) {
    if (sel->n_parts >= sel->cap_parts) {
        int new_cap = sel->cap_parts ? sel->cap_parts * 2 : 8;
        css_selector_part_t *np = (css_selector_part_t *)
            css_arena_alloc(ar, sizeof(*np) * (size_t)new_cap);
        if (sel->parts) memcpy(np, sel->parts, sizeof(*np) * (size_t)sel->n_parts);
        sel->parts = np;
        sel->cap_parts = new_cap;
    }
    if (comb != COMB_NONE || sel->n_parts > 0) {
        /* Store combinator BEFORE this part: combinators[i] joins parts[i] and parts[i+1].
         * We append as we go: when adding a part with a combinator, store at index n_parts-1. */
        if (sel->n_parts > 0) {
            /* ensure combinators array exists */
            if (!sel->combinators) {
                sel->combinators = (css_combinator_t *)
                    css_arena_alloc(ar, sizeof(css_combinator_t) * (size_t)sel->cap_parts);
            }
            sel->combinators[sel->n_parts - 1] = comb;
        }
    }
    sel->parts[sel->n_parts++] = part;
}

/* Parse [attr] or [attr=val] etc. Caller has consumed `[`. */
static void parse_attr(sel_ctx_t *c, css_selector_part_t *out) {
    out->kind = SEL_ATTR;
    if (c->cur.kind == CSST_IDENT) {
        out->name = c->cur.start;
        out->name_len = c->cur.length;
    }
    next(c);

    /* operator */
    if (c->cur.kind == CSST_DELIM ||
        c->cur.kind == CSST_IDENT /* some tokenizers split */) {
        /* Handle = ^= $= *= ~= |= */
        if (c->cur.kind == CSST_DELIM) {
            char opbuf[3] = {0};
            opbuf[0] = c->cur.start[0];
            next(c);
            if (c->cur.kind == CSST_DELIM && c->cur.start[0] == '=') {
                opbuf[1] = '=';
                next(c);
            }
            /* Store raw operator */
            out->attr_op = (const char *)css_arena_alloc(c->ar, 3);
            memcpy((void*)out->attr_op, opbuf, 3);
            out->attr_op_len = (int)strlen(opbuf);
        }
    }

    /* value */
    if (c->cur.kind == CSST_IDENT || c->cur.kind == CSST_STRING) {
        out->attr_value = c->cur.start;
        out->attr_value_len = c->cur.length;
        next(c);
    }

    if (c->cur.kind == CSST_RBRACKET) next(c);
}

static void parse_simple_selector(sel_ctx_t *c, css_selector_part_t *out) {
    memset(out, 0, sizeof(*out));

    /* Universal or element or class or id */
    if (c->cur.kind == CSST_DELIM && c->cur.start[0] == '*') {
        out->kind = SEL_UNIVERSAL;
        next(c);
        return;
    }
    if (c->cur.kind == CSST_IDENT) {
        out->kind = SEL_ELEMENT;
        out->name = c->cur.start;
        out->name_len = c->cur.length;
        next(c);
        return;
    }
    if (c->cur.kind == CSST_DELIM && c->cur.start[0] == '.') {
        next(c);
        if (c->cur.kind == CSST_IDENT) {
            out->kind = SEL_CLASS;
            out->name = c->cur.start;
            out->name_len = c->cur.length;
            next(c);
        }
        return;
    }
    if (c->cur.kind == CSST_HASH) {
        out->kind = SEL_ID;
        out->name = c->cur.start;
        out->name_len = c->cur.length;
        next(c);
        return;
    }
    if (c->cur.kind == CSST_LBRACKET) {
        next(c);
        parse_attr(c, out);
        return;
    }
    if (c->cur.kind == CSST_COLON) {
        next(c);
        int pseudo_elem = 0;
        if (c->cur.kind == CSST_COLON) { pseudo_elem = 1; next(c); }
        if (c->cur.kind == CSST_IDENT || c->cur.kind == CSST_FUNCTION) {
            out->kind = pseudo_elem ? SEL_PSEUDO_ELEM : SEL_PSEUDO_CLASS;
            out->name = c->cur.start;
            out->name_len = c->cur.length;
            if (c->cur.kind == CSST_FUNCTION) {
                /* :not(...) — capture raw argument text up to matching ) */
                const char *arg_start = c->lx->cur;
                int depth = 1;
                while (c->lx->cur < c->lx->end && depth > 0) {
                    uint8_t ch = (uint8_t)*c->lx->cur;
                    if (ch == '(') depth++;
                    else if (ch == ')') { depth--; if (depth == 0) break; }
                    c->lx->cur++;
                }
                out->arg_text = arg_start;
                out->arg_len = (int)(c->lx->cur - arg_start);
                next(c);   /* consume ) */
                if (c->cur.kind == CSST_RPAREN) next(c);
                /* Advance past rparen */
                if (c->cur.kind == CSST_RPAREN) next(c);
            } else {
                next(c);
            }
        }
    }
}

int css_parse_one_selector(css_lexer_t *lx, css_arena_t *ar, css_selector_t *out) {
    memset(out, 0, sizeof(*out));
    sel_ctx_t c = { .lx = lx, .ar = ar, .has_cur = 0 };
    next(&c);

    css_combinator_t pending = COMB_NONE;

    while (c.cur.kind != CSST_EOF &&
           c.cur.kind != CSST_COMMA &&
           c.cur.kind != CSST_LBRACE) {

        /* Check for combinator */
        if (c.cur.kind == CSST_DELIM) {
            char ch = c.cur.start[0];
            if (ch == '>') { pending = COMB_CHILD; next(&c); continue; }
            if (ch == '+') { pending = COMB_ADJACENT; next(&c); continue; }
            if (ch == '~') { pending = COMB_SIBLING; next(&c); continue; }
        }

        /* A part */
        css_selector_part_t part;
        parse_simple_selector(&c, &part);

        /* Ensure we got something */
        if (part.kind == SEL_ELEMENT && !part.name) break;

        part_push(out, ar, part, pending);
        pending = COMB_DESCENDANT;   /* next part is descendant unless overridden */

        /* Peek for a combinator */
        if (c.cur.kind == CSST_DELIM) {
            char ch = c.cur.start[0];
            if (ch == '>') { pending = COMB_CHILD; next(&c); }
            else if (ch == '+') { pending = COMB_ADJACENT; next(&c); }
            else if (ch == '~') { pending = COMB_SIBLING; next(&c); }
        }
    }

    /* Rewind the lexer so the caller sees the token that ENDED the
     * selector — typically `{` or `,`. Without this, the last `next()`
     * inside the parser consumes that token, and the caller has no
     * way to know the selector ended. */
    if (c.cur.start && c.cur.kind != CSST_EOF) {
        lx->cur = c.cur.start;
    }

    /* Compute specificity */
    out->spec_a = out->spec_b = out->spec_c = 0;
    for (int i = 0; i < out->n_parts; i++) {
        switch (out->parts[i].kind) {
            case SEL_ID: out->spec_a++; break;
            case SEL_CLASS: case SEL_ATTR:
            case SEL_PSEUDO_CLASS: out->spec_b++; break;
            case SEL_ELEMENT:
            case SEL_PSEUDO_ELEM: out->spec_c++; break;
            default: break;
        }
    }
    return 0;
}

css_selector_list_t css_parse_selector_list(css_lexer_t *lx, css_arena_t *ar) {
    css_selector_list_t list = {0};
    for (;;) {
        if (list.n >= list.cap) {
            int nc = list.cap ? list.cap * 2 : 4;
            css_selector_t *ni = (css_selector_t *)
                css_arena_alloc(ar, sizeof(*ni) * (size_t)nc);
            if (list.items) memcpy(ni, list.items, sizeof(*ni) * (size_t)list.n);
            list.items = ni;
            list.cap = nc;
        }
        css_selector_t sel;
        css_parse_one_selector(lx, ar, &sel);
        if (sel.n_parts == 0) break;
        list.items[list.n++] = sel;

        /* Save cursor so we can rewind if the next token isn't a comma. */
        const char *save_cur  = lx->cur;
        int         save_line = lx->line;
        int         save_col  = lx->column;

        css_token_t t;
        do { t = css_lexer_next(lx); } while (t.kind == CSST_WHITESPACE);

        if (t.kind == CSST_COMMA) {
            continue;   /* consume comma, next selector */
        }

        /* Not a comma — rewind so the caller sees `{` or `;` as the
         * next token. Without this, we'd eat the `{` and the caller
         * would never know where the selector ended. */
        lx->cur    = save_cur;
        lx->line   = save_line;
        lx->column = save_col;
        break;
    }
    return list;
}
