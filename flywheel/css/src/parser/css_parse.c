/** css_parse.c — top-level CSS parser. Token stream → rules. */

#include "../../include/css.h"
#include "css_selector.h"
#include "css_value.h"
extern css_token_t *css_tok_cache_get(const char *, size_t, int *);
extern void css_tok_cache_put(const char *, size_t, css_token_t *, int);
extern void css_cache_enable(int);

/* Auto-enable caches on first parse. */
static int g_cache_autoinited = 0;
static void cache_lazy_init(void) {
    if (!g_cache_autoinited) {
        css_cache_enable(1);
        g_cache_autoinited = 1;
    }
}
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    css_lexer_t  lx;
    css_arena_t *ar;
    css_token_t  cur;
    int          has_cur;
} parse_ctx_t;

/* Error ring — small, fixed size. */
#define MAX_ERRORS 64
static char  g_errors[MAX_ERRORS][256];
static int   g_err_count = 0;

int css_error_count(void) { return g_err_count; }
const char *css_error_at(int i) {
    if (i < 0 || i >= g_err_count) return "";
    return g_errors[i];
}
void css_error_clear(void) { g_err_count = 0; }

static void report(const parse_ctx_t *p, const char *msg) {
    if (g_err_count >= MAX_ERRORS) return;
    snprintf(g_errors[g_err_count], sizeof(g_errors[0]),
             "line %d col %d: %s", p->lx.line, p->lx.column, msg);
    g_err_count++;
}

static void next(parse_ctx_t *p) {
    do { p->cur = css_lexer_next(&p->lx); } while (p->cur.kind == CSST_WHITESPACE);
    p->has_cur = 1;
}

static void rule_push(css_stylesheet_t *ss, css_arena_t *ar, css_rule_t r) {
    if (ss->n_rules >= ss->cap_rules) {
        int nc = ss->cap_rules ? ss->cap_rules * 2 : 8;
        css_rule_t *nr = (css_rule_t *)css_arena_alloc(ar, sizeof(*nr) * (size_t)nc);
        if (ss->rules) memcpy(nr, ss->rules, sizeof(*nr) * (size_t)ss->n_rules);
        ss->rules = nr;
        ss->cap_rules = nc;
    }
    ss->rules[ss->n_rules++] = r;
}

static void decl_push(css_rule_t *r, css_arena_t *ar, css_decl_t d) {
    if (r->n_decls >= r->cap_decls) {
        int nc = r->cap_decls ? r->cap_decls * 2 : 8;
        css_decl_t *nd = (css_decl_t *)css_arena_alloc(ar, sizeof(*nd) * (size_t)nc);
        if (r->decls) memcpy(nd, r->decls, sizeof(*nd) * (size_t)r->n_decls);
        r->decls = nd;
        r->cap_decls = nc;
    }
    r->decls[r->n_decls++] = d;
}

/* Parse one declaration block body: `prop: value; prop: value` — until `}` */
static void parse_declarations(parse_ctx_t *p, css_arena_t *ar, css_rule_t *rule) {
    next(p);
    while (p->cur.kind != CSST_RBRACE && p->cur.kind != CSST_EOF) {
        if (p->cur.kind != CSST_IDENT) {
            /* skip junk */
            next(p);
            continue;
        }
        css_decl_t d = {0};
        d.prop = p->cur.start;
        d.prop_len = p->cur.length;
        next(p);

        if (p->cur.kind != CSST_COLON) {
            report(p, "expected ':' after property");
            /* Byte-skip recovery — no tokenizing until delimiter. */
            while (p->lx.cur < p->lx.end) {
                char c = *p->lx.cur;
                if (c == ';' || c == '}') break;
                p->lx.cur++;
            }
            if (p->lx.cur < p->lx.end && *p->lx.cur == ';') p->lx.cur++;
            next(p);
            continue;
        }
        next(p);

        /* Value: collect until ; or } respecting parens */
        const char *vstart = p->cur.start;
        const char *vend = vstart;
        int depth = 0;
        int important = 0;
        while (p->cur.kind != CSST_EOF) {
            if (p->cur.kind == CSST_SEMICOLON && depth == 0) break;
            if (p->cur.kind == CSST_RBRACE && depth == 0) break;
            if (p->cur.kind == CSST_LPAREN) depth++;
            if (p->cur.kind == CSST_RPAREN && depth > 0) depth--;
            if (p->cur.kind == CSST_FUNCTION) depth++;
            if (p->cur.kind == CSST_IDENT &&
                p->cur.length == 9 &&
                memcmp(p->cur.start, "important", 9) == 0) {
                /* check for ! before */
                /* Simple: mark important if value contains '!important' */
                important = 1;
            }
            vend = p->cur.start + p->cur.length;
            next(p);
        }
        d.value = vstart;
        d.value_len = (int)(vend - vstart);
        d.important = important;
        /* Value parsing is LAZY. The cascade calls css_decl_value()
         * when it needs a structured value. Parsing garbage or parse-
         * only workloads (extraction) shouldn't pay for it. */
        d.parsed = NULL;
        decl_push(rule, ar, d);

        if (p->cur.kind == CSST_SEMICOLON) next(p);
    }
    if (p->cur.kind == CSST_RBRACE) next(p);
}

/* Parse one rule (style or at-rule). */
static void parse_one_rule(parse_ctx_t *p, css_arena_t *ar, css_stylesheet_t *ss) {
    if (p->cur.kind == CSST_AT_KEYWORD) {
        css_rule_t r = {0};
        r.kind = RULE_AT_UNKNOWN;
        r.at_name = p->cur.start + 1;
        r.at_name_len = p->cur.length - 1;
        /* Capture prelude: tokens until { or ; */
        const char *pre_start = p->cur.start + p->cur.length;
        next(p);
        while (p->cur.kind != CSST_LBRACE &&
               p->cur.kind != CSST_SEMICOLON &&
               p->cur.kind != CSST_EOF) {
            next(p);
        }
        r.at_prelude = pre_start;
        r.at_prelude_len = (int)(p->cur.start - pre_start);

        if (p->cur.kind == CSST_LBRACE) {
            if (r.at_name_len == 5 && memcmp(r.at_name, "media", 5) == 0) r.kind = RULE_AT_MEDIA;
            else if (r.at_name_len == 7 && memcmp(r.at_name, "supports", 8) == 0) r.kind = RULE_AT_SUPPORTS;
            else if (r.at_name_len == 9 && memcmp(r.at_name, "font-face", 9) == 0) r.kind = RULE_AT_FONT_FACE;
            /* Read nested rules until } */
            next(p);
            while (p->cur.kind != CSST_RBRACE && p->cur.kind != CSST_EOF) {
                parse_one_rule(p, ar, ss);   /* recursion — for now, dump nested at top */
            }
            if (p->cur.kind == CSST_RBRACE) next(p);
        } else if (p->cur.kind == CSST_SEMICOLON) {
            if (r.at_name_len == 6 && memcmp(r.at_name, "import", 6) == 0) r.kind = RULE_AT_IMPORT;
            next(p);
        }
        rule_push(ss, ar, r);
        return;
    }

    /* Style rule: selector list { decls } */
    css_rule_t r = {0};
    r.kind = RULE_STYLE;

    /* The selector parser reads directly from the lexer. But we already
     * peeked p->cur as the first token of this rule. Rewind the lexer
     * so the selector parser re-reads that token from the source. */
    if (p->has_cur && p->cur.start) {
        p->lx.cur = p->cur.start;
        p->has_cur = 0;
    }
    r.selectors = css_parse_selector_list(&p->lx, ar);

    /* Re-read the current token (should be `{` if the selector parser
     * rewound correctly, or whatever the selector parser stopped on). */
    next(p);

    if (p->cur.kind != CSST_LBRACE) {
        report(p, "expected '{' after selector");
        /* skip to next { or } */
        while (p->cur.kind != CSST_LBRACE &&
               p->cur.kind != CSST_RBRACE &&
               p->cur.kind != CSST_EOF) next(p);
        if (p->cur.kind != CSST_LBRACE) return;
    }
    parse_declarations(p, ar, &r);
    rule_push(ss, ar, r);
}

/* Fast check: does the first 8 bytes contain any CSS-start char? */
static int looks_like_css(const char *s, size_t len) {
    size_t n = len < 8 ? len : 8;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.' || c == '#' || c == '@' || c == '*' || c == ':' ||
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '/' /* comment */) return 1;
    }
    return 0;
}

css_stylesheet_t *css_parse(const char *source, size_t len) {
    if (!source) return NULL;
    cache_lazy_init();
    css_error_clear();

    /* BAILOUT: reject obvious non-CSS before allocating an arena. */
    if (len > 0 && !looks_like_css(source, len)) {
        css_arena_t *ar0 = css_arena_pool_acquire();
        if (!ar0) return NULL;
        css_stylesheet_t *empty = (css_stylesheet_t *)
            css_arena_alloc(ar0, sizeof(*empty));
        if (empty) empty->arena = ar0;
        return empty;
    }

    css_arena_t *ar = css_arena_pool_acquire();
    if (!ar) return NULL;

    css_stylesheet_t *ss = (css_stylesheet_t *)css_arena_alloc(ar, sizeof(*ss));
    if (!ss) { css_arena_free(ar); return NULL; }
    ss->arena = ar;

    parse_ctx_t p = {0};
    css_lexer_init(&p.lx, source, len);
    p.ar = ar;
    next(&p);

    while (p.cur.kind != CSST_EOF) {
        if (p.cur.kind == CSST_RBRACE || p.cur.kind == CSST_SEMICOLON ||
            p.cur.kind == CSST_CDO || p.cur.kind == CSST_CDC) {
            next(&p);
            continue;
        }
        parse_one_rule(&p, ar, ss);
    }
    return ss;
}

/* Public: parse a single selector (no commas, no braces). */
int css_parse_selector(const char *text, size_t len, css_selector_t *out) {
    if (!text || !out) return -1;
    css_arena_t *ar = css_arena_new(1024);
    if (!ar) return -1;
    css_lexer_t lx;
    css_lexer_init(&lx, text, len);
    int rc = css_parse_one_selector(&lx, ar, out);
    /* We can't free the arena — out->parts point into it.
     * Caller owns the arena indirectly via out->parts. For the test
     * that's fine; real callers should use a longer-lived arena. */
    return rc;
}

void css_free(css_stylesheet_t *s) {
    if (!s) return;
    css_arena_t *ar = (css_arena_t *)s->arena;
    if (ar) css_arena_pool_release(ar);
}

/* ---- debug dump ---- */

void css_dump(const css_stylesheet_t *s) {
    if (!s) { printf("(null stylesheet)\n"); return; }
    printf("=== stylesheet: %d rules ===\n", s->n_rules);
    for (int i = 0; i < s->n_rules; i++) {
        const css_rule_t *r = &s->rules[i];
        if (r->kind == RULE_STYLE) {
            printf("  [rule %d] selector list: %d selectors\n", i, r->selectors.n);
            for (int j = 0; j < r->selectors.n; j++) {
                const css_selector_t *sel = &r->selectors.items[j];
                printf("    sel %d: %d parts (spec %u,%u,%u)  ",
                       j, sel->n_parts, sel->spec_a, sel->spec_b, sel->spec_c);
                for (int k = 0; k < sel->n_parts; k++) {
                    if (k > 0) printf("%c ",
                        sel->combinators && sel->combinators[k-1] == COMB_CHILD ? '>' :
                        sel->combinators && sel->combinators[k-1] == COMB_ADJACENT ? '+' :
                        sel->combinators && sel->combinators[k-1] == COMB_SIBLING ? '~' : ' ');
                    const css_selector_part_t *pt = &sel->parts[k];
                    switch (pt->kind) {
                        case SEL_ELEMENT: printf("E(%.*s)", pt->name_len, pt->name); break;
                        case SEL_CLASS: printf(".%.*s", pt->name_len, pt->name); break;
                        case SEL_ID: printf("#%.*s", pt->name_len, pt->name); break;
                        case SEL_ATTR: printf("[%.*s]", pt->name_len, pt->name); break;
                        case SEL_PSEUDO_CLASS: printf(":%.*s", pt->name_len, pt->name); break;
                        case SEL_PSEUDO_ELEM: printf("::%.*s", pt->name_len, pt->name); break;
                        case SEL_UNIVERSAL: printf("*"); break;
                    }
                }
                printf("\n");
            }
            printf("    %d declarations:\n", r->n_decls);
            for (int k = 0; k < r->n_decls; k++) {
                printf("      %.*s: %.*s%s\n",
                       r->decls[k].prop_len, r->decls[k].prop,
                       r->decls[k].value_len, r->decls[k].value,
                       r->decls[k].important ? " !important" : "");
            }
        } else {
            printf("  [rule %d] @%.*s prelude='%.*s'\n", i,
                   r->at_name_len, r->at_name,
                   r->at_prelude_len, r->at_prelude);
        }
    }
}

void css_selector_dump(const css_selector_t *sel) {
    if (!sel) return;
    printf("selector: %d parts, specificity (%u,%u,%u)\n",
           sel->n_parts, sel->spec_a, sel->spec_b, sel->spec_c);
}

uint32_t css_selector_specificity(const css_selector_t *sel) {
    if (!sel) return 0;
    return (sel->spec_a << 20) | (sel->spec_b << 10) | sel->spec_c;
}

void css_selector_specificity_str(const css_selector_t *sel,
                                  char *out, size_t cap) {
    if (!sel || !out) return;
    snprintf(out, cap, "(%u,%u,%u)", sel->spec_a, sel->spec_b, sel->spec_c);
}
