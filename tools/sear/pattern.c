/** pattern.c — pattern engine.
 *
 * Two implementations behind one API:
 *   - substring: literal find, optional case folding
 *   - regex:     a small backtracking engine
 *
 * Regex features:
 *   .        any byte except \n
 *   *        zero or more of previous
 *   +        one or more of previous
 *   ?        zero or one of previous
 *   ^        anchor to start of line
 *   $        anchor to end of line
 *   [abc]    character class
 *   [^abc]   negated class
 *   [a-z]    range inside class
 *   \d \w \s shortcuts; \D \W \S negated
 *   \. \\ \* escape literal
 *   |        alternation (lowest precedence)
 *   (...)    grouping
 *
 * Not supported: {n,m}, lookarounds, backrefs. Leftmost match wins.
 */

#include "sear.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
    NODE_CHAR,
    NODE_ANY,
    NODE_CLASS,
    NODE_ANCHOR_B,
    NODE_ANCHOR_E,
    NODE_GROUP,
    NODE_ALT,
    NODE_STAR,
    NODE_PLUS,
    NODE_QUEST,
} node_kind_t;

typedef struct node {
    node_kind_t   kind;
    unsigned char ch;
    unsigned char neg;
    unsigned char cls[32];
    struct node  *child;     /* group body, alt-left, quantifier body */
    struct node  *alt_right; /* alt-right only */
    struct node  *next;      /* sibling within a sequence */
    struct node  *free_link; /* pool chain for free() */
} node_t;

struct sear_pattern {
    int       is_regex;
    int       icase;
    char     *needle;
    size_t    nlen;
    node_t   *root;
    node_t   *pool;          /* singly-linked alloc list for freeing */
};

static node_t *node_new(sear_pattern_t *p, node_kind_t k) {
    node_t *n = sear_xmalloc(sizeof(*n));
    memset(n, 0, sizeof(*n));
    n->kind = k;
    n->free_link = p->pool;
    p->pool = n;
    return n;
}

static void cls_set(unsigned char set[32], unsigned char c) {
    set[c >> 3] |= (unsigned char)(1u << (c & 7));
}
static void cls_set_range(unsigned char set[32], unsigned char lo, unsigned char hi) {
    if (lo > hi) { unsigned char t = lo; lo = hi; hi = t; }
    for (unsigned int c = lo; c <= hi; c++) cls_set(set, (unsigned char)c);
}
static int cls_test(const unsigned char set[32], unsigned char c) {
    return (set[c >> 3] >> (c & 7)) & 1;
}

typedef struct {
    const char *p;
    sear_pattern_t *pat;
    int err;
} parser_t;

static node_t *parse_alt(parser_t *s);

static node_t *parse_atom(parser_t *s) {
    if (s->err) return NULL;
    char c = *s->p;
    if (c == 0) return NULL;
    if (c == '(') {
        s->p++;
        node_t *inner = parse_alt(s);
        if (*s->p != ')') { s->err = 1; return NULL; }
        s->p++;
        node_t *g = node_new(s->pat, NODE_GROUP);
        g->child = inner;
        return g;
    }
    if (c == '.') { s->p++; return node_new(s->pat, NODE_ANY); }
    if (c == '^') { s->p++; return node_new(s->pat, NODE_ANCHOR_B); }
    if (c == '$') { s->p++; return node_new(s->pat, NODE_ANCHOR_E); }
    if (c == '[') {
        s->p++;
        node_t *n = node_new(s->pat, NODE_CLASS);
        if (*s->p == '^') { n->neg = 1; s->p++; }
        if (*s->p == ']') { cls_set(n->cls, ']'); s->p++; }
        while (*s->p && *s->p != ']') {
            unsigned char lo = (unsigned char)*s->p++;
            if (*s->p == '-' && s->p[1] != ']' && s->p[1] != 0) {
                s->p++;
                unsigned char hi = (unsigned char)*s->p++;
                cls_set_range(n->cls, lo, hi);
            } else {
                cls_set(n->cls, lo);
            }
        }
        if (*s->p != ']') { s->err = 1; return NULL; }
        s->p++;
        return n;
    }
    if (c == '\\') {
        s->p++;
        char e = *s->p;
        if (e == 0) { s->err = 1; return NULL; }
        s->p++;
        if (e=='d' || e=='w' || e=='s' || e=='D' || e=='W' || e=='S') {
            node_t *n = node_new(s->pat, NODE_CLASS);
            if (e=='D' || e=='W' || e=='S') n->neg = 1;
            char lc = (e >= 'A' && e <= 'Z') ? (char)(e + 32) : e;
            if (lc == 'd') cls_set_range(n->cls, '0', '9');
            else if (lc == 'w') {
                cls_set_range(n->cls, '0', '9');
                cls_set_range(n->cls, 'a', 'z');
                cls_set_range(n->cls, 'A', 'Z');
                cls_set(n->cls, '_');
            } else {
                cls_set(n->cls, ' ');
                cls_set(n->cls, '\t');
                cls_set(n->cls, '\r');
                cls_set(n->cls, '\n');
            }
            return n;
        }
        node_t *n = node_new(s->pat, NODE_CHAR);
        n->ch = (unsigned char)e;
        return n;
    }
    s->p++;
    node_t *n = node_new(s->pat, NODE_CHAR);
    n->ch = (unsigned char)c;
    return n;
}

static node_t *parse_postfix(parser_t *s) {
    node_t *a = parse_atom(s);
    if (!a || s->err) return a;
    for (;;) {
        char c = *s->p;
        if (c == '*' || c == '+' || c == '?') {
            s->p++;
            node_kind_t k = (c == '*') ? NODE_STAR
                          : (c == '+') ? NODE_PLUS : NODE_QUEST;
            node_t *q = node_new(s->pat, k);
            q->child = a;
            a = q;
        } else break;
    }
    return a;
}

static node_t *parse_concat(parser_t *s) {
    node_t *first = NULL, *last = NULL;
    for (;;) {
        char c = *s->p;
        if (c == 0 || c == '|' || c == ')') break;
        node_t *a = parse_postfix(s);
        if (!a || s->err) return first;
        if (!first) first = a;
        else last->next = a;
        last = a;
    }
    return first;
}

static node_t *parse_alt(parser_t *s) {
    node_t *left = parse_concat(s);
    while (*s->p == '|') {
        s->p++;
        node_t *right = parse_concat(s);
        node_t *alt = node_new(s->pat, NODE_ALT);
        alt->child = left;
        alt->alt_right = right;
        left = alt;
    }
    return left;
}

sear_pattern_t *sear_pattern_substring(const char *needle, int icase) {
    sear_pattern_t *p = sear_xmalloc(sizeof(*p));
    memset(p, 0, sizeof(*p));
    p->is_regex = 0;
    p->icase = icase;
    p->needle = sear_xstrdup(needle);
    p->nlen = strlen(needle);
    return p;
}

sear_pattern_t *sear_pattern_regex(const char *re) {
    sear_pattern_t *p = sear_xmalloc(sizeof(*p));
    memset(p, 0, sizeof(*p));
    p->is_regex = 1;
    parser_t s = { re, p, 0 };
    p->root = parse_alt(&s);
    if (s.err || *s.p != 0) {
        sear_pattern_free(p);
        return NULL;
    }
    return p;
}

void sear_pattern_free(sear_pattern_t *p) {
    if (!p) return;
    free(p->needle);
    node_t *n = p->pool;
    while (n) { node_t *fl = n->free_link; free(n); n = fl; }
    free(p);
}

static size_t find_substring(const sear_pattern_t *p,
                             const char *line, size_t len) {
    if (p->nlen == 0) return 0;
    if (p->nlen > len) return SIZE_MAX;
    if (!p->icase) {
        for (size_t i = 0; i + p->nlen <= len; i++)
            if (memcmp(line + i, p->needle, p->nlen) == 0) return i;
        return SIZE_MAX;
    }
    for (size_t i = 0; i + p->nlen <= len; i++) {
        size_t j = 0;
        for (; j < p->nlen; j++) {
            unsigned char a = (unsigned char)line[i + j];
            unsigned char b = (unsigned char)p->needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j == p->nlen) return i;
    }
    return SIZE_MAX;
}

/* Match a node at pos. Returns end offset or SIZE_MAX. */
static size_t match_node(const node_t *n, const char *s, size_t len, size_t pos);

/* Match a sequence of nodes joined by ->next. */
static size_t match_seq(const node_t *n, const char *s, size_t len, size_t pos) {
    while (n) {
        if (n->kind == NODE_ALT) {
            size_t e = match_seq(n->child, s, len, pos);
            if (e != SIZE_MAX) {
                size_t e2 = match_seq(n->next, s, len, e);
                if (e2 != SIZE_MAX) return e2;
            }
            e = match_seq(n->alt_right, s, len, pos);
            if (e != SIZE_MAX) return e;
            return SIZE_MAX;
        }
        size_t e = match_node(n, s, len, pos);
        if (e == SIZE_MAX) return SIZE_MAX;
        pos = e;
        n = n->next;
    }
    return pos;
}

static size_t match_node(const node_t *n, const char *s, size_t len, size_t pos) {
    switch (n->kind) {
    case NODE_CHAR:
        if (pos >= len) return SIZE_MAX;
        if ((unsigned char)s[pos] == n->ch) return pos + 1;
        return SIZE_MAX;
    case NODE_ANY:
        if (pos >= len || s[pos] == '\n') return SIZE_MAX;
        return pos + 1;
    case NODE_CLASS: {
        if (pos >= len) return SIZE_MAX;
        int in = cls_test(n->cls, (unsigned char)s[pos]);
        if (n->neg) in = !in;
        return in ? pos + 1 : SIZE_MAX;
    }
    case NODE_ANCHOR_B: return pos == 0 ? pos : SIZE_MAX;
    case NODE_ANCHOR_E: return pos == len ? pos : SIZE_MAX;
    case NODE_GROUP:    return match_seq(n->child, s, len, pos);
    case NODE_STAR: {
        size_t cur = pos;
        for (;;) {
            size_t e = match_seq(n->next, s, len, cur);
            if (e != SIZE_MAX) return e;
            size_t adv = match_node(n->child, s, len, cur);
            if (adv == SIZE_MAX || adv == cur) return SIZE_MAX;
            cur = adv;
        }
    }
    case NODE_PLUS: {
        size_t adv = match_node(n->child, s, len, pos);
        if (adv == SIZE_MAX) return SIZE_MAX;
        size_t cur = adv;
        for (;;) {
            size_t e = match_seq(n->next, s, len, cur);
            if (e != SIZE_MAX) return e;
            size_t adv2 = match_node(n->child, s, len, cur);
            if (adv2 == SIZE_MAX || adv2 == cur) return SIZE_MAX;
            cur = adv2;
        }
    }
    case NODE_QUEST: {
        size_t e = match_seq(n->next, s, len, pos);
        if (e != SIZE_MAX) return e;
        size_t adv = match_node(n->child, s, len, pos);
        if (adv == SIZE_MAX) return SIZE_MAX;
        return match_seq(n->next, s, len, adv);
    }
    case NODE_ALT:
        /* Handled by match_seq when reached as a sibling */
        return SIZE_MAX;
    }
    return SIZE_MAX;
}

static size_t find_regex(const sear_pattern_t *p,
                         const char *line, size_t len) {
    int anchored = (p->root && p->root->kind == NODE_ANCHOR_B);
    for (size_t start = 0; start <= len; start++) {
        size_t e = match_seq(p->root, line, len, start);
        if (e != SIZE_MAX) return start;
        if (anchored) return SIZE_MAX;
    }
    return SIZE_MAX;
}

size_t sear_pattern_find(const sear_pattern_t *p,
                         const char *line, size_t len) {
    if (!p) return SIZE_MAX;
    if (p->is_regex) return find_regex(p, line, len);
    return find_substring(p, line, len);
}
