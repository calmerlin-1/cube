/** css_token.c — CSS tokenizer per CSS Syntax Module Level 3 (simplified). */

#include "css_token.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Byte class table — one lookup replaces 10+ branches.
 * Values 0-31 are reserved for single-char tokens (see BC_SINGLE). */



/* Bulk skip whitespace. Returns number of bytes advanced. */
static size_t skip_ws_bulk(const char *p, const char *end) {
    size_t n = 0;
    /* 8-byte bulk skip while all 8 bytes are whitespace */
    while (p + 8 <= end) {
        uint64_t w;
        __builtin_memcpy(&w, p, 8);
        /* Check each byte is space (0x20) or in {9,10,11,12,13} */
        uint64_t ws_mask = 0x2020202020202020ull;
        if ((w & 0xDFDFDFDFDFDFDFDFull) != ws_mask) {
            /* Not all whitespace — fall through to byte loop */
            break;
        }
        p += 8; n += 8;
    }
    /* Byte-by-byte for the remainder */
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\f')) {
        p++; n++;
    }
    return n;
}

/* Bulk scan identifier-continue bytes. Returns bytes advanced. */

/* Bulk skip comment body: memchr for '*'. Returns bytes advanced to close. */
static size_t skip_comment_bulk(const char *p, const char *end) {
    while (p + 1 < end) {
        const char *star = (const char *)memchr(p, '*', (size_t)(end - p - 1));
        if (!star) return (size_t)(end - p);   /* unterminated */
        if (star[1] == '/') return (size_t)(star - p + 2);
        p = star + 1;
    }
    return (size_t)(end - p);
}

void css_lexer_init(css_lexer_t *lx, const char *s, size_t n) {
    if (!lx) return;
    lx->source = s;
    lx->cur = s;
    lx->end = s + n;
    lx->line = 1;
    lx->column = 1;
}

static int is_ws(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}
static int is_digit(uint8_t c) { return c >= '0' && c <= '9'; }
static int is_hex(uint8_t c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int is_alpha(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static int is_ident_start(uint8_t c) { return is_alpha(c) || c == '_' || c >= 0x80; }
static int is_ident_cont(uint8_t c) { return is_ident_start(c) || is_digit(c) || c == '-'; }

static uint8_t peek(const css_lexer_t *lx) {
    return (lx->cur < lx->end) ? (uint8_t)*lx->cur : 0;
}
static uint8_t peek_at(const css_lexer_t *lx, int offset) {
    const char *p = lx->cur + offset;
    return (p < lx->end) ? (uint8_t)*p : 0;
}
static uint8_t adv(css_lexer_t *lx) {
    if (lx->cur >= lx->end) return 0;
    uint8_t c = (uint8_t)*lx->cur++;
    if (c == '\n') { lx->line++; lx->column = 1; } else lx->column++;
    return c;
}

/* Consume an escape sequence after a backslash. Returns 0 if none. */
static int consume_escape(css_lexer_t *lx) {
    uint8_t c = peek(lx);
    if (c == 0) return 0;
    if (is_hex(c)) {
        int n = 0;
        while (n < 6 && is_hex(peek(lx))) { adv(lx); n++; }
        if (is_ws(peek(lx))) adv(lx);
        return 1;
    }
    adv(lx);
    return 1;
}

/* Consume an identifier-like sequence. */
static void consume_ident_like(css_lexer_t *lx) {
    for (;;) {
        uint8_t c = peek(lx);
        if (is_ident_cont(c)) { adv(lx); continue; }
        if (c == '\\') { adv(lx); consume_escape(lx); continue; }
        break;
    }
}

/* Consume a numeric sequence. */
static void consume_number(css_lexer_t *lx, double *out) {
    const char *start = lx->cur;
    if (peek(lx) == '+' || peek(lx) == '-') adv(lx);
    while (is_digit(peek(lx))) adv(lx);
    if (peek(lx) == '.' && is_digit(peek_at(lx, 1))) {
        adv(lx);
        while (is_digit(peek(lx))) adv(lx);
    }
    if (peek(lx) == 'e' || peek(lx) == 'E') {
        int off = 1;
        if (peek_at(lx, 1) == '+' || peek_at(lx, 1) == '-') off = 2;
        if (is_digit(peek_at(lx, off))) {
            adv(lx);
            if (peek(lx) == '+' || peek(lx) == '-') adv(lx);
            while (is_digit(peek(lx))) adv(lx);
        }
    }
    /* Parse the numeric portion. */
    char buf[64];
    int n = (int)(lx->cur - start);
    if (n > 63) n = 63;
    memcpy(buf, start, (size_t)n);
    buf[n] = '\0';
    *out = strtod(buf, NULL);
}

/* Consume a string, quoted with `q`. Writes content slice into out. */
static int consume_string(css_lexer_t *lx, uint8_t q,
                          const char **out_start, int *out_len, int *is_bad) {
    *is_bad = 0;
    adv(lx);   /* open quote */
    const char *start = lx->cur;
    int len = 0;
    while (lx->cur < lx->end) {
        uint8_t c = peek(lx);
        if (c == q) {
            *out_start = start;
            *out_len = len;
            adv(lx);
            return 1;
        }
        if (c == '\n') {
            *is_bad = 1;
            *out_start = start;
            *out_len = len;
            return 0;
        }
        if (c == '\\') { adv(lx); consume_escape(lx); len += 1; continue; }
        adv(lx);
        len++;
    }
    *is_bad = 1;
    *out_start = start;
    *out_len = len;
    return 0;
}

/* Skip a URL body: url(...) — content is raw. */
static void consume_url_body(css_lexer_t *lx) {
    while (is_ws(peek(lx))) adv(lx);
    while (lx->cur < lx->end) {
        uint8_t c = peek(lx);
        if (c == ')') return;
        if (c == '\\') { adv(lx); consume_escape(lx); continue; }
        adv(lx);
    }
}

css_token_t css_lexer_next(css_lexer_t *lx) {
    css_token_t t;
    memset(&t, 0, sizeof(t));

    if (!lx || lx->cur >= lx->end) {
        t.kind = CSST_EOF;
        return t;
    }

    const char *start = lx->cur;
    /* Whitespace — bulk skip */
    if (is_ws(peek(lx))) {
        size_t n = skip_ws_bulk(lx->cur, lx->end);
        lx->cur += n;
        t.kind = CSST_WHITESPACE;
        t.start = start;
        t.length = (int)n;
        return t;
    }

    /* Comments — bulk skip with memchr */
    if (peek(lx) == '/' && peek_at(lx, 1) == '*') {
        lx->cur += 2;
        size_t n = skip_comment_bulk(lx->cur, lx->end);
        lx->cur += n;
        t.kind = CSST_WHITESPACE;
        t.start = start;
        t.length = (int)(lx->cur - start);
        return t;
    }

    /* CDO / CDC */
    if (peek(lx) == '<' && peek_at(lx,1) == '!' && peek_at(lx,2) == '-' && peek_at(lx,3) == '-') {
        adv(lx); adv(lx); adv(lx); adv(lx);
        t.kind = CSST_CDO;
        t.start = start;
        t.length = 4;
        return t;
    }
    if (peek(lx) == '-' && peek_at(lx,1) == '-' && peek_at(lx,2) == '>') {
        adv(lx); adv(lx); adv(lx);
        t.kind = CSST_CDC;
        t.start = start;
        t.length = 3;
        return t;
    }

    /* String */
    if (peek(lx) == '"' || peek(lx) == '\'') {
        uint8_t q = peek(lx);
        const char *sstart; int slen; int bad;
        consume_string(lx, q, &sstart, &slen, &bad);
        t.kind = bad ? CSST_BAD_STRING : CSST_STRING;
        t.start = sstart;
        t.length = slen;
        return t;
    }

    /* #hash */
    if (peek(lx) == '#') {
        adv(lx);
        t.kind = CSST_HASH;
        t.start = start + 1;
        if (is_ident_cont(peek(lx))) {
            while (is_ident_cont(peek(lx))) adv(lx);
        }
        t.length = (int)(lx->cur - t.start);
        return t;
    }

    /* @at-keyword */
    if (peek(lx) == '@') {
        adv(lx);
        if (is_ident_start(peek(lx)) || peek(lx) == '\\') {
            consume_ident_like(lx);
            t.kind = CSST_AT_KEYWORD;
            t.start = start;
            t.length = (int)(lx->cur - start);
            return t;
        }
        t.kind = CSST_DELIM;
        t.start = start;
        t.length = 1;
        return t;
    }

    /* Number / dimension / percentage */
    if ((is_digit(peek(lx))) ||
        (peek(lx) == '.' && is_digit(peek_at(lx, 1))) ||
        ((peek(lx) == '+' || peek(lx) == '-') &&
         (is_digit(peek_at(lx, 1)) ||
          (peek_at(lx, 1) == '.' && is_digit(peek_at(lx, 2)))))) {
        consume_number(lx, &t.number);
        t.start = start;
        if (peek(lx) == '%') {
            adv(lx);
            t.kind = CSST_PERCENTAGE;
        } else if (is_ident_start(peek(lx)) || peek(lx) == '\\') {
            const char *ustart = lx->cur;
            consume_ident_like(lx);
            t.kind = CSST_DIMENSION;
            t.unit = ustart;
            t.unit_len = (int)(lx->cur - ustart);
        } else {
            t.kind = CSST_NUMBER;
        }
        t.length = (int)(lx->cur - start);
        return t;
    }

    /* Ident-like, including url( and function( */
    if (is_ident_start(peek(lx)) || peek(lx) == '\\') {
        consume_ident_like(lx);
        const char *name_start = start;
        int name_len = (int)(lx->cur - name_start);

        /* url( — special: read raw until ) */
        if (name_len == 3 &&
            (name_start[0] == 'u' || name_start[0] == 'U') &&
            (name_start[1] == 'r' || name_start[1] == 'R') &&
            (name_start[2] == 'l' || name_start[2] == 'L') &&
            peek(lx) == '(') {
            adv(lx);
            const char *u_start = lx->cur;
            consume_url_body(lx);
            t.kind = CSST_URL;
            t.start = u_start;
            t.length = (int)(lx->cur - u_start);
            if (peek(lx) == ')') adv(lx);
            return t;
        }

        if (peek(lx) == '(') {
            adv(lx);
            t.kind = CSST_FUNCTION;
            t.start = name_start;
            t.length = name_len;
            return t;
        }

        t.kind = CSST_IDENT;
        t.start = name_start;
        t.length = name_len;
        return t;
    }

    /* Single-char tokens */
    uint8_t c = adv(lx);
    switch (c) {
        case ':': t.kind = CSST_COLON; break;
        case ';': t.kind = CSST_SEMICOLON; break;
        case ',': t.kind = CSST_COMMA; break;
        case '[': t.kind = CSST_LBRACKET; break;
        case ']': t.kind = CSST_RBRACKET; break;
        case '(': t.kind = CSST_LPAREN; break;
        case ')': t.kind = CSST_RPAREN; break;
        case '{': t.kind = CSST_LBRACE; break;
        case '}': t.kind = CSST_RBRACE; break;
        default:  t.kind = CSST_DELIM; break;
    }
    t.start = start;
    t.length = 1;
    return t;
}

const char *css_tok_kind_name(css_tok_kind_t k) {
    switch (k) {
        case CSST_EOF: return "EOF";
        case CSST_IDENT: return "IDENT";
        case CSST_FUNCTION: return "FUNCTION";
        case CSST_AT_KEYWORD: return "AT";
        case CSST_HASH: return "HASH";
        case CSST_STRING: return "STRING";
        case CSST_BAD_STRING: return "BAD_STRING";
        case CSST_URL: return "URL";
        case CSST_NUMBER: return "NUMBER";
        case CSST_PERCENTAGE: return "PERCENT";
        case CSST_DIMENSION: return "DIMENSION";
        case CSST_WHITESPACE: return "WS";
        case CSST_COLON: return "COLON";
        case CSST_SEMICOLON: return "SEMI";
        case CSST_COMMA: return "COMMA";
        case CSST_LBRACKET: return "LBRACKET";
        case CSST_RBRACKET: return "RBRACKET";
        case CSST_LPAREN: return "LPAREN";
        case CSST_RPAREN: return "RPAREN";
        case CSST_LBRACE: return "LBRACE";
        case CSST_RBRACE: return "RBRACE";
        case CSST_DELIM: return "DELIM";
        case CSST_CDO: return "CDO";
        case CSST_CDC: return "CDC";
        default: return "?";
    }
}
