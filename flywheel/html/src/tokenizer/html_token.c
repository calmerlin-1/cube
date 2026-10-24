/** html_token.c — HTML tokenizer. State machine over bytes. */

#include "html_token.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void html_lexer_init(html_lexer_t *lx, const char *s, size_t n) {
    if (!lx) return;
    lx->source = s;
    lx->cur = s;
    lx->end = s + n;
    lx->line = 1;
    lx->column = 1;
}

static uint8_t peek(const html_lexer_t *lx) {
    return (lx->cur < lx->end) ? (uint8_t)*lx->cur : 0;
}
static uint8_t peek_at(const html_lexer_t *lx, int off) {
    const char *p = lx->cur + off;
    return (p < lx->end) ? (uint8_t)*p : 0;
}
static uint8_t adv(html_lexer_t *lx) {
    if (lx->cur >= lx->end) return 0;
    uint8_t c = (uint8_t)*lx->cur++;
    if (c == '\n') { lx->line++; lx->column = 1; } else lx->column++;
    return c;
}

static int is_ws(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}
static int is_alpha(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* Read text until '<' or end. */
static html_token_t scan_text(html_lexer_t *lx) {
    html_token_t t = {0};
    t.kind = HTMLT_TEXT;
    t.start = lx->cur;
    t.line = lx->line;
    t.column = lx->column;
    while (lx->cur < lx->end && *lx->cur != '<') adv(lx);
    t.length = (int)(lx->cur - t.start);
    return t;
}

/* Read tag name after < or </. Returns length, advances. */
static int scan_tag_name(html_lexer_t *lx) {
    const char *start = lx->cur;
    while (lx->cur < lx->end) {
        uint8_t c = peek(lx);
        if (is_ws(c) || c == '>' || c == '/' || c == 0) break;
        adv(lx);
    }
    return (int)(lx->cur - start);
}

html_token_t html_lexer_next(html_lexer_t *lx) {
    html_token_t t = {0};
    if (!lx || lx->cur >= lx->end) {
        t.kind = HTMLT_EOF;
        return t;
    }

    /* Not '<' — text */
    if (peek(lx) != '<') return scan_text(lx);

    const char *start = lx->cur;

    /* <!-- comment --> */
    if (peek(lx) == '<' && peek_at(lx, 1) == '!' && peek_at(lx, 2) == '-' && peek_at(lx, 3) == '-') {
        adv(lx); adv(lx); adv(lx); adv(lx);
        const char *body = lx->cur;
        while (lx->cur < lx->end) {
            if (peek(lx) == '-' && peek_at(lx, 1) == '-' && peek_at(lx, 2) == '>') {
                t.kind = HTMLT_COMMENT;
                t.start = body;
                t.length = (int)(lx->cur - body);
                adv(lx); adv(lx); adv(lx);
                return t;
            }
            adv(lx);
        }
        t.kind = HTMLT_COMMENT;
        t.start = body;
        t.length = (int)(lx->cur - body);
        return t;
    }

    /* <!DOCTYPE ...> or <![CDATA[...]]> */
    if (peek(lx) == '<' && peek_at(lx, 1) == '!') {
        if (peek_at(lx, 2) == '[') {
            /* CDATA */
            adv(lx); adv(lx); adv(lx);   /* <![ */
            const char *body = lx->cur;
            while (lx->cur + 2 < lx->end) {
                if (peek(lx) == ']' && peek_at(lx, 1) == ']' && peek_at(lx, 2) == '>') {
                    t.kind = HTMLT_CDATA;
                    t.start = body;
                    t.length = (int)(lx->cur - body);
                    adv(lx); adv(lx); adv(lx);
                    return t;
                }
                adv(lx);
            }
            t.kind = HTMLT_CDATA;
            t.start = body;
            t.length = (int)(lx->cur - body);
            return t;
        }
        /* DOCTYPE */
        adv(lx); adv(lx);   /* <! */
        const char *body = lx->cur;
        while (lx->cur < lx->end && *lx->cur != '>') adv(lx);
        t.kind = HTMLT_DOCTYPE;
        t.start = body;
        t.length = (int)(lx->cur - body);
        if (lx->cur < lx->end) adv(lx);
        return t;
    }

    /* </end tag> */
    if (peek(lx) == '<' && peek_at(lx, 1) == '/') {
        adv(lx); adv(lx);
        const char *tag_start = lx->cur;
        int tag_len = scan_tag_name(lx);
        t.kind = HTMLT_END_TAG;
        t.start = start;
        t.tag = tag_start;
        t.tag_len = tag_len;
        /* Skip whitespace and up to > */
        while (lx->cur < lx->end && peek(lx) != '>') adv(lx);
        if (lx->cur < lx->end) adv(lx);
        t.length = (int)(lx->cur - start);
        return t;
    }

    /* <start tag> or <self-closing/> */
    if (peek(lx) == '<' && (is_alpha(peek_at(lx, 1)) || peek_at(lx, 1) == '_')) {
        adv(lx);
        const char *tag_start = lx->cur;
        int tag_len = scan_tag_name(lx);

        int self_close = 0;
        /* Walk to '>' looking for '/' */
        while (lx->cur < lx->end) {
            uint8_t c = peek(lx);
            if (c == '/') {
                /* Look ahead to confirm it's the self-closer */
                if (peek_at(lx, 1) == '>') { self_close = 1; adv(lx); break; }
            }
            if (c == '>') break;
            /* Skip quoted attribute values so we don't misinterpret > */
            if (c == '"' || c == '\'') {
                uint8_t q = c; adv(lx);
                while (lx->cur < lx->end && peek(lx) != q) adv(lx);
                if (lx->cur < lx->end) adv(lx);
                continue;
            }
            adv(lx);
        }
        if (lx->cur < lx->end && peek(lx) == '>') adv(lx);

        t.kind = self_close ? HTMLT_SELF_CLOSING : HTMLT_START_TAG;
        t.start = start;
        t.tag = tag_start;
        t.tag_len = tag_len;
        t.length = (int)(lx->cur - start);
#ifdef TOK_TRACE
        fprintf(stderr, "[tok] START_TAG start=%.20s.. tag='%.*s' tag_len=%d length=%d\n",
                start, tag_len, tag_start, tag_len, t.length);
#endif
        return t;
    }

    /* Lone '<' — treat as text */
    t.kind = HTMLT_TEXT;
    t.start = lx->cur;
    adv(lx);
    t.length = 1;
    return t;
}

/* Is this tag a raw-text element? Content is not parsed as tags. */
static int is_raw_text_tag(const char *tag, int len) {
    if (len == 6 && (strncmp(tag, "script", 6) == 0 || strncmp(tag, "SCRIPT", 6) == 0)) return 1;
    if (len == 5 && (strncmp(tag, "style", 5) == 0 || strncmp(tag, "STYLE", 5) == 0)) return 1;
    return 0;
}

/* Advance the lexer past raw-text content until </tag>. */
static void skip_raw_text_body(html_lexer_t *lx, const char *tag, int tag_len) {
    while (lx->cur + 1 < lx->end) {
        if (*lx->cur == '<' && lx->cur[1] == '/') {
            /* Check if it's the closing tag */
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
            if (i == tag_len) return;   /* found </tag — stop */
        }
        adv(lx);
    }
}

const char *html_tok_kind_name(html_tok_kind_t k) {
    switch (k) {
        case HTMLT_EOF: return "EOF";
        case HTMLT_TEXT: return "TEXT";
        case HTMLT_START_TAG: return "START_TAG";
        case HTMLT_END_TAG: return "END_TAG";
        case HTMLT_SELF_CLOSING: return "SELF_CLOSING";
        case HTMLT_COMMENT: return "COMMENT";
        case HTMLT_DOCTYPE: return "DOCTYPE";
        case HTMLT_CDATA: return "CDATA";
        case HTMLT_ERROR: return "ERROR";
        default: return "?";
    }
}
