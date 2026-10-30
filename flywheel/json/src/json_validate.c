/** json_validate.c — strict JSON / JSONC validator.
 *
 * JSONC mode permits // and /* *\/ comments and trailing commas in
 * arrays/objects. Everything else is validated to RFC 8259. No
 * allocation; suitable for config files and untrusted response bodies.
 */

#include "json.h"
#include <string.h>

typedef struct {
    const char     *s;
    size_t          len;
    size_t          i;
    int             comments;
    json_error_t   *err;
    int             failed;
} jp_t;

static void fail_at(jp_t *p, size_t off, const char *msg) {
    if (p->failed) return;
    p->failed = 1;
    if (!p->err) return;
    p->err->offset = off;
    p->err->line = 1;
    p->err->column = 1;
    for (size_t k = 0; k < off && k < p->len; k++) {
        if (p->s[k] == '\n') { p->err->line++; p->err->column = 1; }
        else p->err->column++;
    }
    snprintf(p->err->message, sizeof p->err->message, "%s", msg);
}

static int peek(jp_t *p) {
    return p->i < p->len ? (unsigned char)p->s[p->i] : -1;
}

static int take(jp_t *p) {
    if (p->i >= p->len) return -1;
    return (unsigned char)p->s[p->i++];
}

/* Skip whitespace and, in JSONC mode, comments. Returns 0 on success. */
static int skip_ws(jp_t *p) {
    for (;;) {
        while (p->i < p->len) {
            unsigned char c = (unsigned char)p->s[p->i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') p->i++;
            else break;
        }
        if (!p->comments || p->i + 1 >= p->len || p->s[p->i] != '/') return 0;
        if (p->s[p->i + 1] == '/') {
            p->i += 2;
            while (p->i < p->len && p->s[p->i] != '\n') p->i++;
            continue;
        }
        if (p->s[p->i + 1] == '*') {
            size_t start = p->i;
            p->i += 2;
            while (p->i + 1 < p->len &&
                   !(p->s[p->i] == '*' && p->s[p->i + 1] == '/')) p->i++;
            if (p->i + 1 >= p->len) {
                fail_at(p, start, "unterminated block comment");
                return -1;
            }
            p->i += 2;
            continue;
        }
        return 0;
    }
}

static int parse_value(jp_t *p, int depth);

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_string(jp_t *p) {
    size_t start = p->i;
    if (take(p) != '"') { fail_at(p, start, "expected string"); return -1; }
    while (p->i < p->len) {
        unsigned char c = (unsigned char)p->s[p->i++];
        if (c == '"') return 0;
        if (c < 0x20) { fail_at(p, p->i - 1, "unescaped control character in string"); return -1; }
        if (c != '\\') continue;
        int e = take(p);
        if (e < 0) { fail_at(p, p->i, "unterminated escape"); return -1; }
        if (e == '"' || e == '\\' || e == '/' || e == 'b' ||
            e == 'f' || e == 'n' || e == 'r' || e == 't') continue;
        if (e == 'u') {
            for (int k = 0; k < 4; k++) {
                int h = hexval(take(p));
                if (h < 0) { fail_at(p, p->i - 1, "invalid \\u escape"); return -1; }
            }
            continue;
        }
        fail_at(p, p->i - 1, "invalid escape sequence");
        return -1;
    }
    fail_at(p, start, "unterminated string");
    return -1;
}

static int parse_number(jp_t *p) {
    size_t start = p->i;
    if (peek(p) == '-') p->i++;
    if (peek(p) == '0') {
        p->i++;
        if (peek(p) >= '0' && peek(p) <= '9') {
            fail_at(p, p->i, "leading zero in number");
            return -1;
        }
    } else if (peek(p) >= '1' && peek(p) <= '9') {
        while (peek(p) >= '0' && peek(p) <= '9') p->i++;
    } else {
        fail_at(p, start, "invalid number");
        return -1;
    }
    if (peek(p) == '.') {
        p->i++;
        if (!(peek(p) >= '0' && peek(p) <= '9')) {
            fail_at(p, p->i, "missing digits after decimal point");
            return -1;
        }
        while (peek(p) >= '0' && peek(p) <= '9') p->i++;
    }
    if (peek(p) == 'e' || peek(p) == 'E') {
        p->i++;
        if (peek(p) == '+' || peek(p) == '-') p->i++;
        if (!(peek(p) >= '0' && peek(p) <= '9')) {
            fail_at(p, p->i, "missing exponent digits");
            return -1;
        }
        while (peek(p) >= '0' && peek(p) <= '9') p->i++;
    }
    return 0;
}

static int parse_literal(jp_t *p, const char *lit) {
    size_t n = strlen(lit);
    if (p->i + n > p->len || memcmp(p->s + p->i, lit, n) != 0) {
        fail_at(p, p->i, "invalid literal");
        return -1;
    }
    p->i += n;
    return 0;
}

static int parse_array(jp_t *p, int depth) {
    size_t start = p->i;
    p->i++; /* [ */
    if (skip_ws(p) != 0) return -1;
    if (peek(p) == ']') { p->i++; return 0; }
    for (;;) {
        if (skip_ws(p) != 0) return -1;
        if (parse_value(p, depth + 1) != 0) return -1;
        if (skip_ws(p) != 0) return -1;
        int c = take(p);
        if (c == ',') {
            if (skip_ws(p) != 0) return -1;
            if (p->comments && peek(p) == ']') { p->i++; return 0; }
            continue;
        }
        if (c == ']') return 0;
        fail_at(p, p->i ? p->i - 1 : start, "expected ',' or ']'");
        return -1;
    }
}

static int parse_object(jp_t *p, int depth) {
    size_t start = p->i;
    p->i++; /* { */
    if (skip_ws(p) != 0) return -1;
    if (peek(p) == '}') { p->i++; return 0; }
    for (;;) {
        if (skip_ws(p) != 0) return -1;
        if (parse_string(p) != 0) return -1;
        if (skip_ws(p) != 0) return -1;
        if (take(p) != ':') {
            fail_at(p, p->i ? p->i - 1 : start, "expected ':' after object key");
            return -1;
        }
        if (skip_ws(p) != 0) return -1;
        if (parse_value(p, depth + 1) != 0) return -1;
        if (skip_ws(p) != 0) return -1;
        int c = take(p);
        if (c == ',') {
            if (skip_ws(p) != 0) return -1;
            if (p->comments && peek(p) == '}') { p->i++; return 0; }
            continue;
        }
        if (c == '}') return 0;
        fail_at(p, p->i ? p->i - 1 : start, "expected ',' or '}'");
        return -1;
    }
}

static int parse_value(jp_t *p, int depth) {
    if (depth > 512) { fail_at(p, p->i, "nesting too deep"); return -1; }
    if (skip_ws(p) != 0) return -1;
    int c = peek(p);
    switch (c) {
        case '{': return parse_object(p, depth);
        case '[': return parse_array(p, depth);
        case '"': return parse_string(p);
        case 't': return parse_literal(p, "true");
        case 'f': return parse_literal(p, "false");
        case 'n': return parse_literal(p, "null");
        default:
            if (c == '-' || (c >= '0' && c <= '9')) return parse_number(p);
            fail_at(p, p->i, c < 0 ? "unexpected end of input" : "unexpected character");
            return -1;
    }
}

int json_validate(const char *src, size_t len, int allow_comments, json_error_t *err) {
    if (err) memset(err, 0, sizeof(*err));
    if (!src) {
        if (err) snprintf(err->message, sizeof err->message, "null input");
        return -1;
    }
    jp_t p = { src, len, 0, allow_comments, err, 0 };

    /* UTF-8 BOM */
    if (len >= 3 && (unsigned char)src[0] == 0xEF &&
        (unsigned char)src[1] == 0xBB && (unsigned char)src[2] == 0xBF) p.i = 3;

    if (skip_ws(&p) != 0) return -1;
    if (p.i >= p.len) { fail_at(&p, p.i, "empty input"); return -1; }
    if (parse_value(&p, 0) != 0) return -1;
    if (skip_ws(&p) != 0) return -1;
    if (p.i != p.len) { fail_at(&p, p.i, "trailing data after JSON value"); return -1; }
    return 0;
}
