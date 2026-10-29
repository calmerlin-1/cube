/* url_percent.c — percent decode/encode + UTF-8 validation. */

#include "url_percent.h"

/* Return hex value of c, or -1. */
static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Uppercase hex digit. */
static char hexdig(unsigned v) {
    return (char)(v < 10 ? '0' + v : 'A' + (v - 10));
}

/* Is this byte UTF-8 continuation (10xxxxxx)? */
static int is_cont(unsigned char c) { return (c & 0xC0) == 0x80; }

/* Validate one UTF-8 sequence starting at s[0]. Returns length 1..4, or 0 invalid. */
static size_t utf8_seq_len(const unsigned char *s, size_t n) {
    if (n == 0) return 0;
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    if (c < 0xC2) return 0;
    if (c < 0xE0) return (n >= 2 && is_cont(s[1])) ? 2 : 0;
    if (c < 0xF0) {
        if (n < 3 || !is_cont(s[1]) || !is_cont(s[2])) return 0;
        if (c == 0xE0 && s[1] < 0xA0) return 0;
        if (c == 0xED && s[1] >= 0xA0) return 0;
        return 3;
    }
    if (c < 0xF5) {
        if (n < 4 || !is_cont(s[1]) || !is_cont(s[2]) || !is_cont(s[3])) return 0;
        if (c == 0xF0 && s[1] < 0x90) return 0;
        if (c == 0xF4 && s[1] >= 0x90) return 0;
        return 4;
    }
    return 0;
}

int url_utf8_valid(const char *s, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        size_t l = utf8_seq_len(p + i, n - i);
        if (l == 0) return 0;
        i += l;
    }
    return 1;
}

int url_percent_decode(const char *in, size_t inlen,
                       char *out, size_t outcap, size_t *outlen,
                       int plus_to_space) {
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '%' && i + 2 < inlen) {
            int hi = hexval((unsigned char)in[i+1]);
            int lo = hexval((unsigned char)in[i+2]);
            if (hi >= 0 && lo >= 0) {
                if (w >= outcap) { if (outlen) *outlen = w; return URLP_ERR_OVERFLOW; }
                out[w++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        if (plus_to_space && c == '+') c = ' ';
        if (w >= outcap) { if (outlen) *outlen = w; return URLP_ERR_OVERFLOW; }
        out[w++] = (char)c;
    }
    if (outlen) *outlen = w;
    return URLP_OK;
}

/* One of: unreserved (ALPHA DIGIT - . _ ~). */
static int is_unreserved(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_' || c == '~';
}

/* Encode one byte as %XX. */
static int emit_pct(char *out, size_t cap, size_t *w, unsigned char c) {
    if (*w + 3 > cap) return URLP_ERR_OVERFLOW;
    out[(*w)++] = '%';
    out[(*w)++] = hexdig(c >> 4);
    out[(*w)++] = hexdig(c & 0xF);
    return URLP_OK;
}

/* Path-safe characters beyond unreserved. */
static int path_safe(unsigned char c) {
    if (is_unreserved(c)) return 1;
    switch (c) {
        case '/': case ':': case '@':
        case '!': case '$': case '&': case '\'':
        case '(': case ')': case '*': case '+':
        case ',': case ';': case '=':
            return 1;
    }
    return 0;
}

/* Query-value safe characters. */
static int query_safe(unsigned char c) {
    if (path_safe(c)) return 1;
    switch (c) { case '?': return 1; }
    return 0;
}

int url_percent_encode_path(const char *in, size_t inlen,
                            char *out, size_t outcap, size_t *outlen) {
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (path_safe(c)) {
            if (w >= outcap) return URLP_ERR_OVERFLOW;
            out[w++] = (char)c;
        } else {
            int r = emit_pct(out, outcap, &w, c);
            if (r) return r;
        }
    }
    if (outlen) *outlen = w;
    return URLP_OK;
}

int url_percent_encode_query(const char *in, size_t inlen,
                             char *out, size_t outcap, size_t *outlen) {
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (query_safe(c)) {
            if (w >= outcap) return URLP_ERR_OVERFLOW;
            out[w++] = (char)c;
        } else {
            int r = emit_pct(out, outcap, &w, c);
            if (r) return r;
        }
    }
    if (outlen) *outlen = w;
    return URLP_OK;
}

int url_percent_encode_strict(const char *in, size_t inlen,
                              char *out, size_t outcap, size_t *outlen) {
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (is_unreserved(c)) {
            if (w >= outcap) return URLP_ERR_OVERFLOW;
            out[w++] = (char)c;
        } else {
            int r = emit_pct(out, outcap, &w, c);
            if (r) return r;
        }
    }
    if (outlen) *outlen = w;
    return URLP_OK;
}
