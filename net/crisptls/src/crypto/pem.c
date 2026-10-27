/* pem.c — PEM (RFC 7468) base64 envelope decoder. No OpenSSL. */
#include "pem.h"
#include <string.h>
#include <ctype.h>

/* Base64 decode table: 0..63 for valid chars, 0xFF for invalid. */
static const uint8_t B64[256] = {
    ['A']=0,  ['B']=1,  ['C']=2,  ['D']=3,  ['E']=4,  ['F']=5,  ['G']=6,  ['H']=7,
    ['I']=8,  ['J']=9,  ['K']=10, ['L']=11, ['M']=12, ['N']=13, ['O']=14, ['P']=15,
    ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25,
    ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31, ['g']=32, ['h']=33,
    ['i']=34, ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39, ['o']=40, ['p']=41,
    ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47, ['w']=48, ['x']=49,
    ['y']=50, ['z']=51,
    ['0']=52, ['1']=53, ['2']=54, ['3']=55, ['4']=56, ['5']=57, ['6']=58, ['7']=59,
    ['8']=60, ['9']=61, ['+']=62, ['/']=63,
};

ct_pem_err ct_pem_b64_decode(const char *in, size_t in_len,
                             uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!in || !out) return CT_PEM_ERR_ARGS;
    size_t w = 0;
    uint32_t acc = 0;
    int bits = 0;
    int pad = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') { pad++; continue; }
        if (isspace(c)) continue;
        if (c >= 128) return CT_PEM_ERR_BAD_BASE64;
        uint8_t v = B64[c];
        /* 0xFF sentinel for chars not in table. char 'A' is 0, so we need
         * a separate check: any char not explicitly set is 0 by default.
         * Fix: check alphabet membership directly. */
        int valid = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/');
        if (!valid) return CT_PEM_ERR_BAD_BASE64;
        (void)v;
        acc = (acc << 6) | ((c >= 'A' && c <= 'Z') ? (uint32_t)(c - 'A')
                          : (c >= 'a' && c <= 'z') ? (uint32_t)(c - 'a' + 26)
                          : (c >= '0' && c <= '9') ? (uint32_t)(c - '0' + 52)
                          : (c == '+') ? 62u : 63u);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= out_cap) return CT_PEM_ERR_OVERFLOW;
            out[w++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    if (pad > 2) return CT_PEM_ERR_BAD_BASE64;
    if (out_len) *out_len = w;
    return CT_PEM_OK;
}

/* Find "-----BEGIN <label>-----" in buf. If `label` is NULL, any label
 * matches. Returns pointer past the marker, or NULL. */
static const char *find_begin(const char *buf, size_t len, const char *label) {
    const char *p = buf;
    const char *end = buf + len;
    while (p + 5 <= end) {
        if (memcmp(p, "-----", 5) != 0) { p++; continue; }
        /* expect "-----BEGIN LABEL-----" */
        if (p + 11 > end) return NULL;
        if (memcmp(p + 5, "BEGIN ", 6) != 0) { p++; continue; }
        const char *lbl = p + 11;
        const char *lbl_end = lbl;
        while (lbl_end < end && *lbl_end != '-') lbl_end++;
        if (lbl_end + 5 > end) return NULL;
        if (memcmp(lbl_end, "-----", 5) != 0) { p++; continue; }
        size_t lbl_len = (size_t)(lbl_end - lbl);
        if (label) {
            size_t want = strlen(label);
            if (want != lbl_len || memcmp(lbl, label, want) != 0) { p++; continue; }
        }
        return lbl_end + 5;
    }
    return NULL;
}

/* Find "-----END <label>-----" in buf. Returns pointer past it, or NULL. */
static const char *find_end(const char *buf, size_t len, const char *label) {
    const char *p = buf;
    const char *end = buf + len;
    while (p + 5 <= end) {
        if (memcmp(p, "-----", 5) != 0) { p++; continue; }
        if (p + 9 > end) return NULL;
        if (memcmp(p + 5, "END ", 4) != 0) { p++; continue; }
        const char *lbl = p + 9;
        const char *lbl_end = lbl;
        while (lbl_end < end && *lbl_end != '-') lbl_end++;
        if (lbl_end + 5 > end) return NULL;
        if (memcmp(lbl_end, "-----", 5) != 0) { p++; continue; }
        if (label) {
            size_t want = strlen(label);
            size_t have = (size_t)(lbl_end - lbl);
            if (want != have || memcmp(lbl, label, want) != 0) { p++; continue; }
        }
        return p;
    }
    return NULL;
}

ct_pem_err ct_pem_decode(const char *in, size_t in_len,
                         const char *label,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         size_t *consumed) {
    if (!in || in_len == 0 || !out) return CT_PEM_ERR_ARGS;
    const char *body = find_begin(in, in_len, label);
    if (!body) return CT_PEM_ERR_NO_BLOCK;
    const char *body_end = find_end(body, (size_t)((in + in_len) - body), label);
    if (!body_end) return CT_PEM_ERR_NO_BLOCK;

    ct_pem_err r = ct_pem_b64_decode(body, (size_t)(body_end - body),
                                     out, out_cap, out_len);
    if (consumed) *consumed = (size_t)(body_end - in);
    return r;
}

const char *ct_pem_err_name(ct_pem_err e) {
    switch (e) {
        case CT_PEM_OK:              return "ok";
        case CT_PEM_ERR_ARGS:        return "args";
        case CT_PEM_ERR_NO_BLOCK:    return "no-block";
        case CT_PEM_ERR_BAD_BASE64:  return "bad-base64";
        case CT_PEM_ERR_OVERFLOW:    return "overflow";
    }
    return "unknown";
}
