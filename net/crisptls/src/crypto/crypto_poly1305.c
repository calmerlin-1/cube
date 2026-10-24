/* crypto_poly1305.c — Poly1305 MAC (RFC 8439 §2.5). */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t r[5];   /* 5 × 26-bit limbs */
    uint32_t h[5];
    uint8_t  pad[16];
    uint8_t  buf[16];
    size_t   buf_len;
} poly1305_ctx;

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void poly_init(poly1305_ctx *c, const uint8_t key[32]) {
    /* r = key[0..15] with clamps, h = 0, pad = key[16..31] */
    c->r[0] = ( load32_le(key + 0)                    ) & 0x3ffffff;
    c->r[1] = ( load32_le(key + 3) >> 2               ) & 0x3ffff03;
    c->r[2] = ( load32_le(key + 6) >> 4               ) & 0x3ffc0ff;
    c->r[3] = ( load32_le(key + 9) >> 6               ) & 0x3f03fff;
    c->r[4] = ( load32_le(key + 12) >> 8              ) & 0x00fffff;
    c->h[0] = c->h[1] = c->h[2] = c->h[3] = c->h[4] = 0;
    memcpy(c->pad, key + 16, 16);
    c->buf_len = 0;
}

static void poly_blocks(poly1305_ctx *c, const uint8_t *m, size_t bytes, uint32_t hibit) {
    uint32_t r0 = c->r[0], r1 = c->r[1], r2 = c->r[2], r3 = c->r[3], r4 = c->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4];

    while (bytes >= 16) {
        h0 += ( load32_le(m + 0)                    ) & 0x3ffffff;
        h1 += ( load32_le(m + 3) >> 2               ) & 0x3ffffff;
        h2 += ( load32_le(m + 6) >> 4               ) & 0x3ffffff;
        h3 += ( load32_le(m + 9) >> 6               ) & 0x3ffffff;
        h4 += ( load32_le(m + 12) >> 8              ) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c0 = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c0; uint32_t c1 = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c1; uint32_t c2 = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c2; uint32_t c3 = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c3; uint32_t c4 = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c4 * 5; uint32_t c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        m += 16; bytes -= 16;
    }
    c->h[0] = h0; c->h[1] = h1; c->h[2] = h2; c->h[3] = h3; c->h[4] = h4;
}

static void poly_update(poly1305_ctx *c, const uint8_t *m, size_t len) {
    if (c->buf_len) {
        size_t want = 16 - c->buf_len;
        size_t take = (len < want) ? len : want;
        memcpy(c->buf + c->buf_len, m, take);
        c->buf_len += take;
        m += take; len -= take;
        if (c->buf_len == 16) {
            poly_blocks(c, c->buf, 16, 1u << 24);
            c->buf_len = 0;
        }
    }
    if (len >= 16) {
        size_t blocks = len / 16;
        poly_blocks(c, m, blocks * 16, 1u << 24);
        m += blocks * 16; len -= blocks * 16;
    }
    if (len) {
        memcpy(c->buf, m, len);
        c->buf_len = len;
    }
}

static void poly_final(poly1305_ctx *c, uint8_t tag[16]) {
    if (c->buf_len) {
        c->buf[c->buf_len] = 1;
        memset(c->buf + c->buf_len + 1, 0, 15 - c->buf_len);
        poly_blocks(c, c->buf, 16, 0);
    }

    uint32_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4];
    uint32_t c0 = h1 >> 26; h1 &= 0x3ffffff; h2 += c0;
    c0 = h2 >> 26; h2 &= 0x3ffffff; h3 += c0;
    c0 = h3 >> 26; h3 &= 0x3ffffff; h4 += c0;
    c0 = h4 >> 26; h4 &= 0x3ffffff; h0 += c0 * 5;
    c0 = h0 >> 26; h0 &= 0x3ffffff; h1 += c0;

    /* g = h + 5 - 2^130; if g < 0 keep h else g */
    uint32_t g0 = h0 + 5; c0 = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c0; c0 = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c0; c0 = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c0; c0 = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c0 - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h mod 2^128, then add pad */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    uint64_t f;
    f = (uint64_t)h0 + load32_le(c->pad + 0); h0 = (uint32_t)f;
    f = (uint64_t)h1 + load32_le(c->pad + 4) + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + load32_le(c->pad + 8) + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + load32_le(c->pad + 12) + (f >> 32); h3 = (uint32_t)f;

    store32_le(tag + 0, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);
}

/* Public: one-shot Poly1305 */
int ct_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]) {
    poly1305_ctx c;
    poly_init(&c, key);
    poly_update(&c, msg, len);
    poly_final(&c, tag);
    return CT_OK;
}
