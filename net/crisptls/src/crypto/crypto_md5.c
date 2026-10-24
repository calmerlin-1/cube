/* crypto_md5.c — native MD5 (RFC 1321). Streaming + one-shot.
 * Used for JA3 fingerprinting and TLS 1.2 HMAC-MD5 (rare legacy suites). */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint8_t S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static void md5_block(uint32_t state[4], const uint8_t block[64]) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3*i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7*i) % 16; }
        uint32_t tmp = D;
        D = C; C = B; B = B + ROTL32(A + F + K[i] + M[g], S[i]); A = tmp;
    }
    state[0] += A; state[1] += B; state[2] += C; state[3] += D;
}

void ct_md5_init(ct_md5_ctx_t *c) {
    c->state[0]=0x67452301; c->state[1]=0xefcdab89;
    c->state[2]=0x98badcfe; c->state[3]=0x10325476;
    c->len = 0; c->buflen = 0;
}

void ct_md5_update(ct_md5_ctx_t *c, const uint8_t *d, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, d, take);
        c->buflen += take;
        d += take; n -= take;
        if (c->buflen == 64) {
            md5_block(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

void ct_md5_final(ct_md5_ctx_t *c, uint8_t out[16]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    ct_md5_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) ct_md5_update(c, &zero, 1);
    uint8_t len_le[8];
    for (int i = 0; i < 8; i++) len_le[i] = (uint8_t)(bits >> (8*i));
    ct_md5_update(c, len_le, 8);
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(c->state[i]);
        out[i*4+1] = (uint8_t)(c->state[i] >> 8);
        out[i*4+2] = (uint8_t)(c->state[i] >> 16);
        out[i*4+3] = (uint8_t)(c->state[i] >> 24);
    }
}

int ct_md5(const uint8_t *data, size_t len, uint8_t out[16]) {
    ct_md5_ctx_t c;
    ct_md5_init(&c);
    ct_md5_update(&c, data, len);
    ct_md5_final(&c, out);
    return CT_OK;
}
