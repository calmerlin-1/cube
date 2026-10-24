/* crypto_chacha20.c — ChaCha20 block function and keystream (RFC 8439 §2.3).
 * Used by QUIC header protection (RFC 9001 §5.4.4).
 * Full AEAD (ChaCha20-Poly1305) is Batch 5. */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7); \
} while (0)

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void chacha20_block(uint32_t out[16], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    static const uint32_t CONST[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t s[16];
    s[0]=CONST[0]; s[1]=CONST[1]; s[2]=CONST[2]; s[3]=CONST[3];
    for (int i = 0; i < 8; i++) s[4+i] = load32_le(key + 4*i);
    s[12] = counter;
    s[13] = load32_le(nonce + 0);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);

    uint32_t x[16];
    memcpy(x, s, sizeof x);
    for (int r = 0; r < 10; r++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + s[i];
}

int ct_chacha20_block_64(const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t out[64]) {
    uint32_t blk[16];
    chacha20_block(blk, key, 0, nonce);
    for (int i = 0; i < 16; i++) store32_le(out + 4*i, blk[i]);
    return CT_OK;
}

int ct_chacha20_keystream(const uint8_t key[32], uint32_t counter,
                          const uint8_t nonce[12],
                          uint8_t *out, size_t out_len) {
    uint32_t blk[16];
    uint8_t block[64];
    while (out_len > 0) {
        chacha20_block(blk, key, counter, nonce);
        for (int i = 0; i < 16; i++) store32_le(block + 4*i, blk[i]);
        size_t take = out_len < 64 ? out_len : 64;
        memcpy(out, block, take);
        out += take; out_len -= take;
        counter++;
    }
    return CT_OK;
}
