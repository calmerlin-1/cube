/* crypto_gcm_ghash.c — AES-CTR and GHASH primitives for GCM.
 * NIST SP 800-38D Algorithm 1: bit 0 = MSB of byte 0 (leftmost bit). */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

extern int ct_aes128_ecb_encrypt_block(const uint8_t key[16],
                                       const uint8_t in[16], uint8_t out[16]);
extern int ct_aes256_ecb_encrypt_block(const uint8_t key[32],
                                       const uint8_t in[16], uint8_t out[16]);

int ct_aes128ctr(const uint8_t key[16], const uint8_t icb[16],
                 const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ctr[16];
    memcpy(ctr, icb, 16);
    size_t done = 0;
    while (done < len) {
        uint8_t ks[16];
        if (ct_aes128_ecb_encrypt_block(key, ctr, ks) != CT_OK) return CT_ERR_CRYPTO;
        size_t take = (len - done < 16) ? (len - done) : 16;
        for (size_t i = 0; i < take; i++) out[done + i] = in[done + i] ^ ks[i];
        done += take;
        for (int i = 15; i >= 12; i--) {
            if (++ctr[i] != 0) break;
        }
    }
    return CT_OK;
}

int ct_aes256ctr(const uint8_t key[32], const uint8_t icb[16],
                 const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ctr[16];
    memcpy(ctr, icb, 16);
    size_t done = 0;
    while (done < len) {
        uint8_t ks[16];
        if (ct_aes256_ecb_encrypt_block(key, ctr, ks) != CT_OK) return CT_ERR_CRYPTO;
        size_t take = (len - done < 16) ? (len - done) : 16;
        for (size_t i = 0; i < take; i++) out[done + i] = in[done + i] ^ ks[i];
        done += take;
        for (int i = 15; i >= 12; i--) {
            if (++ctr[i] != 0) break;
        }
    }
    return CT_OK;
}

/* NIST SP 800-38D Algorithm 1: X *= H.
 * Bit i of X: bit 0 = MSB of byte 0. So bit i = byte (i/8), bit (7 - i%8).
 * V >> 1: integer right shift in big-endian byte array = each byte shifts
 * right, carry from PREVIOUS byte's LSB into current byte's MSB.
 * R = 0xe1 at byte 0 (XORed when LSB of V[15] was set). */
static void ghash_mul(uint8_t X[16], const uint8_t H[16]) {
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, H, 16);

    for (int i = 0; i < 128; i++) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) {
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        }
        V[0] = (uint8_t)(V[0] >> 1);
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(X, Z, 16);
}

void ct_ghash(const uint8_t H[16],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *ct, size_t ct_len,
              uint8_t out[16]) {
    uint8_t Y[16] = {0};

    for (size_t i = 0; i < aad_len; i += 16) {
        size_t take = (aad_len - i < 16) ? (aad_len - i) : 16;
        for (size_t b = 0; b < take; b++) Y[b] ^= aad[i + b];
        ghash_mul(Y, H);
    }

    for (size_t i = 0; i < ct_len; i += 16) {
        size_t take = (ct_len - i < 16) ? (ct_len - i) : 16;
        for (size_t b = 0; b < take; b++) Y[b] ^= ct[i + b];
        ghash_mul(Y, H);
    }

    uint64_t abits = (uint64_t)aad_len * 8;
    uint64_t cbits = (uint64_t)ct_len * 8;
    for (int b = 0; b < 8; b++) Y[b]     ^= (uint8_t)(abits >> (56 - b*8));
    for (int b = 0; b < 8; b++) Y[8 + b] ^= (uint8_t)(cbits >> (56 - b*8));
    ghash_mul(Y, H);

    memcpy(out, Y, 16);
}
