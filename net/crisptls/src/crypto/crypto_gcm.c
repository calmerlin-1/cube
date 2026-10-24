/* crypto_gcm.c — full AES-GCM (NIST SP 800-38D §7).

Uses ct_ghash + ct_aes128ctr / ct_aes256ctr from crypto_gcm_ghash.c.
Public API: ct_aes128gcm_encrypt/decrypt, ct_aes256gcm_encrypt/decrypt.

IV is always 96 bits (12 bytes) for TLS 1.3 and QUIC — the case
where J0 = IV || 0^31 || 1 and no GHASH-of-IV step is needed. */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

extern int ct_aes128ctr(const uint8_t key[16], const uint8_t icb[16],
                        const uint8_t *in, uint8_t *out, size_t len);
extern int ct_aes256ctr(const uint8_t key[32], const uint8_t icb[16],
                        const uint8_t *in, uint8_t *out, size_t len);
extern void ct_ghash(const uint8_t H[16],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t out[16]);

extern int ct_aes128_ecb_encrypt_block(const uint8_t key[16],
                                       const uint8_t in[16], uint8_t out[16]);
extern int ct_aes256_ecb_encrypt_block(const uint8_t key[32],
                                       const uint8_t in[16], uint8_t out[16]);

/* Build J0 for 96-bit IV: J0 = IV || 0x00000001 */
static void make_j0(const uint8_t iv[12], uint8_t J0[16]) {
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
}

/* Build the counter block for the first data block:
 * inc32(J0) — increment the last 32 bits. */
static void inc32(const uint8_t in[16], uint8_t out[16]) {
    memcpy(out, in, 16);
    for (int i = 15; i >= 12; i--) {
        if (++out[i] != 0) break;
    }
}

/* Common encrypt — works for 128 or 256 bit key. */
static int gcm_encrypt(const uint8_t *key, int keylen,
                       const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, uint8_t tag[16]) {
    /* H = AES_K(0^128) */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    if (keylen == 16) {
        if (ct_aes128_ecb_encrypt_block(key, zero, H) != CT_OK) return CT_ERR_CRYPTO;
    } else {
        if (ct_aes256_ecb_encrypt_block(key, zero, H) != CT_OK) return CT_ERR_CRYPTO;
    }

    /* J0 = nonce || 0^31 || 1 */
    uint8_t J0[16];
    make_j0(nonce, J0);

    /* C = AES-CTR(inc32(J0), P) */
    uint8_t icb[16];
    inc32(J0, icb);
    if (pt_len) {
        if (keylen == 16) {
            if (ct_aes128ctr(key, icb, pt, ct, pt_len) != CT_OK) return CT_ERR_CRYPTO;
        } else {
            if (ct_aes256ctr(key, icb, pt, ct, pt_len) != CT_OK) return CT_ERR_CRYPTO;
        }
    }

    /* S = GHASH(H, AAD, C) */
    uint8_t S[16];
    ct_ghash(H, aad, aad_len, ct, pt_len, S);

    /* tag = AES_K(J0) ^ S */
    uint8_t ekj0[16];
    if (keylen == 16) {
        if (ct_aes128_ecb_encrypt_block(key, J0, ekj0) != CT_OK) return CT_ERR_CRYPTO;
    } else {
        if (ct_aes256_ecb_encrypt_block(key, J0, ekj0) != CT_OK) return CT_ERR_CRYPTO;
    }
    for (int i = 0; i < 16; i++) tag[i] = ekj0[i] ^ S[i];
    return CT_OK;
}

/* Common decrypt. */
static int gcm_decrypt(const uint8_t *key, int keylen,
                       const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[16],
                       uint8_t *pt) {
    uint8_t zero[16] = {0};
    uint8_t H[16];
    if (keylen == 16) {
        if (ct_aes128_ecb_encrypt_block(key, zero, H) != CT_OK) return CT_ERR_CRYPTO;
    } else {
        if (ct_aes256_ecb_encrypt_block(key, zero, H) != CT_OK) return CT_ERR_CRYPTO;
    }

    uint8_t J0[16];
    make_j0(nonce, J0);

    uint8_t S[16];
    ct_ghash(H, aad, aad_len, ct, ct_len, S);

    uint8_t ekj0[16];
    if (keylen == 16) {
        if (ct_aes128_ecb_encrypt_block(key, J0, ekj0) != CT_OK) return CT_ERR_CRYPTO;
    } else {
        if (ct_aes256_ecb_encrypt_block(key, J0, ekj0) != CT_OK) return CT_ERR_CRYPTO;
    }

    /* Verify tag constant-time */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)((ekj0[i] ^ S[i]) ^ tag[i]);
    if (diff != 0) return CT_ERR_VERIFY;

    /* Decrypt */
    uint8_t icb[16];
    inc32(J0, icb);
    if (ct_len) {
        if (keylen == 16) {
            if (ct_aes128ctr(key, icb, ct, pt, ct_len) != CT_OK) return CT_ERR_CRYPTO;
        } else {
            if (ct_aes256ctr(key, icb, ct, pt, ct_len) != CT_OK) return CT_ERR_CRYPTO;
        }
    }
    return CT_OK;
}

int ct_aes128gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[16]) {
    return gcm_encrypt(key, 16, nonce, aad, aad_len, pt, pt_len, ct, tag);
}

int ct_aes128gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[16],
                         uint8_t *pt) {
    return gcm_decrypt(key, 16, nonce, aad, aad_len, ct, ct_len, tag, pt);
}

int ct_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[16]) {
    return gcm_encrypt(key, 32, nonce, aad, aad_len, pt, pt_len, ct, tag);
}

int ct_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[16],
                         uint8_t *pt) {
    return gcm_decrypt(key, 32, nonce, aad, aad_len, ct, ct_len, tag, pt);
}
