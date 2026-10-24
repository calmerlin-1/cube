/* crypto_chacha20poly1305.c — ChaCha20-Poly1305 AEAD (RFC 8439 §2.8). */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

extern int ct_chacha20_keystream(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12],
                                 uint8_t *out, size_t out_len);
extern int ct_chacha20_block_64(const uint8_t key[32], const uint8_t nonce[12],
                                uint8_t out[64]);
extern int ct_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len,
                       uint8_t tag[16]);

/* Build the Poly1305 input: AAD || pad16 || CT || pad16 || len(AAD)_64 || len(CT)_64.
 * We stream it through a stack buffer since TLS records are ≤16 KB. */

#define MAX_AEAD (16 * 1024 + 1024)
static uint8_t poly_buf[MAX_AEAD];

static size_t build_poly_input(const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               uint8_t *out) {
    size_t w = 0;
    if (aad_len) { memcpy(out + w, aad, aad_len); w += aad_len; }
    while (w % 16) out[w++] = 0;
    if (ct_len) { memcpy(out + w, ct, ct_len); w += ct_len; }
    while (w % 16) out[w++] = 0;
    uint64_t abytes = (uint64_t)aad_len;
    uint64_t cbytes = (uint64_t)ct_len;
    for (int i = 0; i < 8; i++) out[w++] = (uint8_t)(abytes >> (8*i));
    for (int i = 0; i < 8; i++) out[w++] = (uint8_t)(cbytes >> (8*i));
    return w;
}

int ct_chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t *ct, uint8_t tag[16]) {
    /* Poly key = first 32 bytes of ChaCha20 block 0 */
    uint8_t block0[64];
    if (ct_chacha20_block_64(key, nonce, block0) != CT_OK) return CT_ERR_CRYPTO;

    /* Ciphertext = ChaCha20 keystream starting at counter 1, XORed with PT */
    if (pt_len) {
        if (ct_chacha20_keystream(key, 1, nonce, ct, pt_len) != CT_OK) return CT_ERR_CRYPTO;
        for (size_t i = 0; i < pt_len; i++) ct[i] ^= pt[i];
    }

    size_t plen = build_poly_input(aad, aad_len, ct, pt_len, poly_buf);
    return ct_poly1305(block0, poly_buf, plen, tag);
}

int ct_chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                const uint8_t tag[16],
                                uint8_t *pt) {
    uint8_t block0[64];
    if (ct_chacha20_block_64(key, nonce, block0) != CT_OK) return CT_ERR_CRYPTO;

    size_t plen = build_poly_input(aad, aad_len, ct, ct_len, poly_buf);
    uint8_t expected[16];
    if (ct_poly1305(block0, poly_buf, plen, expected) != CT_OK) return CT_ERR_CRYPTO;

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff != 0) return CT_ERR_VERIFY;

    if (ct_len) {
        if (ct_chacha20_keystream(key, 1, nonce, pt, ct_len) != CT_OK) return CT_ERR_CRYPTO;
        for (size_t i = 0; i < ct_len; i++) pt[i] ^= ct[i];
    }
    return CT_OK;
}
