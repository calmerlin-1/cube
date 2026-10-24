/** quic_hp.c — QUIC header protection (RFC 9001 §5.4).
 *
 * Given a 16-byte sample of ciphertext, derive a 5-byte mask and XOR
 * it into:
 *   - the low bits of the first byte (4 bits for long header, 5 for short)
 *   - the packet number bytes
 */

#include "crisptls_quic.h"
#include "crypto.h"
#include <string.h>

/* Produce the 5-byte mask. */
static int build_mask(const uint8_t *hp_key, uint16_t cipher_suite,
                      const uint8_t sample[16], uint8_t mask[5]) {
    switch (cipher_suite) {
        case 0x1301: {
            uint8_t block[16];
            if (ct_aes128_ecb_encrypt_block(hp_key, sample, block) != CT_OK)
                return -1;
            memcpy(mask, block, 5);
            return 0;
        }
        case 0x1302: {
            uint8_t block[16];
            if (ct_aes256_ecb_encrypt_block(hp_key, sample, block) != CT_OK)
                return -1;
            memcpy(mask, block, 5);
            return 0;
        }
        case 0x1303: {
            /* ChaCha20: counter = LE(sample[0..3]); nonce = sample[4..15] */
            uint32_t counter = (uint32_t)sample[0]
                             | ((uint32_t)sample[1] << 8)
                             | ((uint32_t)sample[2] << 16)
                             | ((uint32_t)sample[3] << 24);
            uint8_t nonce[12];
            memcpy(nonce, sample + 4, 12);

            /* OpenSSL's EVP_chacha20 IV layout is counter(4 LE) || nonce(12). */
            uint8_t iv[16];
            iv[0] = (uint8_t)counter;
            iv[1] = (uint8_t)(counter >> 8);
            iv[2] = (uint8_t)(counter >> 16);
            iv[3] = (uint8_t)(counter >> 24);
            memcpy(iv + 4, nonce, 12);

            /* Produce 64 bytes of keystream. First 5 bytes = mask. */
            uint8_t ks[64];
            /* We use ct_chacha20_block_64 but with counter from sample.
             * Our primitive hardcodes counter=0, so do it inline here. */
            extern int ct_chacha20_keystream(const uint8_t key[32],
                                              uint32_t counter,
                                              const uint8_t nonce[12],
                                              uint8_t *out, size_t out_len);
            if (ct_chacha20_keystream(hp_key, counter, nonce, ks, 64) != CT_OK)
                return -1;
            memcpy(mask, ks, 5);
            return 0;
        }
        default:
            return -1;
    }
}

int crisptls_quic_apply_hp(const uint8_t *hp_key,
                            uint16_t cipher_suite,
                            uint8_t *first_byte,
                            uint8_t *pn_bytes, size_t pn_len,
                            const uint8_t sample[16],
                            int long_header) {
    if (!hp_key || !first_byte || !pn_bytes) return -1;
    if (pn_len < 1 || pn_len > 4) return -1;

    uint8_t mask[5];
    if (build_mask(hp_key, cipher_suite, sample, mask) != 0) return -1;

    uint8_t fb_mask = long_header ? 0x0f : 0x1f;
    *first_byte ^= (mask[0] & fb_mask);
    for (size_t i = 0; i < pn_len; i++) {
        pn_bytes[i] ^= mask[1 + i];
    }
    return 0;
}

int crisptls_quic_remove_hp(const uint8_t *hp_key,
                             uint16_t cipher_suite,
                             uint8_t *first_byte,
                             uint8_t *pn_bytes, size_t pn_len,
                             const uint8_t sample[16],
                             int long_header) {
    /* XOR is symmetric — same operation. */
    return crisptls_quic_apply_hp(hp_key, cipher_suite,
                                    first_byte, pn_bytes, pn_len,
                                    sample, long_header);
}
