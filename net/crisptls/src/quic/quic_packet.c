/** quic_packet.c — QUIC packet protection (RFC 9001 §5.3).
 *
 *   nonce = iv XOR packet_number (last 8 bytes, big-endian)
 *   AEAD-encrypt the payload with the packet key.
 */

#include "crisptls_quic.h"
#include "crypto.h"
#include <string.h>

/* Build the 12-byte nonce: copy iv, XOR last 8 bytes with packet_number
 * (big-endian). */
static void build_nonce(const uint8_t iv[12], uint64_t pn, uint8_t out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(pn >> (8 * i));
    }
}

int crisptls_quic_packet_encrypt(const crisptls_quic_dir_keys_t *keys,
                                 uint16_t cipher_suite,
                                 uint64_t packet_number,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, uint8_t tag[16]) {
    if (!keys || !ct || !tag) return -1;
    uint8_t nonce[12];
    build_nonce(keys->packet_iv, packet_number, nonce);

    switch (cipher_suite) {
        case 0x1301:
            return ct_aes128gcm_encrypt(keys->packet_key, nonce,
                                         aad, aad_len,
                                         pt, pt_len, ct, tag) == CT_OK ? 0 : -1;
        case 0x1302:
            return ct_aes256gcm_encrypt(keys->packet_key, nonce,
                                         aad, aad_len,
                                         pt, pt_len, ct, tag) == CT_OK ? 0 : -1;
        case 0x1303:
            return ct_chacha20poly1305_encrypt(keys->packet_key, nonce,
                                                aad, aad_len,
                                                pt, pt_len, ct, tag) == CT_OK ? 0 : -1;
        default:
            return -1;
    }
}

int crisptls_quic_packet_decrypt(const crisptls_quic_dir_keys_t *keys,
                                 uint16_t cipher_suite,
                                 uint64_t packet_number,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[16],
                                 uint8_t *pt) {
    if (!keys || !ct || !tag || !pt) return -1;
    uint8_t nonce[12];
    build_nonce(keys->packet_iv, packet_number, nonce);

    switch (cipher_suite) {
        case 0x1301:
            return ct_aes128gcm_decrypt(keys->packet_key, nonce,
                                         aad, aad_len,
                                         ct, ct_len, tag, pt) == CT_OK ? 0 : -1;
        case 0x1302:
            return ct_aes256gcm_decrypt(keys->packet_key, nonce,
                                         aad, aad_len,
                                         ct, ct_len, tag, pt) == CT_OK ? 0 : -1;
        case 0x1303:
            return ct_chacha20poly1305_decrypt(keys->packet_key, nonce,
                                                aad, aad_len,
                                                ct, ct_len, tag, pt) == CT_OK ? 0 : -1;
        default:
            return -1;
    }
}
