/** record_decrypt.c — AEAD decryption. Reverse of record_encrypt. */

#include "record.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>

#ifdef CT_DEBUG
  #define DBG_DEC(...) do { fprintf(stderr, "[dec] " __VA_ARGS__); fputc('\n', stderr); } while (0)
#else
  #define DBG_DEC(...) do {} while (0)
#endif

static void build_nonce_13(const uint8_t static_iv[12], uint64_t seq,
                           uint8_t out[12]) {
    memcpy(out, static_iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

/** Decrypt and strip TLS 1.3 inner content type.
 * Returns pt_len (buffer length after strip) or -1.
 * content_type_out receives the inner type. */
int tls_record_decrypt_13_aes128gcm(const uint8_t key[16],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint16_t version,
                                     const uint8_t *ct, size_t ct_len,
                                     uint8_t *out, uint8_t *content_type_out) {
    if (ct_len < 17) return -1;

    uint8_t nonce[12];
    build_nonce_13(static_iv, seq, nonce);

    uint8_t aad[5];
    tls_record_write_header(TLS_CT_APPLICATION_DATA, version,
                            (uint16_t)ct_len, aad);

    uint8_t tag[16];
    memcpy(tag, ct + ct_len - 16, 16);

    int r = ct_aes128gcm_decrypt(key, nonce, aad, 5,
                                  ct, ct_len - 16,
                                  tag, out);
    if (r != CT_OK) return -1;

    size_t inner_len = ct_len - 16;
    while (inner_len > 0 && out[inner_len - 1] == 0) inner_len--;   /* strip padding */
    if (inner_len == 0) return -1;
    if (content_type_out) *content_type_out = out[inner_len - 1];
    return (int)(inner_len - 1);
}

/** ChaCha20-Poly1305 variant. Same record structure, different AEAD. */
int tls_record_decrypt_13_chacha20(const uint8_t key[32],
                                    const uint8_t static_iv[12],
                                    uint64_t seq,
                                    uint16_t version,
                                    const uint8_t *ct, size_t ct_len,
                                    uint8_t *out, uint8_t *content_type_out) {
    if (ct_len < 17) return -1;

    uint8_t nonce[12];
    build_nonce_13(static_iv, seq, nonce);

    uint8_t aad[5];
    tls_record_write_header(TLS_CT_APPLICATION_DATA, version,
                            (uint16_t)ct_len, aad);

    uint8_t tag[16];
    memcpy(tag, ct + ct_len - 16, 16);

    int r = ct_chacha20poly1305_decrypt(key, nonce, aad, 5,
                                         ct, ct_len - 16,
                                         tag, out);
    if (r != CT_OK) return -1;

    size_t inner_len = ct_len - 16;
    while (inner_len > 0 && out[inner_len - 1] == 0) inner_len--;
    if (inner_len == 0) return -1;
    if (content_type_out) *content_type_out = out[inner_len - 1];
    return (int)(inner_len - 1);
}


/* TLS 1.2 AEAD decryption — reverse of encrypt_12 above. */

int tls_record_decrypt_12_aes128gcm(const uint8_t key[16],
                                     const uint8_t fixed_iv[4],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     const uint8_t *body, size_t body_len,
                                     uint8_t *out, size_t out_cap)
{
    if (!key || !fixed_iv || !body || !out) return -1;
    if (body_len < 8 + 16) return -1;
    size_t pt_len = body_len - 8 - 16;
    if (pt_len > out_cap) return -1;

    uint8_t nonce[12];
    memcpy(nonce, fixed_iv, 4);
    memcpy(nonce + 4, body, 8);

    uint8_t aad[13];
    for (int i = 0; i < 8; i++)
        aad[7 - i] = (uint8_t)(seq >> (8 * i));
    aad[8]  = content_type;
    aad[9]  = (uint8_t)(version >> 8);
    aad[10] = (uint8_t)(version);
    aad[11] = (uint8_t)(pt_len >> 8);
    aad[12] = (uint8_t)(pt_len);

    uint8_t tag[16];
    memcpy(tag, body + body_len - 16, 16);

    int r = ct_aes128gcm_decrypt(key, nonce, aad, 13,
                                  body + 8, pt_len, tag, out);
    if (r != CT_OK) return -1;
    return (int)pt_len;
}

int tls_record_decrypt_12_chacha20(const uint8_t key[32],
                                    const uint8_t fixed_iv[12],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *out, size_t out_cap)
{
    if (!key || !fixed_iv || !body || !out) return -1;
    if (body_len < 8 + 16) return -1;
    size_t pt_len = body_len - 8 - 16;
    if (pt_len > out_cap) return -1;

    uint8_t nonce[12];
    memcpy(nonce, fixed_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));

    uint8_t aad[13];
    for (int i = 0; i < 8; i++)
        aad[7 - i] = (uint8_t)(seq >> (8 * i));
    aad[8]  = content_type;
    aad[9]  = (uint8_t)(version >> 8);
    aad[10] = (uint8_t)(version);
    aad[11] = (uint8_t)(pt_len >> 8);
    aad[12] = (uint8_t)(pt_len);

    uint8_t tag[16];
    memcpy(tag, body + body_len - 16, 16);

    int r = ct_chacha20poly1305_decrypt(key, nonce, aad, 13,
                                         body + 8, pt_len, tag, out);
    if (r != CT_OK) return -1;
    return (int)pt_len;
}
