/** record_encrypt.c — AEAD encryption for TLS records (1.2 AEAD + 1.3).
 * Nonce construction and AAD differ by version. */

#include "record.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>

/** TLS 1.3 nonce = static_iv XOR seqnum (last 8 bytes). */
static void build_nonce_13(const uint8_t static_iv[12], uint64_t seq,
                           uint8_t out[12]) {
    memcpy(out, static_iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

/** TLS 1.3 AAD = 5-byte record header with ciphertext length. */
static void build_aad_13(uint8_t type, uint16_t version, uint16_t ct_len,
                         uint8_t out[5]) {
    tls_record_write_header(type, version, ct_len, out);
}

/** Encrypt one record in place: plaintext -> ciphertext + tag appended.
 * buf must have room for pt_len + 16 bytes. Returns ct_len or -1. */
int tls_record_encrypt_13_aes128gcm(const uint8_t key[16],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     uint8_t *buf, size_t pt_len) {
    uint8_t inner[TLS_MAX_PLAINTEXT + 1];
    if (pt_len + 1 > sizeof(inner)) return -1;
    memcpy(inner, buf, pt_len);
    inner[pt_len] = content_type;   /* TLS 1.3 puts content type inside */

    uint8_t nonce[12];
    build_nonce_13(static_iv, seq, nonce);

    uint8_t aad[5];
    build_aad_13(TLS_CT_APPLICATION_DATA, version,
                 (uint16_t)(pt_len + 1 + 16), aad);

    uint8_t tag[16];
    int r = ct_aes128gcm_encrypt(key, nonce, aad, 5,
                                  inner, pt_len + 1,
                                  buf, tag);
    if (r != CT_OK) return -1;
    memcpy(buf + pt_len + 1, tag, 16);
    if (g_crisptls_trace) fprintf(stderr, "[_13enc] r=%d buf0=%02x%02x%02x%02x inner0=%02x%02x%02x%02x\n",
            r, buf[0], buf[1], buf[2], buf[3], inner[0], inner[1], inner[2], inner[3]);
    return (int)(pt_len + 1 + 16);
}

int tls_record_encrypt_13_chacha20(const uint8_t key[32],
                                    const uint8_t static_iv[12],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    uint8_t *buf, size_t pt_len) {
    uint8_t inner[TLS_MAX_PLAINTEXT + 1];
    if (pt_len + 1 > sizeof(inner)) return -1;
    memcpy(inner, buf, pt_len);
    inner[pt_len] = content_type;

    uint8_t nonce[12];
    build_nonce_13(static_iv, seq, nonce);

    uint8_t aad[5];
    build_aad_13(TLS_CT_APPLICATION_DATA, version,
                 (uint16_t)(pt_len + 1 + 16), aad);

    uint8_t tag[16];
    int r = ct_chacha20poly1305_encrypt(key, nonce, aad, 5,
                                         inner, pt_len + 1,
                                         buf, tag);
    if (r != CT_OK) return -1;
    memcpy(buf + pt_len + 1, tag, 16);
    return (int)(pt_len + 1 + 16);
}

/** AES-256-GCM variant (cipher 0x1302). Same wire layout, 32-byte key. */
int tls_record_encrypt_13_aes256gcm(const uint8_t key[32],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     uint8_t *buf, size_t pt_len) {
    uint8_t inner[TLS_MAX_PLAINTEXT + 1];
    if (pt_len + 1 > sizeof(inner)) return -1;
    memcpy(inner, buf, pt_len);
    inner[pt_len] = content_type;

    uint8_t nonce[12];
    build_nonce_13(static_iv, seq, nonce);

    uint8_t aad[5];
    build_aad_13(TLS_CT_APPLICATION_DATA, version,
                 (uint16_t)(pt_len + 1 + 16), aad);

    uint8_t tag[16];
    int r = ct_aes256gcm_encrypt(key, nonce, aad, 5,
                                  inner, pt_len + 1,
                                  buf, tag);
    if (r != CT_OK) return -1;
    memcpy(buf + pt_len + 1, tag, 16);
    return (int)(pt_len + 1 + 16);
}


/* =========================================================
 * TLS 1.2 AEAD encryption
 *
 * Wire format for 1.2 GCM/ChaCha:
 *   [8-byte explicit_nonce][ciphertext][16-byte tag]
 * AAD = seq_num(8) || type(1) || version(2) || length(2)
 * Nonce = fixed_iv (4 or 12 bytes) || explicit_nonce
 * ========================================================= */

int tls_record_encrypt_12_aes128gcm(const uint8_t key[16],
                                     const uint8_t fixed_iv[4],
                                     const uint8_t explicit_nonce[8],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     const uint8_t *pt, size_t pt_len,
                                     uint8_t *out, size_t out_cap)
{
    if (!key || !fixed_iv || !explicit_nonce || !pt || !out) return -1;
    if (8 + pt_len + 16 > out_cap) return -1;

    uint8_t nonce[12];
    memcpy(nonce, fixed_iv, 4);
    memcpy(nonce + 4, explicit_nonce, 8);

    uint8_t aad[13];
    for (int i = 0; i < 8; i++)
        aad[7 - i] = (uint8_t)(seq >> (8 * i));
    aad[8]  = content_type;
    aad[9]  = (uint8_t)(version >> 8);
    aad[10] = (uint8_t)(version);
    aad[11] = (uint8_t)(pt_len >> 8);
    aad[12] = (uint8_t)(pt_len);

    uint8_t tag[16];
    int r = ct_aes128gcm_encrypt(key, nonce, aad, 13, pt, pt_len, out + 8, tag);
    if (r != CT_OK) return -1;
    memcpy(out, explicit_nonce, 8);
    memcpy(out + 8 + pt_len, tag, 16);
    return (int)(8 + pt_len + 16);
}

int tls_record_encrypt_12_chacha20(const uint8_t key[32],
                                    const uint8_t fixed_iv[12],
                                    const uint8_t explicit_nonce[8],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *out, size_t out_cap)
{
    if (!key || !fixed_iv || !explicit_nonce || !pt || !out) return -1;
    if (8 + pt_len + 16 > out_cap) return -1;

    /* RFC 7905: ChaCha20-Poly1305 in 1.2 uses a 12-byte nonce = fixed_iv XOR
     * (0x00000000 || seq_num) — NOT iv||explicit. Different from AES-GCM. */
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
    int r = ct_chacha20poly1305_encrypt(key, nonce, aad, 13, pt, pt_len, out + 8, tag);
    if (r != CT_OK) return -1;
    memcpy(out, explicit_nonce, 8);
    memcpy(out + 8 + pt_len, tag, 16);
    return (int)(8 + pt_len + 16);
}
