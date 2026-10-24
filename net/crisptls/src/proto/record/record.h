/** record.h — TLS record layer. Framing plus AEAD encrypt/decrypt. */

#ifndef CRISPTLS_RECORD_H
#define CRISPTLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

/** Content types */
#define TLS_CT_CHANGE_CIPHER_SPEC  20
#define TLS_CT_ALERT               21
#define TLS_CT_HANDSHAKE           22
#define TLS_CT_APPLICATION_DATA    23

/** Header is 5 bytes: type(1) version(2) length(2) */
#define TLS_RECORD_HEADER_LEN 5
#define TLS_MAX_PLAINTEXT   16384
#define TLS_MAX_CIPHERTEXT  (TLS_MAX_PLAINTEXT + 256)

typedef struct {
    uint8_t  type;
    uint16_t version;
    uint16_t length;
    const uint8_t *payload;
} tls_record_t;

/** Parse one record header. Returns 5, 0 (need more), or -1 (error). */
int tls_record_parse_header(const uint8_t *buf, size_t len, tls_record_t *out);

/** Write a record header into 5-byte out. Returns 5. */
int tls_record_write_header(uint8_t type, uint16_t version, uint16_t length,
                            uint8_t out[5]);

/* ---- AEAD (TLS 1.3) ---- */

int tls_record_encrypt_13_aes128gcm(const uint8_t key[16],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     uint8_t *buf, size_t pt_len);

int tls_record_encrypt_13_aes256gcm(const uint8_t key[32],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     uint8_t *buf, size_t pt_len);

int tls_record_encrypt_13_chacha20(const uint8_t key[32],
                                    const uint8_t static_iv[12],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    uint8_t *buf, size_t pt_len);

int tls_record_decrypt_13_aes128gcm(const uint8_t key[16],
                                     const uint8_t static_iv[12],
                                     uint64_t seq,
                                     uint16_t version,
                                     const uint8_t *ct, size_t ct_len,
                                     uint8_t *out, uint8_t *content_type_out);

int tls_record_decrypt_13_chacha20(const uint8_t key[32],
                                    const uint8_t static_iv[12],
                                    uint64_t seq,
                                    uint16_t version,
                                    const uint8_t *ct, size_t ct_len,
                                    uint8_t *out, uint8_t *content_type_out);

/* ---- AEAD (TLS 1.2) ---- */

int tls_record_encrypt_12_aes128gcm(const uint8_t key[16],
                                     const uint8_t fixed_iv[4],
                                     const uint8_t explicit_nonce[8],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     const uint8_t *pt, size_t pt_len,
                                     uint8_t *out, size_t out_cap);

int tls_record_encrypt_12_chacha20(const uint8_t key[32],
                                    const uint8_t fixed_iv[12],
                                    const uint8_t explicit_nonce[8],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *out, size_t out_cap);

int tls_record_decrypt_12_aes128gcm(const uint8_t key[16],
                                     const uint8_t fixed_iv[4],
                                     uint64_t seq,
                                     uint8_t content_type,
                                     uint16_t version,
                                     const uint8_t *body, size_t body_len,
                                     uint8_t *out, size_t out_cap);

int tls_record_decrypt_12_chacha20(const uint8_t key[32],
                                    const uint8_t fixed_iv[12],
                                    uint64_t seq,
                                    uint8_t content_type,
                                    uint16_t version,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *out, size_t out_cap);

#endif
