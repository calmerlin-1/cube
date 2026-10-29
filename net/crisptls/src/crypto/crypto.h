/** crypto.h — primitives only. Hash, AEAD, ECDH, sign. No protocol.
 * Binds to libsodium (default). Every call here is math, not TLS. */

#ifndef CRISPTLS_CRYPTO_H
#define CRISPTLS_CRYPTO_H

/* Runtime trace flag (defined in api/crisptls.c). Set via crisptls_set_trace. */
extern int g_crisptls_trace;

#include <stddef.h>
#include <stdint.h>

/** Random */
int ct_random(uint8_t *out, size_t n);

/** Hash */
int ct_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int ct_sha384(const uint8_t *data, size_t len, uint8_t out[48]);
int ct_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/** HMAC */
int ct_hmac_sha256(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen,
                   uint8_t out[32]);
int ct_hmac_sha384(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen,
                   uint8_t out[48]);

/** HKDF (RFC 5869) */
int ct_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[32]);
int ct_hkdf_expand_sha256(const uint8_t prk[32],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len);
int ct_hkdf_expand_label_sha256(const uint8_t secret[32],
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len);

int ct_hkdf_extract_sha384(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[48]);
int ct_hkdf_expand_sha384(const uint8_t prk[48],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len);
int ct_hkdf_expand_label_sha384(const uint8_t secret[48],
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len);

/** AEAD: AES-GCM */
int ct_aes128gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[16]);
int ct_aes128gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[16],
                         uint8_t *pt);
int ct_aes256gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[16]);
int ct_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[16],
                         uint8_t *pt);

/** AEAD: ChaCha20-Poly1305 */
int ct_chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t *ct, uint8_t tag[16]);
int ct_chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                const uint8_t tag[16],
                                uint8_t *pt);

/** ECDH */
int ct_x25519_keypair(uint8_t priv[32], uint8_t pub[32]);

/* P-256 ECDH (secp256r1) — used by TLS 1.2 ECDHE */
int ct_p256_keypair(uint8_t priv[32], uint8_t pub_uncompressed[65]);
int ct_p256_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t peer_pub[65]);
int ct_x25519(uint8_t shared[32], const uint8_t priv[32], const uint8_t peer[32]);

/** Signature verify */
int ct_verify_rsa_pss_sha256(const uint8_t *pub_der, size_t pub_der_len,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len);

/** RSA PKCS#1 v1.5 SHA-256 verify (RFC 8017 §8.2.2). Native. */
int ct_verify_rsa_pkcs1_sha256(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);
int ct_verify_rsa_pkcs1_sha384(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);
int ct_verify_rsa_pkcs1_sha512(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);
int ct_verify_ecdsa_p256_sha256(const uint8_t *pub_der, size_t pub_der_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);
int ct_verify_ecdsa_p384_sha384(const uint8_t *pub_der, size_t pub_der_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);
int ct_verify_ed25519(const uint8_t pub[32],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[64]);

/** Extract SubjectPublicKeyInfo (DER) from an X.509 certificate.
 *  Caller must free *spki_out with ct_free_spki(). */
int ct_cert_get_spki(const uint8_t *cert_der, size_t cert_der_len,
                     const uint8_t **spki_out, size_t *spki_len_out);
void ct_free_spki(const uint8_t *spki);

/** MD5 — needed for JA3 fingerprinting (not for crypto). */
int ct_md5(const uint8_t *data, size_t len, uint8_t out[16]);

/** Constant-time compare */
int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n);

/** Single AES-ECB block encryption (16 bytes in, 16 bytes out).
 *  Used by QUIC header protection (RFC 9001 §5.4.1). */
int ct_aes128_ecb_encrypt_block(const uint8_t key[16],
                                const uint8_t in[16], uint8_t out[16]);
int ct_aes256_ecb_encrypt_block(const uint8_t key[32],
                                const uint8_t in[16], uint8_t out[16]);

/** Single ChaCha20 block (RFC 8439 §2.3.2), counter = 0.
 *  `nonce` is 12 bytes. Writes 64 bytes to out.
 *  Used by QUIC header protection (RFC 9001 §5.4.4). */
int ct_chacha20_block_64(const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t out[64]);

/** ChaCha20 keystream with caller-specified counter. Used by QUIC HP. */
int ct_chacha20_keystream(const uint8_t key[32], uint32_t counter,
                          const uint8_t nonce[12],
                          uint8_t *out, size_t out_len);

/** Return codes */
#define CT_OK            0
#define CT_ERR_ARGS     -1
#define CT_ERR_CRYPTO   -2
#define CT_ERR_VERIFY   -3

#endif

/* ---- Streaming hash API (exposed for TLS 1.2 multipart hashing) ----
 * Use _init / _update (repeatable) / _final. Same output as the one-shot
 * ct_shaXXX / ct_md5 functions. All contexts are caller-owned. */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} ct_sha256_ctx_t;

typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t  buf[128];
    size_t   buflen;
} ct_sha512_ctx_t;

typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t  buf[128];
    size_t   buflen;
} ct_sha384_ctx_t;

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} ct_sha1_ctx_t;

typedef struct {
    uint32_t state[4];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} ct_md5_ctx_t;

void ct_sha1_init  (ct_sha1_ctx_t *c);
void ct_sha1_update(ct_sha1_ctx_t *c, const uint8_t *data, size_t len);
void ct_sha1_final (ct_sha1_ctx_t *c, uint8_t out[20]);
int  ct_sha1       (const uint8_t *data, size_t len, uint8_t out[20]);

void ct_sha256_init  (ct_sha256_ctx_t *c);
void ct_sha256_update(ct_sha256_ctx_t *c, const uint8_t *data, size_t len);
void ct_sha256_final (ct_sha256_ctx_t *c, uint8_t out[32]);

void ct_sha384_init  (ct_sha384_ctx_t *c);
void ct_sha384_update(ct_sha384_ctx_t *c, const uint8_t *data, size_t len);
void ct_sha384_final (ct_sha384_ctx_t *c, uint8_t out[48]);

void ct_sha512_init  (ct_sha512_ctx_t *c);
void ct_sha512_update(ct_sha512_ctx_t *c, const uint8_t *data, size_t len);
void ct_sha512_final (ct_sha512_ctx_t *c, uint8_t out[64]);

void ct_md5_init  (ct_md5_ctx_t *c);
void ct_md5_update(ct_md5_ctx_t *c, const uint8_t *data, size_t len);
void ct_md5_final (ct_md5_ctx_t *c, uint8_t out[16]);

/* ---- AES-CBC (NIST SP 800-38A §6.2) ----
 * No padding — callers pass len = multiple of 16. in == out allowed.
 * `iv` is copied before use, caller retains ownership. */

int ct_aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                          const uint8_t *in, uint8_t *out, size_t len);
int ct_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                          const uint8_t *in, uint8_t *out, size_t len);
int ct_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t *in, uint8_t *out, size_t len);
int ct_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t *in, uint8_t *out, size_t len);
