/** record_cbc.h — CBC record protection for SSL 3.0 / TLS 1.0 / 1.1 / 1.2.
 *
 *  MAC-then-encrypt (all versions) and encrypt-then-MAC (RFC 7366, TLS only).
 *  Decrypt path: constant-time padding validation, uniform failure, and
 *  hash-compression-count balancing for the MAC (Lucky13 class). EtM is immune
 *  by construction — prefer it whenever the server offers it.
 *
 *  Self-contained: does not touch the AEAD functions in record.h. */
#ifndef CRISPTLS_RECORD_CBC_H
#define CRISPTLS_RECORD_CBC_H

#include <stddef.h>
#include <stdint.h>
#include "crypto_legacy.h"

/* Worst-case bytes added to a plaintext fragment (IV + MAC + padding). */
#define TLS_CBC_MAX_OVERHEAD 96
/* RFC 5246 §6.2.3: 2^14 + 2048. NOTE: record.h's TLS_MAX_CIPHERTEXT (16640) and the
 * session rx_buf (18432) are smaller; widen them when wiring CBC in. */
#define TLS_CBC_MAX_BODY     (16384 + 2048)

typedef struct {
    uint16_t   version;        /* negotiated: 0x0300 .. 0x0303 */
    ctl_cbc_t  cipher;
    ctl_hash_t mac_hash;
    int        etm;            /* RFC 7366 encrypt-then-MAC */
    size_t     block, key_len, mac_len;
    uint8_t    key[32];
    uint8_t    mac_key[48];
    uint8_t    iv[16];         /* chaining IV (SSL3 / TLS1.0 only) */
    uint64_t   seq;
} tls_cbc_state_t;

/** implicit_iv: required for version <= 0x0301 (block-size bytes), ignored otherwise. */
int  tls_cbc_state_init(tls_cbc_state_t *st, uint16_t version, ctl_cbc_t cipher,
                        ctl_hash_t mac_hash, const uint8_t *key, const uint8_t *mac_key,
                        const uint8_t *implicit_iv, int etm);
void tls_cbc_state_wipe(tls_cbc_state_t *st);

/** TLS 1.0 only: caller should send the first app-data byte in its own record (BEAST, 1/n-1). */
int  tls_cbc_needs_split(const tls_cbc_state_t *st);

/** Protect one fragment. rec_version = version field written in the record header.
 *  out gets [explicit IV][ciphertext][MAC if EtM]. Returns body length or -1. */
int tls_record_encrypt_cbc(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                           const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap);

/** Same, with a caller-chosen explicit IV (TLS 1.1+). For known-answer tests only:
 *  production code must use tls_record_encrypt_cbc (random IV). */
int tls_record_encrypt_cbc_with_iv(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                                   const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap,
                                   const uint8_t *fixed_iv);

/** Unprotect one record body. Returns plaintext length or -1 (single uniform error:
 *  the caller must send bad_record_mac for every failure, never anything finer). */
int tls_record_decrypt_cbc(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                           const uint8_t *body, size_t body_len, uint8_t *out, size_t out_cap);

/* ---- suite metadata for the CBC family ---- */
typedef enum { TLS_KX_RSA = 1, TLS_KX_DHE_RSA, TLS_KX_ECDHE_RSA, TLS_KX_ECDHE_ECDSA } tls_kx_t;
typedef struct {
    uint16_t   suite;
    ctl_cbc_t  cipher;
    ctl_hash_t mac;
    tls_kx_t   kx;
    uint16_t   min_version;    /* lowest protocol version the suite is defined for */
    int        is_3des;        /* Sweet32: gate on policy allow_3des */
} tls_cbc_suite_t;

const tls_cbc_suite_t *tls_cbc_suite_lookup(uint16_t suite);   /* NULL if not a CBC suite */

/** Legacy stub kept so existing references still link. Always -1. */
int tls_record_encrypt_cbc_stub(void);

#endif
