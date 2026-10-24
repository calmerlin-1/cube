/** handshake.h — internal handshake message builders/parsers.
 *  Not public API. Used by state_13.c. */

#ifndef CRISPTLS_HANDSHAKE_H
#define CRISPTLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include "crisptls_policy.h"

/* Handshake message types */
#define HS_CLIENT_HELLO          1
#define HS_SERVER_HELLO          2
#define HS_NEW_SESSION_TICKET    4
#define HS_ENCRYPTED_EXTENSIONS  8
#define HS_CERTIFICATE          11
#define HS_CERTIFICATE_VERIFY   15
#define HS_FINISHED             20
#define HS_KEY_UPDATE           24

/* --- clienthello.c --- */
int clienthello_build(const crisptls_policy_t *p,
                      const char *hostname,
                      const uint8_t random[32],
                      const uint8_t x25519_pub[32],
                      uint8_t *out, size_t cap, size_t *written);
size_t hs_write_header(uint8_t type, uint32_t len, uint8_t out[4]);

/* --- serverhello.c --- */
typedef struct {
    uint16_t legacy_version;
    uint8_t  random[32];
    uint8_t  session_id_len;
    const uint8_t *session_id;
    uint16_t cipher_suite;
    uint8_t  compression;
    const uint8_t *extensions;
    size_t   extensions_len;
    uint16_t selected_version;
    uint16_t selected_group;
    const uint8_t *server_pubkey;
    size_t   server_pubkey_len;
} server_hello_t;

int serverhello_parse(const uint8_t *buf, size_t len, server_hello_t *out);

/* --- certificate.c --- */
typedef struct {
    const uint8_t *data;
    size_t         len;
} cert_der_t;

typedef struct {
    cert_der_t *certs;
    size_t      count;
    size_t      capacity;
} cert_chain_t;

int certificate_parse(const uint8_t *buf, size_t len, cert_chain_t *out);

/** Parse CertificateVerify message (RFC 8446 §4.4.3).
 *  Returns 0 on success. sig points into buf. */
int certificate_verify_parse(const uint8_t *buf, size_t len,
                              uint16_t *sig_scheme,
                              const uint8_t **sig, size_t *sig_len);

/* --- keyexchange.c --- */
int keyexchange_x25519_keypair(uint8_t priv[32], uint8_t pub[32]);
int keyexchange_x25519_shared(uint8_t shared[32],
                              const uint8_t priv[32],
                              const uint8_t peer_pub[32]);

/* --- finished_13.c --- */
/** Compute TLS 1.3 Finished verify_data.
 *  hash_len = 32 (SHA-256) or 48 (SHA-384).
 *  out must be at least hash_len bytes. */
int finished_13_compute(const uint8_t base_key[48],
                        const uint8_t transcript_hash[48],
                        size_t hash_len,
                        uint8_t *out);

/** Verify server Finished. hash_len = 32 or 48. */
int finished_13_verify(const uint8_t base_key[48],
                       const uint8_t transcript_hash[48],
                       size_t hash_len,
                       const uint8_t *received, size_t received_len);

/* --- finished_12.c (TLS 1.2 path, not implemented) --- */
int finished_12_compute(const uint8_t master_secret[48],
                        const uint8_t *handshake_hash, size_t hash_len,
                        uint8_t out[12]);

#endif
