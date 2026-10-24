/** keyschedule_legacy.h — PRFs, master secret, key block and Finished for
 *  SSL 3.0 / TLS 1.0 / 1.1 and the SHA-384 flavour of TLS 1.2.
 *  Additive: existing prf_12_sha256 / keyschedule_12_derive are untouched. */
#ifndef CRISPTLS_KEYSCHEDULE_LEGACY_H
#define CRISPTLS_KEYSCHEDULE_LEGACY_H

#include <stddef.h>
#include <stdint.h>
#include "keyschedule.h"
#include "crypto_legacy.h"

#define TLS_V_SSL3  0x0300
#define TLS_V_10    0x0301
#define TLS_V_11    0x0302
#define TLS_V_12    0x0303

/** Hash a TLS 1.2 suite uses for its PRF / Finished (SHA-384 or SHA-256). */
ctl_hash_t tls12_suite_prf_hash(uint16_t suite);

/* Raw PRFs */
int prf_tls12(ctl_hash_t h, const uint8_t *secret, size_t slen, const char *label,
              const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen);
int prf_tls10(const uint8_t *secret, size_t slen, const char *label,
              const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen);
/** SSL 3.0 expansion: MD5(secret||SHA1('A'||secret||r1||r2)) || MD5(secret||SHA1('BB'||...)) ...
 *  master secret: r1=client_random r2=server_random; key block: r1=server_random r2=client_random. */
int prf_ssl3(const uint8_t *secret, size_t slen, const uint8_t r1[32], const uint8_t r2[32],
             uint8_t *out, size_t outlen);

/** Version-dispatched PRF for TLS 1.0-1.2 (prf_hash only used for 1.2). -1 for SSL3. */
int tls_prf(uint16_t version, ctl_hash_t prf_hash, const uint8_t *secret, size_t slen,
            const char *label, const uint8_t *seed, size_t seedlen,
            uint8_t *out, size_t outlen);

int tls_master_secret(uint16_t version, ctl_hash_t prf_hash,
                      const uint8_t *pms, size_t pms_len,
                      const uint8_t client_random[32], const uint8_t server_random[32],
                      uint8_t out[48]);
/** RFC 7627 extended master secret (TLS 1.0-1.2). session_hash = transcript hash up to and
 *  including ClientKeyExchange (MD5||SHA1 for <=1.1, suite hash for 1.2). */
int tls_master_secret_ems(uint16_t version, ctl_hash_t prf_hash,
                          const uint8_t *pms, size_t pms_len,
                          const uint8_t *session_hash, size_t session_hash_len,
                          uint8_t out[48]);

/** Key block -> keyschedule_12_t, for every version SSL3..TLS1.2 and either PRF hash.
 *  CBC: TLS1.1+ has iv_len = 0 (explicit IV on the wire); SSL3/TLS1.0 iv_len = block size. */
int keyschedule_legacy_derive(uint16_t version, ctl_hash_t prf_hash,
                              const uint8_t master[48],
                              const uint8_t client_random[32], const uint8_t server_random[32],
                              size_t mac_len, size_t key_len, size_t iv_len,
                              keyschedule_12_t *out);

/** Finished verify_data for TLS 1.0-1.2 (12 bytes).
 *  <=1.1: hs_hash = MD5(hs)||SHA1(hs) (36 bytes). 1.2: hs_hash = suite hash(hs). */
int tls_finished_verify(uint16_t version, ctl_hash_t prf_hash, const uint8_t master[48],
                        int is_client, const uint8_t *hs_hash, size_t hs_hash_len,
                        uint8_t out[12]);
/** SSL 3.0 Finished (MD5 16 || SHA1 20 = 36 bytes) over the raw handshake messages
 *  (excluding the Finished being built). */
int ssl3_finished(const uint8_t master[48], int is_client,
                  const uint8_t *hs_msgs, size_t hs_len, uint8_t out[36]);

#endif
