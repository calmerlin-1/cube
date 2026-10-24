/** keyschedule.h — key derivation for all TLS versions. */

#ifndef CRISPTLS_KEYSCHEDULE_H
#define CRISPTLS_KEYSCHEDULE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t client_write_mac[48];
    uint8_t server_write_mac[48];
    uint8_t client_write_key[32];
    uint8_t server_write_key[32];
    uint8_t client_write_iv[16];
    uint8_t server_write_iv[16];
    size_t  mac_len;
    size_t  key_len;
    size_t  iv_len;
} keyschedule_12_t;

typedef struct {
    /* Sized for the largest hash (SHA-384 = 48 bytes). For SHA-256
     * only the first 32 bytes are meaningful; hash_len tells which. */
    uint8_t client_handshake_traffic[48];
    uint8_t server_handshake_traffic[48];
    uint8_t client_application_traffic[48];
    uint8_t server_application_traffic[48];
    uint8_t exporter_master[48];
    uint8_t resumption_master[48];
    uint8_t master_secret[48];
    size_t  hash_len;   /* 32 for SHA-256, 48 for SHA-384 */
} keyschedule_13_t;

int prf_12_sha256(const uint8_t *secret, size_t secret_len,
                  const char *label,
                  const uint8_t *seed, size_t seed_len,
                  uint8_t *out, size_t out_len);

int keyschedule_12_derive(const uint8_t master_secret[48],
                          const uint8_t client_random[32],
                          const uint8_t server_random[32],
                          size_t mac_len, size_t key_len, size_t iv_len,
                          keyschedule_12_t *out);

/* hash_len = 32 (SHA-256) or 48 (SHA-384). Determines which HKDF to use. */
int keyschedule_13_derive_handshake(const uint8_t shared_secret[48],
                                    const uint8_t transcript_hash[48],
                                    size_t hash_len,
                                    keyschedule_13_t *out);

/* RFC 8446 §7.2: next application traffic secret.
 *   next = HKDF-Expand-Label(current, "traffic upd", "", hash_len)
 * Writes hash_len bytes to `out`. */
int keyschedule_13_traffic_update(const uint8_t current[48],
                                   size_t hash_len,
                                   uint8_t out[48]);

int keyschedule_13_derive_application(const uint8_t master_secret[48],
                                      const uint8_t transcript_hash[48],
                                      size_t hash_len,
                                      uint8_t client_app[48],
                                      uint8_t server_app[48]);

#endif
