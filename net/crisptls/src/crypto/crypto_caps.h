/** crypto_caps.h — cache of what this CPU/device does fast. */

#ifndef CRISPTLS_CRYPTO_CAPS_H
#define CRISPTLS_CRYPTO_CAPS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    /* CPU feature bits (raw hwcap + our interpretation) */
    unsigned long hwcap;
    int      has_aes;
    int      has_pmull;
    int      has_sha1_hw;
    int      has_sha2_hw;
    int      has_crc32;

    /* measured throughput, MB/s */
    double   aes128gcm_mbps;
    double   aes256gcm_mbps;
    double   chacha20_mbps;
    double   sha256_mbps;
    double   sha384_mbps;
    double   hmac_sha256_mbps;

    /* measured ops/s */
    double   x25519_ops_per_sec;

    /* derived: preference order for AEAD */
    int      prefer_aes_gcm;    /* 1 = AES-GCM > ChaCha */
    int      prefer_sha256;     /* 1 = SHA-256 > SHA-384 where both fit */

    /* metadata */
    uint64_t probed_at_ns;
    uint32_t probe_duration_ms;
    int      valid;
} crisptls_crypto_caps_t;

/** Return cached caps, probing or loading from disk if needed.
 * Safe to call repeatedly — probes once per process. */
const crisptls_crypto_caps_t *crypto_caps_get(void);

/** Force re-probe (ignores cache). */
void crypto_caps_refresh(void);

/** Where the cache file lives.
 *  Default: net/crisptls/cache/crypto_caps.txt (relative to CWD). */
void crypto_caps_set_path(const char *path);

/** Serialize to a file. Returns 0 on success. */
int crypto_caps_save(const crisptls_crypto_caps_t *caps, const char *path);

/** Load from file. Returns 0 on success. */
int crypto_caps_load(crisptls_crypto_caps_t *caps, const char *path);

/** Run the probe. Fills `out`. Returns 0 on success. */
int crypto_caps_probe(crisptls_crypto_caps_t *out);

/** Human-readable summary. Caller-supplied buffer. */
void crypto_caps_format(const crisptls_crypto_caps_t *caps,
                        char *out, size_t cap);

#endif
