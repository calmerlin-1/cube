/** finished_13.c — TLS 1.3 Finished (RFC 8446 §4.4.4).
 *  Parameterized on hash_len: 32 (SHA-256) or 48 (SHA-384). */

#include "handshake.h"
#include "crypto.h"
#include <string.h>

static int derive_finished_key(size_t hl, const uint8_t *base_key, uint8_t *out) {
    if (hl == 48)
        return ct_hkdf_expand_label_sha384(base_key, "finished",
                                            (const uint8_t *)"", 0, out, 48);
    return ct_hkdf_expand_label_sha256(base_key, "finished",
                                        (const uint8_t *)"", 0, out, 32);
}

int finished_13_compute(const uint8_t base_key[48],
                        const uint8_t transcript_hash[48],
                        size_t hash_len,
                        uint8_t *out) {
    if (!base_key || !transcript_hash || !out) return -1;
    if (hash_len != 32 && hash_len != 48) return -1;

    uint8_t finished_key[48];
    if (derive_finished_key(hash_len, base_key, finished_key) != CT_OK) return -1;

    int rc;
    if (hash_len == 48)
        rc = ct_hmac_sha384(finished_key, 48, transcript_hash, 48, out);
    else
        rc = ct_hmac_sha256(finished_key, 32, transcript_hash, 32, out);

    volatile uint8_t *p = finished_key;
    for (size_t i = 0; i < 48; i++) p[i] = 0;
    return rc == CT_OK ? 0 : -1;
}

int finished_13_verify(const uint8_t base_key[48],
                       const uint8_t transcript_hash[48],
                       size_t hash_len,
                       const uint8_t *received, size_t received_len) {
    if (!received || received_len != hash_len) return -1;

    uint8_t expected[48];
    if (finished_13_compute(base_key, transcript_hash, hash_len, expected) != 0)
        return -1;

    int ok = ct_memeq(expected, received, hash_len);
    volatile uint8_t *p = expected;
    for (size_t i = 0; i < 48; i++) p[i] = 0;
    return ok ? 0 : -1;
}
