/** keyschedule_13.c — TLS 1.3 key schedule (RFC 8446 §7.1).
 *  Parameterized on hash_len: 32 (SHA-256) or 48 (SHA-384). */

#include "keyschedule.h"
#include "crypto.h"
#include <string.h>

static int hkdf_extract(size_t hl,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t *out) {
    if (hl == 48) return ct_hkdf_extract_sha384(salt, salt_len, ikm, ikm_len, out);
    return ct_hkdf_extract_sha256(salt, salt_len, ikm, ikm_len, out);
}

static int hkdf_expand_label(size_t hl,
                              const uint8_t *secret,
                              const char *label,
                              const uint8_t *context, size_t context_len,
                              uint8_t *out, size_t out_len) {
    if (hl == 48) return ct_hkdf_expand_label_sha384(secret, label, context, context_len, out, out_len);
    return ct_hkdf_expand_label_sha256(secret, label, context, context_len, out, out_len);
}

static int empty_hash(size_t hl, uint8_t *out) {
    if (hl == 48) return ct_sha384((const uint8_t *)"", 0, out);
    return ct_sha256((const uint8_t *)"", 0, out);
}

static int derive_secret(size_t hl,
                         const uint8_t *secret,
                         const char *label,
                         const uint8_t *transcript_hash,
                         uint8_t *out) {
    return hkdf_expand_label(hl, secret, label, transcript_hash, hl, out, hl);
}

int keyschedule_13_derive_application(const uint8_t master_secret[48],
                                      const uint8_t transcript_hash[48],
                                      size_t hash_len,
                                      uint8_t client_app[48],
                                      uint8_t server_app[48]) {
    if (!master_secret || !transcript_hash || !client_app || !server_app) return -1;
    if (hash_len != 32 && hash_len != 48) return -1;

    if (derive_secret(hash_len, master_secret, "c ap traffic",
                      transcript_hash, client_app) != CT_OK) return -1;
    if (derive_secret(hash_len, master_secret, "s ap traffic",
                      transcript_hash, server_app) != CT_OK) return -1;
    return 0;
}

int keyschedule_13_derive_handshake(const uint8_t shared_secret[48],
                                    const uint8_t transcript_hash[48],
                                    size_t hash_len,
                                    keyschedule_13_t *out) {
    if (!shared_secret || !transcript_hash || !out) return -1;
    if (hash_len != 32 && hash_len != 48) return -1;
    memset(out, 0, sizeof(*out));
    out->hash_len = hash_len;

    uint8_t zeros[48] = {0};
    uint8_t eh[48];
    if (empty_hash(hash_len, eh) != CT_OK) return -1;

    /* early_secret = HKDF-Extract(salt=0^hl, IKM=0^hl) */
    uint8_t early_secret[48];
    if (hkdf_extract(hash_len, zeros, hash_len, zeros, hash_len,
                      early_secret) != CT_OK) return -1;

    /* derived = Derive-Secret(early_secret, "derived", Hash("")) */
    uint8_t derived[48];
    if (derive_secret(hash_len, early_secret, "derived", eh, derived) != CT_OK)
        return -1;

    /* handshake_secret = HKDF-Extract(derived, shared_secret)
     * shared_secret is always 32 bytes (X25519 output) — never hash_len. */
    uint8_t handshake_secret[48];
    if (hkdf_extract(hash_len, derived, hash_len, shared_secret, 32,
                      handshake_secret) != CT_OK) return -1;

    if (derive_secret(hash_len, handshake_secret, "c hs traffic",
                       transcript_hash, out->client_handshake_traffic) != CT_OK)
        return -1;
    if (derive_secret(hash_len, handshake_secret, "s hs traffic",
                       transcript_hash, out->server_handshake_traffic) != CT_OK)
        return -1;

    /* derived2 = Derive-Secret(handshake_secret, "derived", "") */
    uint8_t derived2[48];
    if (derive_secret(hash_len, handshake_secret, "derived", eh, derived2) != CT_OK)
        return -1;

    /* master_secret = HKDF-Extract(derived2, 0^hl) */
    uint8_t master_secret[48];
    if (hkdf_extract(hash_len, derived2, hash_len, zeros, hash_len,
                      master_secret) != CT_OK) return -1;

    memcpy(out->exporter_master, master_secret, hash_len);
    memcpy(out->resumption_master, master_secret, hash_len);
    memcpy(out->master_secret, master_secret, hash_len);
    return 0;
}

/** RFC 8446 §7.2 traffic secret update.
 *   next = HKDF-Expand-Label(current, "traffic upd", "", hash_len) */
int keyschedule_13_traffic_update(const uint8_t current[48],
                                   size_t hash_len,
                                   uint8_t out[48]) {
    if (!current || !out) return -1;
    if (hash_len != 32 && hash_len != 48) return -1;
    return hkdf_expand_label(hash_len, current, "traffic upd",
                              (const uint8_t *)"", 0, out, hash_len);
}

