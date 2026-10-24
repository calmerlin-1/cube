/** quic_derive.c — QUIC key derivation (RFC 9001 §5). */

#include "crisptls_quic.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>

/* RFC 9001 §5.2: initial salt for QUIC v1.
 * = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
const uint8_t CRISPTLS_QUIC_V1_INITIAL_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

/* SHA-256-based derive: HKDF-Extract, then Expand-Label with QUIC labels. */

static int derive_initial_dir_sha256(const uint8_t *init_secret,
                                      const char *label,
                                      crisptls_quic_dir_keys_t *out) {
    /* client_initial_secret = HKDF-Expand-Label(initial_secret,
     *     "client in" or "server in", "", 32) */
    uint8_t secret[32];
    if (ct_hkdf_expand_label_sha256(init_secret, label,
                                     (const uint8_t *)"", 0,
                                     secret, 32) != CT_OK)
        return -1;

    /* packet_key = HKDF-Expand-Label(secret, "quic key", "", 16) */
    if (ct_hkdf_expand_label_sha256(secret, "quic key",
                                     (const uint8_t *)"", 0,
                                     out->packet_key, 16) != CT_OK)
        return -1;

    /* packet_iv = HKDF-Expand-Label(secret, "quic iv", "", 12) */
    if (ct_hkdf_expand_label_sha256(secret, "quic iv",
                                     (const uint8_t *)"", 0,
                                     out->packet_iv, 12) != CT_OK)
        return -1;

    /* hp_key = HKDF-Expand-Label(secret, "quic hp", "", 16) */
    if (ct_hkdf_expand_label_sha256(secret, "quic hp",
                                     (const uint8_t *)"", 0,
                                     out->hp_key, 16) != CT_OK)
        return -1;

    out->key_len = 16;
    return 0;
}

int crisptls_quic_derive_initial(const uint8_t *dcid, size_t dcid_len,
                                 uint32_t version,
                                 crisptls_quic_keys_t *out) {
    if (!dcid || !out) return -1;
    if (version != CRISPTLS_QUIC_V1) return -1;

    /* initial_secret = HKDF-Extract(initial_salt, dcid) */
    uint8_t initial_secret[32];
    if (ct_hkdf_extract_sha256(CRISPTLS_QUIC_V1_INITIAL_SALT, 20,
                                dcid, dcid_len,
                                initial_secret) != CT_OK)
        return -1;

    if (derive_initial_dir_sha256(initial_secret, "client in",
                                   &out->client) != 0) return -1;
    if (derive_initial_dir_sha256(initial_secret, "server in",
                                   &out->server) != 0) return -1;
    return 0;
}

/* ---- Key derivation from a TLS 1.3 traffic secret ---- */

int crisptls_quic_derive_dir(const uint8_t *secret, size_t secret_len,
                             uint16_t cipher_suite,
                             crisptls_quic_dir_keys_t *out) {
    if (!secret || !out) return -1;

    int    key_len;
    int    use_sha384 = 0;

    switch (cipher_suite) {
        case 0x1301: key_len = 16; break;                 /* AES-128-GCM-SHA256 */
        case 0x1302: key_len = 32; use_sha384 = 1; break; /* AES-256-GCM-SHA384 */
        case 0x1303: key_len = 32; break;                 /* ChaCha20-SHA256 */
        default: return -1;
    }

    if (use_sha384) {
        if (secret_len < 48) return -1;
        if (ct_hkdf_expand_label_sha384(secret, "quic key",
                                         (const uint8_t *)"", 0,
                                         out->packet_key, key_len) != CT_OK)
            return -1;
        if (ct_hkdf_expand_label_sha384(secret, "quic iv",
                                         (const uint8_t *)"", 0,
                                         out->packet_iv, 12) != CT_OK)
            return -1;
        if (ct_hkdf_expand_label_sha384(secret, "quic hp",
                                         (const uint8_t *)"", 0,
                                         out->hp_key, key_len) != CT_OK)
            return -1;
    } else {
        if (secret_len < 32) return -1;
        if (ct_hkdf_expand_label_sha256(secret, "quic key",
                                         (const uint8_t *)"", 0,
                                         out->packet_key, key_len) != CT_OK)
            return -1;
        if (ct_hkdf_expand_label_sha256(secret, "quic iv",
                                         (const uint8_t *)"", 0,
                                         out->packet_iv, 12) != CT_OK)
            return -1;
        if (ct_hkdf_expand_label_sha256(secret, "quic hp",
                                         (const uint8_t *)"", 0,
                                         out->hp_key, key_len) != CT_OK)
            return -1;
    }
    out->key_len = (size_t)key_len;
    return 0;
}
