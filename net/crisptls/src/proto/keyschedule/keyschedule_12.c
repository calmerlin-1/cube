/** keyschedule_12.c — TLS 1.2 PRF and key block derivation. */

#include "keyschedule.h"
#include "crypto.h"
#include <string.h>

/** P_hash (RFC 5246 §5). */
static int p_hash_sha256(const uint8_t *secret, size_t secret_len,
                         const uint8_t *seed, size_t seed_len,
                         uint8_t *out, size_t out_len) {
    uint8_t a[32];
    uint8_t tmp[32];
    /* A(1) = HMAC(secret, seed) */
    if (ct_hmac_sha256(secret, secret_len, seed, seed_len, a) != CT_OK) return -1;

    size_t done = 0;
    while (done < out_len) {
        /* tmp = HMAC(secret, A(i) || seed) */
        uint8_t buf[32 + 256];
        if (32 + seed_len > sizeof(buf)) return -1;
        memcpy(buf, a, 32);
        memcpy(buf + 32, seed, seed_len);
        if (ct_hmac_sha256(secret, secret_len, buf, 32 + seed_len, tmp) != CT_OK)
            return -1;
        size_t copy = out_len - done;
        if (copy > 32) copy = 32;
        memcpy(out + done, tmp, copy);
        done += copy;

        /* A(i+1) = HMAC(secret, A(i)) */
        if (ct_hmac_sha256(secret, secret_len, a, 32, a) != CT_OK) return -1;
    }
    return 0;
}

int prf_12_sha256(const uint8_t *secret, size_t secret_len,
                  const char *label,
                  const uint8_t *seed, size_t seed_len,
                  uint8_t *out, size_t out_len) {
    size_t label_len = strlen(label);
    uint8_t combined[256];
    if (label_len + seed_len > sizeof(combined)) return -1;
    memcpy(combined, label, label_len);
    memcpy(combined + label_len, seed, seed_len);
    return p_hash_sha256(secret, secret_len, combined, label_len + seed_len,
                         out, out_len);
}

int keyschedule_12_derive(const uint8_t master_secret[48],
                          const uint8_t client_random[32],
                          const uint8_t server_random[32],
                          size_t mac_len, size_t key_len, size_t iv_len,
                          keyschedule_12_t *out) {
    if (!master_secret || !out) return -1;

    uint8_t seed[64];
    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);

    size_t total = 2 * mac_len + 2 * key_len + 2 * iv_len;
    uint8_t block[256];
    if (total > sizeof(block)) return -1;

    int r = prf_12_sha256(master_secret, 48, "key expansion",
                          seed, 64, block, total);
    if (r != 0) return -1;

    out->mac_len = mac_len;
    out->key_len = key_len;
    out->iv_len = iv_len;

    size_t w = 0;
    memcpy(out->client_write_mac, block + w, mac_len); w += mac_len;
    memcpy(out->server_write_mac, block + w, mac_len); w += mac_len;
    memcpy(out->client_write_key, block + w, key_len); w += key_len;
    memcpy(out->server_write_key, block + w, key_len); w += key_len;
    memcpy(out->client_write_iv, block + w, iv_len); w += iv_len;
    memcpy(out->server_write_iv, block + w, iv_len); w += iv_len;
    return 0;
}
