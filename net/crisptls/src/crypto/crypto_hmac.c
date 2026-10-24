/* crypto_hmac.c — native HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869).
 * No OpenSSL. Public API matches crypto.h.
 *
 * Note: only SHA-256 HMAC + HKDF are implemented here. SHA-384 HMAC
 * stays in crypto_libcrypto.c for now (rarely used, added later).
 * This covers the TLS 1.3 default ciphersuite
 * TLS_AES_128_GCM_SHA256. */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

/* Exposed from crypto_sha.c — needed for streaming SHA-256 inside HMAC.
 * Rather than expose sha256_ctx_t (internal to crypto_sha.c), we
 * construct the HMAC input concatenation into a stack buffer and call
 * ct_sha256 once. Max key 64 bytes, max msg 255+32+1 = 288 bytes for
 * HKDF. For arbitrary msg, HMAC input is 64 + mlen. We chunk it. */

static void make_pad(uint8_t out[64], const uint8_t *key, size_t klen, uint8_t pad) {
    uint8_t k[64];
    memset(k, 0, 64);
    if (klen > 64) {
        ct_sha256(key, klen, k);
    } else {
        memcpy(k, key, klen);
    }
    for (int i = 0; i < 64; i++) out[i] = k[i] ^ pad;
}

int ct_hmac_sha256(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen,
                   uint8_t out[32]) {
    uint8_t ipad[64], opad[64];
    make_pad(ipad, key, klen, 0x36);
    make_pad(opad, key, klen, 0x5c);

    /* inner = SHA256(ipad || msg). To avoid copying arbitrary msg,
     * we hash incrementally — but crypto_sha.c only exposes the
     * one-shot API. So we allocate a temp buffer for the concatenation.
     * mlen in TLS is small (transcript hashes, HKDF blocks, finished
     * verify) — bounded to a few hundred bytes. */
    enum { STACK_MAX = 512 };
    uint8_t stackbuf[STACK_MAX];
    uint8_t *concat = stackbuf;
    size_t total = 64 + mlen;

    if (total > STACK_MAX) {
        /* Very rare. Heap fallback. */
        extern void *malloc(size_t);
        extern void  free(void *);
        concat = (uint8_t *)malloc(total);
        if (!concat) return -1;
    }

    memcpy(concat, ipad, 64);
    if (mlen) memcpy(concat + 64, msg, mlen);

    uint8_t inner[32];
    ct_sha256(concat, total, inner);

    if (total > STACK_MAX) {
        extern void free(void *);
        free(concat);
    }

    /* out = SHA256(opad || inner) */
    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner, 32);
    ct_sha256(outer, 96, out);
    return 0;
}

/* ---- HKDF (RFC 5869) ---- */

int ct_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[32]) {
    return ct_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int ct_hkdf_expand_sha256(const uint8_t prk[32],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len) {
    uint8_t t[32];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        uint8_t block[32 + 255 + 1];
        size_t bl = 0;
        if (t_len) { memcpy(block + bl, t, t_len); bl += t_len; }
        size_t take = info_len > 255 ? 255 : info_len;
        if (take) { memcpy(block + bl, info, take); bl += take; }
        block[bl++] = counter;
        if (ct_hmac_sha256(prk, 32, block, bl, t) != 0) return -1;
        t_len = 32;
        size_t copy = (out_len - done < 32) ? (out_len - done) : 32;
        memcpy(out + done, t, copy);
        done += copy;
        counter++;
    }
    return 0;
}

int ct_hkdf_expand_label_sha256(const uint8_t secret[32],
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len) {
    uint8_t info[2 + 1 + 6 + 255 + 1 + 255];
    size_t w = 0;
    info[w++] = (uint8_t)(out_len >> 8);
    info[w++] = (uint8_t)(out_len & 0xFF);
    const char *prefix = "tls13 ";
    size_t plen = 6;
    size_t llen = strlen(label);
    if (llen > 200) llen = 200;
    info[w++] = (uint8_t)(plen + llen);
    memcpy(info + w, prefix, plen); w += plen;
    memcpy(info + w, label, llen);  w += llen;
    size_t take = context_len > 255 ? 255 : context_len;
    info[w++] = (uint8_t)take;
    if (take) { memcpy(info + w, context, take); w += take; }
    return ct_hkdf_expand_sha256(secret, info, w, out, out_len);
}

/* ---- SHA-384 variants (TLS_AES_256_GCM_SHA384) — deferred.
 * These stay in crypto_libcrypto.c for now.
 *   ct_hmac_sha384
 *   ct_hkdf_extract_sha384
 *   ct_hkdf_expand_sha384
 *   ct_hkdf_expand_label_sha384
 * ---- */

/* ---- SHA-384 variants (RFC 4231 HMAC, RFC 5869 HKDF) ---- */

static void make_pad384(uint8_t out[128], const uint8_t *key, size_t klen, uint8_t pad) {
    uint8_t k[128];
    memset(k, 0, 128);
    if (klen > 128) {
        ct_sha384(key, klen, k);
    } else {
        memcpy(k, key, klen);
    }
    for (int i = 0; i < 128; i++) out[i] = k[i] ^ pad;
}

int ct_hmac_sha384(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen,
                   uint8_t out[48]) {
    uint8_t ipad[128], opad[128];
    make_pad384(ipad, key, klen, 0x36);
    make_pad384(opad, key, klen, 0x5c);

    enum { STACK_MAX = 1024 };
    uint8_t stackbuf[STACK_MAX];
    uint8_t *concat = stackbuf;
    size_t total = 128 + mlen;

    if (total > STACK_MAX) {
        extern void *malloc(size_t);
        concat = (uint8_t *)malloc(total);
        if (!concat) return -1;
    }

    memcpy(concat, ipad, 128);
    if (mlen) memcpy(concat + 128, msg, mlen);

    uint8_t inner[48];
    ct_sha384(concat, total, inner);

    if (total > STACK_MAX) {
        extern void free(void *);
        free(concat);
    }

    uint8_t outer[128 + 48];
    memcpy(outer, opad, 128);
    memcpy(outer + 128, inner, 48);
    ct_sha384(outer, 176, out);
    return 0;
}

int ct_hkdf_extract_sha384(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[48]) {
    return ct_hmac_sha384(salt, salt_len, ikm, ikm_len, prk);
}

int ct_hkdf_expand_sha384(const uint8_t prk[48],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len) {
    uint8_t t[48];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        uint8_t block[48 + 255 + 1];
        size_t bl = 0;
        if (t_len) { memcpy(block + bl, t, t_len); bl += t_len; }
        size_t take = info_len > 255 ? 255 : info_len;
        if (take) { memcpy(block + bl, info, take); bl += take; }
        block[bl++] = counter;
        if (ct_hmac_sha384(prk, 48, block, bl, t) != 0) return -1;
        t_len = 48;
        size_t copy = (out_len - done < 48) ? (out_len - done) : 48;
        memcpy(out + done, t, copy);
        done += copy;
        counter++;
    }
    return 0;
}

int ct_hkdf_expand_label_sha384(const uint8_t secret[48],
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len) {
    uint8_t info[2 + 1 + 6 + 255 + 1 + 255];
    size_t w = 0;
    info[w++] = (uint8_t)(out_len >> 8);
    info[w++] = (uint8_t)(out_len & 0xFF);
    const char *prefix = "tls13 ";
    size_t plen = 6;
    size_t llen = strlen(label);
    if (llen > 200) llen = 200;
    info[w++] = (uint8_t)(plen + llen);
    memcpy(info + w, prefix, plen); w += plen;
    memcpy(info + w, label, llen);  w += llen;
    size_t take = context_len > 255 ? 255 : context_len;
    info[w++] = (uint8_t)take;
    if (take) { memcpy(info + w, context, take); w += take; }
    return ct_hkdf_expand_sha384(secret, info, w, out, out_len);
}
