/** keyschedule_legacy.c — see keyschedule_legacy.h */
#include "keyschedule_legacy.h"
#include <string.h>

#define SEED_MAX 512

ctl_hash_t tls12_suite_prf_hash(uint16_t s) {
    switch (s) {
    case 0x009D: case 0x009F: case 0x00A3:
    case 0xC024: case 0xC028: case 0xC02C: case 0xC02E:
    case 0xC030: case 0xC032:
        return CTL_SHA384;
    }
    return CTL_SHA256;
}

static int build_seed(const char *label, const uint8_t *seed, size_t seedlen,
                      uint8_t *buf, size_t *n) {
    size_t ll = strlen(label);
    if (ll + seedlen > SEED_MAX) return -1;
    memcpy(buf, label, ll);
    if (seedlen) memcpy(buf + ll, seed, seedlen);
    *n = ll + seedlen;
    return 0;
}

/* RFC 5246 §5 P_hash; xor_into=1 XORs into out (used to combine MD5 and SHA-1 halves). */
static int p_hash(ctl_hash_t h, const uint8_t *secret, size_t slen,
                  const uint8_t *seed, size_t seedlen,
                  uint8_t *out, size_t outlen, int xor_into) {
    size_t hl = ctl_hash_len(h);
    uint8_t a[48], t[48];
    ctl_part_t ps = { seed, seedlen };
    if (ctl_hmac_parts(h, secret, slen, &ps, 1, a)) return -1;
    size_t done = 0;
    while (done < outlen) {
        ctl_part_t pp[2] = { { a, hl }, { seed, seedlen } };
        if (ctl_hmac_parts(h, secret, slen, pp, 2, t)) { ctl_wipe(a, 48); return -1; }
        size_t n = outlen - done < hl ? outlen - done : hl;
        for (size_t i = 0; i < n; i++)
            out[done + i] = xor_into ? (uint8_t)(out[done + i] ^ t[i]) : t[i];
        done += n;
        if (done < outlen) {
            ctl_part_t pa = { a, hl };
            if (ctl_hmac_parts(h, secret, slen, &pa, 1, a)) { ctl_wipe(a, 48); return -1; }
        }
    }
    ctl_wipe(a, sizeof a); ctl_wipe(t, sizeof t);
    return 0;
}

int prf_tls12(ctl_hash_t h, const uint8_t *secret, size_t slen, const char *label,
              const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
    if (h != CTL_SHA256 && h != CTL_SHA384) return -1;
    uint8_t buf[SEED_MAX]; size_t n;
    if (build_seed(label, seed, seedlen, buf, &n)) return -1;
    return p_hash(h, secret, slen, buf, n, out, outlen, 0);
}

int prf_tls10(const uint8_t *secret, size_t slen, const char *label,
              const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
    uint8_t buf[SEED_MAX]; size_t n;
    if (build_seed(label, seed, seedlen, buf, &n)) return -1;
    size_t half = (slen + 1) / 2;                   /* halves share a byte when slen is odd */
    if (p_hash(CTL_MD5, secret, half, buf, n, out, outlen, 0)) return -1;
    return p_hash(CTL_SHA1, secret + (slen - half), half, buf, n, out, outlen, 1);
}

int prf_ssl3(const uint8_t *secret, size_t slen, const uint8_t r1[32], const uint8_t r2[32],
             uint8_t *out, size_t outlen) {
    size_t done = 0;
    for (int i = 0; done < outlen; i++) {
        if (i >= 26) return -1;
        uint8_t lab[26];
        memset(lab, 'A' + i, (size_t)i + 1);
        uint8_t sha[20], md[16];
        ctl_part_t p1[4] = { { lab, (size_t)i + 1 }, { secret, slen }, { r1, 32 }, { r2, 32 } };
        if (ctl_hash_parts(CTL_SHA1, p1, 4, sha)) return -1;
        ctl_part_t p2[2] = { { secret, slen }, { sha, 20 } };
        if (ctl_hash_parts(CTL_MD5, p2, 2, md)) return -1;
        size_t n = outlen - done < 16 ? outlen - done : 16;
        memcpy(out + done, md, n);
        done += n;
    }
    return 0;
}

int tls_prf(uint16_t version, ctl_hash_t prf_hash, const uint8_t *secret, size_t slen,
            const char *label, const uint8_t *seed, size_t seedlen,
            uint8_t *out, size_t outlen) {
    if (version == TLS_V_12) return prf_tls12(prf_hash, secret, slen, label, seed, seedlen, out, outlen);
    if (version == TLS_V_10 || version == TLS_V_11)
        return prf_tls10(secret, slen, label, seed, seedlen, out, outlen);
    return -1;
}

int tls_master_secret(uint16_t version, ctl_hash_t prf_hash,
                      const uint8_t *pms, size_t pms_len,
                      const uint8_t client_random[32], const uint8_t server_random[32],
                      uint8_t out[48]) {
    if (!pms || !out) return -1;
    if (version == TLS_V_SSL3) return prf_ssl3(pms, pms_len, client_random, server_random, out, 48);
    uint8_t seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    return tls_prf(version, prf_hash, pms, pms_len, "master secret", seed, 64, out, 48);
}

int tls_master_secret_ems(uint16_t version, ctl_hash_t prf_hash,
                          const uint8_t *pms, size_t pms_len,
                          const uint8_t *session_hash, size_t session_hash_len,
                          uint8_t out[48]) {
    if (!pms || !session_hash || !out || version == TLS_V_SSL3) return -1;
    return tls_prf(version, prf_hash, pms, pms_len, "extended master secret",
                   session_hash, session_hash_len, out, 48);
}

int keyschedule_legacy_derive(uint16_t version, ctl_hash_t prf_hash,
                              const uint8_t master[48],
                              const uint8_t client_random[32], const uint8_t server_random[32],
                              size_t mac_len, size_t key_len, size_t iv_len,
                              keyschedule_12_t *out) {
    if (!master || !out || mac_len > 48 || key_len > 32 || iv_len > 16) return -1;
    size_t total = 2 * mac_len + 2 * key_len + 2 * iv_len;
    uint8_t block[256];
    int r;
    if (version == TLS_V_SSL3) {
        r = prf_ssl3(master, 48, server_random, client_random, block, total);
    } else {
        uint8_t seed[64];
        memcpy(seed, server_random, 32);
        memcpy(seed + 32, client_random, 32);
        r = tls_prf(version, prf_hash, master, 48, "key expansion", seed, 64, block, total);
    }
    if (r) return -1;
    memset(out, 0, sizeof *out);
    out->mac_len = mac_len; out->key_len = key_len; out->iv_len = iv_len;
    size_t w = 0;
    memcpy(out->client_write_mac, block + w, mac_len); w += mac_len;
    memcpy(out->server_write_mac, block + w, mac_len); w += mac_len;
    memcpy(out->client_write_key, block + w, key_len); w += key_len;
    memcpy(out->server_write_key, block + w, key_len); w += key_len;
    memcpy(out->client_write_iv,  block + w, iv_len);  w += iv_len;
    memcpy(out->server_write_iv,  block + w, iv_len);
    ctl_wipe(block, sizeof block);
    return 0;
}

int tls_finished_verify(uint16_t version, ctl_hash_t prf_hash, const uint8_t master[48],
                        int is_client, const uint8_t *hs_hash, size_t hs_hash_len,
                        uint8_t out[12]) {
    const char *label = is_client ? "client finished" : "server finished";
    if (version == TLS_V_10 || version == TLS_V_11) {
        if (hs_hash_len != 36) return -1;
    } else if (version == TLS_V_12) {
        if (hs_hash_len != ctl_hash_len(prf_hash)) return -1;
    } else return -1;
    return tls_prf(version, prf_hash, master, 48, label, hs_hash, hs_hash_len, out, 12);
}

int ssl3_finished(const uint8_t master[48], int is_client,
                  const uint8_t *hs_msgs, size_t hs_len, uint8_t out[36]) {
    static const uint8_t cl[4] = { 0x43, 0x4C, 0x4E, 0x54 };   /* "CLNT" */
    static const uint8_t sv[4] = { 0x53, 0x52, 0x56, 0x52 };   /* "SRVR" */
    uint8_t p1[48], p2[48];
    memset(p1, 0x36, 48); memset(p2, 0x5c, 48);
    const uint8_t *sender = is_client ? cl : sv;
    static const ctl_hash_t hs[2] = { CTL_MD5, CTL_SHA1 };
    for (int i = 0; i < 2; i++) {
        size_t padn = i == 0 ? 48 : 40, hl = ctl_hash_len(hs[i]);
        uint8_t inner[20];
        ctl_part_t a[4] = { { hs_msgs, hs_len }, { sender, 4 }, { master, 48 }, { p1, padn } };
        if (ctl_hash_parts(hs[i], a, 4, inner)) return -1;
        ctl_part_t b[3] = { { master, 48 }, { p2, padn }, { inner, hl } };
        if (ctl_hash_parts(hs[i], b, 3, out + (i == 0 ? 0 : 16))) return -1;
    }
    return 0;
}
