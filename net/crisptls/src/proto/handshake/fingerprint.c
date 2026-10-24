/** fingerprint.c — JA3 (and later JA4) TLS fingerprint computation.
 *
 * JA3 string format:
 *   SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
 * Each field is a dash-separated list of decimal numbers.
 * JA3 hash = MD5(ja3_string), lowercase hex.
 *
 * Example (Chrome on Linux):
 *   "771,4865-4866-4867-...,0-23-65281-...,29-23-24,0"
 *   -> "cd08e31494f9531f560d64c695473da9"
 */

#include "crisptls_policy.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>

/** Build the JA3 string from a policy. Returns length written. */
static int ja3_string_from_policy(const crisptls_policy_t *p,
                                   char *out, size_t cap) {
    if (!p || !out) return -1;
    size_t w = 0;

    /* SSLVersion: for TLS 1.3 use 771 (0x0303). */
    w += (size_t)snprintf(out + w, cap - w, "%d,", 771);

    /* Ciphers: dash-separated decimal */
    if (p->cipher_suites_13) {
        for (size_t i = 0; p->cipher_suites_13[i]; i++) {
            if (w + 8 >= cap) return -1;
            w += (size_t)snprintf(out + w, cap - w, "%s%u",
                                   i ? "-" : "", p->cipher_suites_13[i]);
        }
    }
    if (p->cipher_suites_12) {
        size_t start = w;
        int first = (p->cipher_suites_13 == NULL ||
                     p->cipher_suites_13[0] == 0);
        for (size_t i = 0; p->cipher_suites_12[i]; i++) {
            if (w + 8 >= cap) return -1;
            w += (size_t)snprintf(out + w, cap - w, "%s%u",
                                   (!first ? "-" : (i ? "-" : "")),
                                   p->cipher_suites_12[i]);
            first = 0;
        }
        (void)start;
    }
    if (w + 2 >= cap) return -1;
    out[w++] = ',';

    /* Extensions: use policy's list if set, else a fixed default order
     * that matches what clienthello.c writes. */
    static const uint16_t default_exts[] = {
        0,        /* server_name */
        10,       /* supported_groups */
        13,       /* signature_algorithms */
        16,       /* ALPN */
        43,       /* supported_versions */
        51,       /* key_share */
        45,       /* psk_key_exchange_modes */
        0
    };
    const uint16_t *exts = p->extensions ? p->extensions : default_exts;
    for (size_t i = 0; exts[i] || i == 0; i++) {
        if (!exts[i]) break;
        if (w + 6 >= cap) return -1;
        w += (size_t)snprintf(out + w, cap - w, "%s%u",
                               i ? "-" : "", exts[i]);
    }
    if (w + 2 >= cap) return -1;
    out[w++] = ',';

    /* Elliptic curves (groups) */
    if (p->groups) {
        for (size_t i = 0; p->groups[i]; i++) {
            if (w + 8 >= cap) return -1;
            w += (size_t)snprintf(out + w, cap - w, "%s%u",
                                   i ? "-" : "", p->groups[i]);
        }
    }
    if (w + 2 >= cap) return -1;
    out[w++] = ',';

    /* EC point formats — we always send 0 (uncompressed) */
    if (w + 2 >= cap) return -1;
    w += (size_t)snprintf(out + w, cap - w, "%d", 0);

    out[w] = 0;
    return (int)w;
}

static void hex_lower(const uint8_t *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = h[in[i] >> 4];
        out[i*2+1] = h[in[i] & 0xF];
    }
    out[n*2] = 0;
}

int crisptls_ja3(const crisptls_policy_t *policy,
                 char *md5_hex_out, size_t cap) {
    if (!policy || !md5_hex_out || cap < 33) return -1;

    char ja3_str[2048];
    int n = ja3_string_from_policy(policy, ja3_str, sizeof(ja3_str));
    if (n < 0) return -1;

    uint8_t digest[16];
    if (ct_md5((const uint8_t *)ja3_str, (size_t)n, digest) != CT_OK)
        return -1;

    hex_lower(digest, 16, md5_hex_out);
    return 0;
}

/* =========================================================
 * JA4 (FoxIO spec)
 * =========================================================
 * Format: <proto><version><sni><ciphers>_<ext_count><alpn>_<hash>_<hash>
 * Example: t13d1516h2_8daaf6152771_b186095e22b6
 *
 * Fields:
 *   proto     = "t" (TCP) or "q" (QUIC)
 *   version   = "13" for TLS 1.3
 *   sni       = "d" (domain) or "i" (IP)
 *   ciphers   = 2-digit count of non-GREASE cipher suites
 *   ext_count = 2-digit count of non-GREASE extensions
 *   alpn      = first and last char of ALPN, or "00"
 *   part_a    = first 12 hex of SHA-256 of "cipher1,cipher2,..._ext1,ext2,..."
 *   part_b    = first 12 hex of SHA-256 of raw ClientHello bytes
 */

/* Extract fields from raw ClientHello handshake message.
 * `raw` = full handshake message (type 0x01, 3-byte len, body). */
static int ja4_parse_ch(const uint8_t *raw, size_t raw_len,
                        uint16_t *cipher_list, size_t *cipher_count,
                        uint16_t *ext_list, size_t *ext_count,
                        char alpn_first_last[3],
                        int *has_sni) {
    if (!raw || raw_len < 4) return -1;
    if (raw[0] != 1) return -1;   /* not ClientHello */

    uint32_t body_len = ((uint32_t)raw[1] << 16) |
                        ((uint32_t)raw[2] << 8) | raw[3];
    if (4 + body_len > raw_len) return -1;

    const uint8_t *p = raw + 4;
    const uint8_t *end = p + body_len;

    /* legacy_version(2) + random(32) = 34 bytes */
    if (p + 34 > end) return -1;
    p += 34;

    /* session_id */
    if (p >= end) return -1;
    uint8_t sid_len = *p++;
    if (p + sid_len > end) return -1;
    p += sid_len;

    /* cipher_suites */
    if (p + 2 > end) return -1;
    uint16_t cs_len = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    if (p + cs_len > end) return -1;
    size_t n_ciphers = 0;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t cs = (uint16_t)((p[i] << 8) | p[i+1]);
        /* skip GREASE (RFC 8701) — values of form 0x?a?a */
        if (cs >= 0x0a0a && (cs & 0x0f0f) == 0x0a0a) continue;
        if (cipher_list && n_ciphers < *cipher_count) {
            cipher_list[n_ciphers] = cs;
        }
        n_ciphers++;
    }
    *cipher_count = n_ciphers;
    p += cs_len;

    /* compression_methods */
    if (p >= end) return -1;
    uint8_t cm_len = *p++;
    if (p + cm_len > end) return -1;
    p += cm_len;

    /* extensions */
    if (ext_count) *ext_count = 0;
    if (has_sni) *has_sni = 0;
    if (alpn_first_last) { alpn_first_last[0] = '0'; alpn_first_last[1] = '0'; alpn_first_last[2] = 0; }

    if (p + 2 > end) return 0;   /* no extensions block */
    uint16_t ext_total = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    if (p + ext_total > end) return -1;

    const uint8_t *ep = p;
    const uint8_t *ee = p + ext_total;
    size_t n_ext = 0;
    while (ep + 4 <= ee) {
        uint16_t et = (uint16_t)((ep[0] << 8) | ep[1]);
        uint16_t el = (uint16_t)((ep[2] << 8) | ep[3]);
        ep += 4;
        if (ep + el > ee) break;

        /* skip GREASE */
        if (!(et >= 0x0a0a && (et & 0x0f0f) == 0x0a0a)) {
            if (ext_list && n_ext < *ext_count) ext_list[n_ext] = et;
            n_ext++;
        }

        /* SNI (type 0) */
        if (et == 0) {
            if (has_sni) *has_sni = 1;
        }

        /* ALPN (type 16) — first+last char of FIRST entry.
         *   "http/1.1" -> "h1", "h2" -> "h2". */
        if (et == 16 && el >= 3 && alpn_first_last) {
            uint16_t list_len = (uint16_t)((ep[0] << 8) | ep[1]);
            if (list_len + 2 <= el) {
                const uint8_t *ap = ep + 2;
                if (list_len > 0) {
                    uint8_t f_len = ap[0];
                    if (f_len > 0 && 1 + f_len <= list_len) {
                        alpn_first_last[0] = (char)ap[1];
                        alpn_first_last[1] = (char)ap[1 + f_len - 1];
                    }
                }
            }
        }

        ep += el;
    }
    if (ext_count) *ext_count = n_ext;
    return 0;
}

static void hash_truncated_12hex(const char *input, size_t len, char *out) {
    uint8_t digest[32];
    ct_sha256((const uint8_t *)input, len, digest);
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 6; i++) {
        out[i*2]   = h[digest[i] >> 4];
        out[i*2+1] = h[digest[i] & 0xF];
    }
    out[12] = 0;
}

/** JA3 from raw ClientHello handshake message.
 *
 * String format (RFC-less, but standardized by Salesforce):
 *   SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
 *
 * Each list is dash-separated DECIMAL. GREASE values ARE included
 * (unlike JA4) — that's why real Chrome's JA3 varies per connection.
 *
 * `raw` = full handshake message: [type=1][len(3)][body].
 */
int crisptls_ja3_from_raw(const uint8_t *raw, size_t raw_len,
                          char *md5_hex_out, size_t cap) {
    if (!raw || !md5_hex_out || cap < 33) return -1;
    if (raw_len < 4 || raw[0] != 1) return -1;

    uint32_t body_len = ((uint32_t)raw[1] << 16) |
                        ((uint32_t)raw[2] << 8) | raw[3];
    if (4 + body_len > raw_len) return -1;

    const uint8_t *p = raw + 4;
    const uint8_t *end = p + body_len;

    if (p + 2 > end) return -1;
    uint16_t legacy_version = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    if (p + 32 > end) return -1;
    p += 32;   /* random */

    if (p >= end) return -1;
    uint8_t sid_len = *p++;
    if (p + sid_len > end) return -1;
    p += sid_len;

    char ja3[2048];
    size_t w = 0;
    w += (size_t)snprintf(ja3 + w, sizeof(ja3) - w, "%u,", (unsigned)legacy_version);

    /* Ciphers */
    if (p + 2 > end) return -1;
    uint16_t cs_len = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    if (p + cs_len > end) return -1;
    int first = 1;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t cs = (uint16_t)((p[i] << 8) | p[i+1]);
        w += (size_t)snprintf(ja3 + w, sizeof(ja3) - w,
                              "%s%u", first ? "" : "-", cs);
        first = 0;
    }
    p += cs_len;
    if (w + 2 < sizeof(ja3)) ja3[w++] = ',';

    /* Compression methods */
    if (p >= end) return -1;
    uint8_t cm_len = *p++;
    if (p + cm_len > end) return -1;
    p += cm_len;

    /* Extensions */
    if (p + 2 > end) return -1;
    uint16_t ext_total = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    if (p + ext_total > end) return -1;

    const uint8_t *ep = p;
    const uint8_t *ee = p + ext_total;
    uint16_t groups[64];
    size_t ngroups = 0;
    int ext_first = 1;
    while (ep + 4 <= ee) {
        uint16_t et = (uint16_t)((ep[0] << 8) | ep[1]);
        uint16_t el = (uint16_t)((ep[2] << 8) | ep[3]);
        ep += 4;
        if (ep + el > ee) break;

        w += (size_t)snprintf(ja3 + w, sizeof(ja3) - w,
                              "%s%u", ext_first ? "" : "-", et);
        ext_first = 0;

        /* Extract supported_groups (type 10) for the curves field */
        if (et == 10 && el >= 2) {
            uint16_t gl = (uint16_t)((ep[0] << 8) | ep[1]);
            if ((size_t)gl + 2 <= el && gl % 2 == 0) {
                for (size_t i = 2; i < 2 + gl && ngroups < 64; i += 2) {
                    groups[ngroups++] = (uint16_t)((ep[i] << 8) | ep[i+1]);
                }
            }
        }
        ep += el;
    }
    if (w + 2 < sizeof(ja3)) ja3[w++] = ',';

    /* Curves (groups) */
    first = 1;
    for (size_t i = 0; i < ngroups; i++) {
        w += (size_t)snprintf(ja3 + w, sizeof(ja3) - w,
                              "%s%u", first ? "" : "-", groups[i]);
        first = 0;
    }
    if (w + 2 < sizeof(ja3)) ja3[w++] = ',';

    /* EC point formats — we always send uncompressed (0) */
    if (w + 2 < sizeof(ja3)) ja3[w++] = '0';

    ja3[w] = 0;

    uint8_t digest[16];
    if (ct_md5((const uint8_t *)ja3, w, digest) != CT_OK) return -1;
    hex_lower(digest, 16, md5_hex_out);
    return 0;
}

/** JA4 from raw ClientHello bytes. */
int crisptls_ja4_from_raw(const uint8_t *raw, size_t raw_len,
                          char *out, size_t cap) {
    if (!raw || !out || cap < 40) return -1;

    uint16_t ciphers[128]; size_t nc = 128;
    uint16_t exts[128];    size_t ne = 128;
    char alpn[3] = {0};
    int has_sni = 0;

    if (ja4_parse_ch(raw, raw_len, ciphers, &nc, exts, &ne, alpn, &has_sni) != 0)
        return -1;

    /* Per FoxIO JA4 spec:
     *   part_a = SHA-256( sorted ciphers, comma-separated as 4-hex-lower )
     *   part_b = SHA-256( sorted extensions, comma-separated as 4-hex-lower )
     * Both truncated to 12 hex chars. No raw bytes, no randoms. */

    /* Sort ciphers ascending (insertion sort, small N) */
    for (size_t i = 1; i < nc; i++) {
        uint16_t key = ciphers[i];
        size_t j = i;
        while (j > 0 && ciphers[j-1] > key) {
            ciphers[j] = ciphers[j-1];
            j--;
        }
        ciphers[j] = key;
    }
    /* Sort extensions ascending */
    for (size_t i = 1; i < ne; i++) {
        uint16_t key = exts[i];
        size_t j = i;
        while (j > 0 && exts[j-1] > key) {
            exts[j] = exts[j-1];
            j--;
        }
        exts[j] = key;
    }

    char a_buf[1024];
    size_t w = 0;
    for (size_t i = 0; i < nc; i++) {
        w += (size_t)snprintf(a_buf + w, sizeof(a_buf) - w,
                               "%s%04x", i ? "," : "", ciphers[i]);
    }
    char part_a[13];
    hash_truncated_12hex(a_buf, w, part_a);

    char b_buf[1024];
    w = 0;
    for (size_t i = 0; i < ne; i++) {
        w += (size_t)snprintf(b_buf + w, sizeof(b_buf) - w,
                               "%s%04x", i ? "," : "", exts[i]);
    }
    char part_b[13];
    hash_truncated_12hex(b_buf, w, part_b);

    /* alpn: 2 chars, or "00" if none */
    char alpn_str[3];
    if (alpn[0] && alpn[1] && alpn[0] != '0') {
        alpn_str[0] = alpn[0];
        alpn_str[1] = alpn[1];
    } else {
        alpn_str[0] = '0';
        alpn_str[1] = '0';
    }
    alpn_str[2] = 0;

    /* Assemble: t13d1516h2_8daaf6152771_b186095e22b6 */
    int n = snprintf(out, cap,
                     "t13%s%02zu%02zu%s_%s_%s",
                     has_sni ? "d" : "i",
                     nc > 99 ? 99 : nc,
                     ne > 99 ? 99 : ne,
                     alpn_str,
                     part_a, part_b);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/** JA4 from a policy — fallback when we don't have raw bytes. */
int crisptls_ja4(const crisptls_policy_t *policy, char *out, size_t cap) {
    /* Without raw bytes we can only emit a placeholder. */
    (void)policy;
    if (!out || cap < 8) return -1;
    snprintf(out, cap, "t13d000000_000000000000_000000000000");
    return 0;
}

