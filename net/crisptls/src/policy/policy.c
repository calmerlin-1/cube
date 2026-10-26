/** policy.c — policy constructors and profile binding. */

#include "crisptls_policy.h"
#include "crisptls_fingerprint.h"
#include "crypto_caps.h"
#include "crisptls_tier.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern const uint16_t CRISPTLS_CIPHERS_13_CHROME[];
extern const uint16_t CRISPTLS_CIPHERS_12_CHROME[];
extern const uint16_t CRISPTLS_GROUPS_CHROME[];
extern const uint16_t CRISPTLS_SIGALGS_CHROME[];
extern const uint16_t CRISPTLS_CIPHERS_13_FIREFOX[];
extern const uint16_t CRISPTLS_CIPHERS_12_FIREFOX[];
extern const uint16_t CRISPTLS_GROUPS_FIREFOX[];
extern const uint16_t CRISPTLS_SIGALGS_FIREFOX[];
extern const uint16_t CRISPTLS_CIPHERS_13_CURL[];
extern const uint16_t CRISPTLS_CIPHERS_12_CURL[];
extern const uint16_t CRISPTLS_GROUPS_CURL[];
extern const uint16_t CRISPTLS_SIGALGS_CURL[];

void crisptls_policy_default(crisptls_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));

    /* consult cached crypto caps to pick fastest AEAD for this device */
    const crisptls_crypto_caps_t *caps = crypto_caps_get();
    (void)caps;
    p->min_version = CRISPTLS_VERSION_TLS12;
    p->max_version = CRISPTLS_VERSION_TLS13;
    p->legacy_version_field = CRISPTLS_VERSION_TLS12;
    p->cipher_suites_13 = CRISPTLS_CIPHERS_13_CHROME;
    p->cipher_suites_12 = CRISPTLS_CIPHERS_12_MODERN;   /* advertise only what policy accepts */
    p->groups = CRISPTLS_GROUPS_CHROME;
    p->sigalgs = CRISPTLS_SIGALGS_CHROME;
    p->alpn = "h2,http/1.1";
    p->send_sni = 1;
    p->verify_peer = 1;
    p->verify_hostname = 1;
    p->allow_renegotiation = 0;
    p->allow_compression = 0;
    p->send_grease = 0;
    p->strict_alpn = 0;
    p->connect_timeout_ms = 5000;
    p->handshake_timeout_ms = 10000;
    p->read_timeout_ms = 15000;
    p->write_timeout_ms = 15000;
}

void crisptls_policy_strict(crisptls_policy_t *p) {
    crisptls_policy_default(p);
    if (!p) return;
    p->min_version = CRISPTLS_VERSION_TLS13;
    p->max_version = CRISPTLS_VERSION_TLS13;
    p->alpn = "h2";
    p->strict_alpn = 1;
}

void crisptls_policy_legacy(crisptls_policy_t *p) {
    /* Alias of the "ancient" tier (SSL 3.0 .. TLS 1.3). Prefer crisptls_policy_tier(). */
    crisptls_policy_tier(p, CRISPTLS_TIER_ANCIENT);
}

void crisptls_policy_tls13(crisptls_policy_t *p) {
    crisptls_policy_default(p);
    if (!p) return;
    p->min_version = 0x0304;
    p->max_version = 0x0304;
    p->alpn = "h2";
    p->strict_alpn = 1;
}

void crisptls_policy_tls12(crisptls_policy_t *p) {
    crisptls_policy_default(p);
    if (!p) return;
    p->min_version = 0x0303;
    p->max_version = 0x0303;
}

int crisptls_policy_from_profile(crisptls_policy_t *p, const char *name) {
    if (!p || !name) return CRISPTLS_ERR_ARGS;
    const crisptls_profile_t *prof = crisptls_profile_lookup(name);
    if (!prof) return CRISPTLS_ERR_PROFILE;
    crisptls_policy_default(p);
    p->allow_cbc = 1;                  /* browsers accept ECDHE-CBC; static RSA etc. stay gated */
    p->tier = CRISPTLS_TIER_COMPAT;
    p->min_version = prof->tls_min;
    p->max_version = prof->tls_max;
    p->legacy_version_field = (p->min_version < 0x0303) ? p->min_version : 0x0303;
    if (prof->ciphers)    p->cipher_suites_13 = prof->ciphers;
    if (prof->ciphers_12) p->cipher_suites_12 = prof->ciphers_12;
    if (prof->groups)     p->groups = prof->groups;
    if (prof->sigalgs)    p->sigalgs = prof->sigalgs;
    if (prof->alpn)       p->alpn = prof->alpn;
    if (prof->send_grease) p->send_grease = prof->send_grease;
    return CRISPTLS_OK;
}

/* Generated policy loader — Session B addition. Reads cache/policy.generated.txt (produced by tools/profile_gen). Falls back silently to crisptls_policy_default on any error. Does not touch crisptls_policy_default or any other existing function. */

/* Pre-declared cipher order tables. Loader maps file strings to these. */
static const uint16_t GEN_13_AES_FIRST[] = {
    0x1301, 0x1302, 0x1303, 0
};
static const uint16_t GEN_13_CHACHA_FIRST[] = {
    0x1303, 0x1301, 0x1302, 0
};
static const uint16_t GEN_12_AES_FIRST[] = {
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0
};
static const uint16_t GEN_12_CHACHA_FIRST[] = {
    0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0
};

/* Parse a single hex value like "0x0303" or "0x1301". */
static int parse_hex_u16(const char *s, uint16_t *out) {
    if (!s || !out) return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    char *end = NULL;
    long v = strtol(s, &end, 16);
    if (end == s || v < 0 || v > 0xFFFF) return -1;
    *out = (uint16_t)v;
    return 0;
}

/* Compare an ordered list of hex codes to one of our pre-declared tables.
 * Return 1 if they match in exactly the same order. */
static int suites_match(const uint16_t *file_vals, size_t n,
                        const uint16_t *tbl) {
    for (size_t i = 0; i < n; i++) {
        if (tbl[i] == 0) return 0;      /* table shorter than file */
        if (tbl[i] != file_vals[i]) return 0;
    }
    return tbl[n] == 0;                 /* table must end exactly here */
}

int crisptls_policy_from_generated(crisptls_policy_t *p, const char *path) {
    if (!p || !path) return CRISPTLS_ERR_ARGS;

    /* Start from a known-good baseline. This is what happens if we bail. */
    crisptls_policy_default(p);

    FILE *f = fopen(path, "r");
    if (!f) return CRISPTLS_ERR_ARGS;   /* caller falls back to default */

    uint16_t file_13[16]; size_t n_13 = 0;
    uint16_t file_12[16]; size_t n_12 = 0;
    int saw_13 = 0, saw_12 = 0;

    char line[1024];
    while (fgets(line, sizeof line, f)) {
        /* strip newline + comments */
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r' || line[n-1] == ' '))
            line[--n] = 0;
        if (n == 0) continue;

        if (!strncmp(line, "min_version ", 12)) {
            uint16_t v;
            if (parse_hex_u16(line + 12, &v) == 0) p->min_version = v;
        } else if (!strncmp(line, "max_version ", 12)) {
            uint16_t v;
            if (parse_hex_u16(line + 12, &v) == 0) p->max_version = v;
        } else if (!strncmp(line, "cipher_suites_13 ", 17)) {
            char *tok = strtok(line + 17, " \t");
            while (tok && n_13 < 16) {
                uint16_t v;
                if (parse_hex_u16(tok, &v) == 0) file_13[n_13++] = v;
                tok = strtok(NULL, " \t");
            }
            saw_13 = 1;
        } else if (!strncmp(line, "cipher_suites_12 ", 17)) {
            char *tok = strtok(line + 17, " \t");
            while (tok && n_12 < 16) {
                uint16_t v;
                if (parse_hex_u16(tok, &v) == 0) file_12[n_12++] = v;
                tok = strtok(NULL, " \t");
            }
            saw_12 = 1;
        }
        /* prefer_aes_gcm / prefer_sha256 are informational only in this
         * version — they drove the ordering at generation time. */
    }
    fclose(f);

    /* Map cipher lists to pre-declared tables. Unknown order = fall back
     * to whatever crisptls_policy_default already chose. */
    if (saw_13) {
        if      (suites_match(file_13, n_13, GEN_13_AES_FIRST))    p->cipher_suites_13 = GEN_13_AES_FIRST;
        else if (suites_match(file_13, n_13, GEN_13_CHACHA_FIRST)) p->cipher_suites_13 = GEN_13_CHACHA_FIRST;
        /* else: leave p->cipher_suites_13 as default set it */
    }
    if (saw_12) {
        if      (suites_match(file_12, n_12, GEN_12_AES_FIRST))    p->cipher_suites_12 = GEN_12_AES_FIRST;
        else if (suites_match(file_12, n_12, GEN_12_CHACHA_FIRST)) p->cipher_suites_12 = GEN_12_CHACHA_FIRST;
    }

    /* If min_version dropped below 1.2, keep legacy_version_field consistent. */
    p->legacy_version_field = (p->min_version < 0x0303)
                              ? p->min_version : 0x0303;

    return CRISPTLS_OK;
}
