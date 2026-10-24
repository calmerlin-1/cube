/** tier.c — policy tiers and the post-ServerHello negotiation gate. */
#include "crisptls_tier.h"
#include "record_cbc.h"      /* tls_cbc_suite_lookup: authoritative CBC suite table */
#include <string.h>

extern const uint16_t CRISPTLS_CIPHERS_13_CHROME[];

enum { KX_NONE = 0, KX_RSA, KX_DHE, KX_ECDHE, KX_TLS13 };

typedef struct {
    int      is13, aead, kx, is_3des, is_rc4;
    uint16_t min_ver;
} suite_info_t;

/* Returns 0 and fills *o, or -1 for a suite we do not know (denied). */
static int classify(uint16_t s, suite_info_t *o) {
    memset(o, 0, sizeof *o);
    switch (s) {
    case 0x1301: case 0x1302: case 0x1303:
        o->is13 = 1; o->aead = 1; o->kx = KX_TLS13; o->min_ver = 0x0304; return 0;
    case 0xC02B: case 0xC02F: case 0xC02C: case 0xC030: case 0xCCA9: case 0xCCA8:
        o->aead = 1; o->kx = KX_ECDHE; o->min_ver = 0x0303; return 0;
    case 0x009E: case 0x009F: case 0xCCAA:
        o->aead = 1; o->kx = KX_DHE;   o->min_ver = 0x0303; return 0;
    case 0x009C: case 0x009D:
        o->aead = 1; o->kx = KX_RSA;   o->min_ver = 0x0303; return 0;
    case 0x0004: case 0x0005:
        o->is_rc4 = 1; o->kx = KX_RSA;   o->min_ver = 0x0300; return 0;
    case 0xC007: case 0xC011:
        o->is_rc4 = 1; o->kx = KX_ECDHE; o->min_ver = 0x0301; return 0;
    }
    const tls_cbc_suite_t *c = tls_cbc_suite_lookup(s);
    if (!c) return -1;
    o->kx = c->kx == TLS_KX_RSA ? KX_RSA : c->kx == TLS_KX_DHE_RSA ? KX_DHE : KX_ECDHE;
    o->is_3des = c->is_3des;
    o->min_ver = c->min_version;
    return 0;
}

#define DENY(code, msg) do { if (reason) *reason = (msg); return (code); } while (0)

int crisptls_policy_check(const crisptls_policy_t *p, uint16_t version,
                          uint16_t suite, const char **reason) {
    if (reason) *reason = "ok";
    if (!p) DENY(CRISPTLS_GATE_VERSION, "no policy");
    if (version < 0x0300 || version > 0x0304) DENY(CRISPTLS_GATE_VERSION, "unknown protocol version");
    {   /* 0 = unset -> secure default range 1.2..1.3 */
        int mn = p->min_version ? p->min_version : 0x0303;
        int mx = p->max_version ? p->max_version : 0x0304;
        if ((int)version < mn || (int)version > mx)
            DENY(CRISPTLS_GATE_VERSION, "protocol version outside policy range");
    }
    if (version == 0x0300 && !p->allow_ssl3)  DENY(CRISPTLS_GATE_VERSION, "SSL 3.0 not allowed (tier ancient / allow_ssl3)");
    if (version == 0x0301 && !p->allow_tls10) DENY(CRISPTLS_GATE_VERSION, "TLS 1.0 not allowed (tier legacy / allow_tls10)");
    if (version == 0x0302 && !p->allow_tls11) DENY(CRISPTLS_GATE_VERSION, "TLS 1.1 not allowed (tier legacy / allow_tls11)");

    suite_info_t si;
    if (classify(suite, &si)) DENY(CRISPTLS_GATE_SUITE, "unknown or unsupported cipher suite");
    if (version == 0x0304 && !si.is13) DENY(CRISPTLS_GATE_SUITE, "pre-1.3 suite selected for TLS 1.3");
    if (version != 0x0304 && si.is13)  DENY(CRISPTLS_GATE_SUITE, "TLS 1.3 suite selected for pre-1.3 version");
    if (version < si.min_ver)          DENY(CRISPTLS_GATE_SUITE, "suite not defined for this protocol version");
    if (si.is_rc4  && !p->allow_rc4)   DENY(CRISPTLS_GATE_SUITE, "RC4 not allowed (tier legacy / allow_rc4)");
    if (si.is_3des && !p->allow_3des)  DENY(CRISPTLS_GATE_SUITE, "3DES not allowed (tier legacy / allow_3des)");
    if (!si.aead && !si.is_rc4 && !p->allow_cbc)
                                       DENY(CRISPTLS_GATE_SUITE, "CBC not allowed (tier compat / allow_cbc)");
    if (si.kx == KX_RSA && !p->allow_rsa_kx)
                                       DENY(CRISPTLS_GATE_SUITE, "static RSA key exchange not allowed (tier legacy / allow_rsa_kx)");
    return CRISPTLS_GATE_OK;
}

int crisptls_policy_check_downgrade(const crisptls_policy_t *p, uint16_t version,
                                    const uint8_t r[32], const char **reason) {
    static const uint8_t d12[8] = { 0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x01 };   /* "DOWNGRD\x01" */
    static const uint8_t d11[8] = { 0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x00 };   /* "DOWNGRD\x00" */
    if (reason) *reason = "ok";
    if (!p || !r) return CRISPTLS_GATE_OK;
    if (version == 0x0303 && p->max_version >= 0x0304 && !memcmp(r + 24, d12, 8))
        DENY(CRISPTLS_GATE_DOWNGRADE, "server signalled TLS 1.3 -> 1.2 downgrade (RFC 8446 4.1.3)");
    if (version <= 0x0302 && p->max_version >= 0x0303 && !memcmp(r + 24, d11, 8))
        DENY(CRISPTLS_GATE_DOWNGRADE, "server signalled downgrade to TLS 1.1 or below (RFC 8446 4.1.3)");
    return CRISPTLS_GATE_OK;
}

const char *crisptls_tier_name(crisptls_tier_t t) {
    switch (t) {
    case CRISPTLS_TIER_MODERN:  return "modern";
    case CRISPTLS_TIER_COMPAT:  return "compat";
    case CRISPTLS_TIER_LEGACY:  return "legacy";
    case CRISPTLS_TIER_ANCIENT: return "ancient";
    }
    return "?";
}

int crisptls_policy_tier_from_name(const char *n, crisptls_tier_t *out) {
    if (!n || !out) return -1;
    for (int t = CRISPTLS_TIER_MODERN; t <= CRISPTLS_TIER_ANCIENT; t++)
        if (!strcmp(n, crisptls_tier_name((crisptls_tier_t)t))) { *out = (crisptls_tier_t)t; return 0; }
    return -1;
}

void crisptls_policy_tier(crisptls_policy_t *p, crisptls_tier_t t) {
    if (!p) return;
    crisptls_policy_default(p);                       /* modern baseline */
    p->tier = (int)t;
    p->cipher_suites_13 = CRISPTLS_CIPHERS_13_CHROME;
    p->cipher_suites_12 = CRISPTLS_CIPHERS_12_MODERN;
    if (t >= CRISPTLS_TIER_COMPAT) {
        p->cipher_suites_12 = CRISPTLS_CIPHERS_12_COMPAT;
        p->allow_cbc = 1;
    }
    if (t >= CRISPTLS_TIER_LEGACY) {
        p->cipher_suites_12 = CRISPTLS_CIPHERS_12_LEGACY;
        p->min_version = 0x0301;
        p->allow_tls10 = p->allow_tls11 = 1;
        p->allow_3des = p->allow_rc4 = p->allow_rsa_kx = 1;
        p->allow_sha1_sig = p->allow_dhe_lt_2048 = 1;
        p->warn_on_legacy = 1;
    }
    if (t >= CRISPTLS_TIER_ANCIENT) {
        p->min_version = 0x0300;
        p->allow_ssl3 = 1;
    }
    p->max_version = 0x0304;
    p->legacy_version_field = (p->min_version < 0x0303) ? p->min_version : 0x0303;
}
