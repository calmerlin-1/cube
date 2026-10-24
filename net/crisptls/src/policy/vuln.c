/** vuln.c — TLS vulnerability map. Given negotiated params, report known issues. */

#include "crisptls_policy.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *cve;
    const char *desc;
} vuln_t;

/** Vulnerability categories as bitmask, so a cipher can have many. */
#define VULN_RC4        (1u << 0)
#define VULN_3DES       (1u << 1)
#define VULN_CBC        (1u << 2)
#define VULN_RSA_KX     (1u << 3)
#define VULN_SHA1       (1u << 4)
#define VULN_NO_PFS     (1u << 5)
#define VULN_EXPORT     (1u << 6)

/** Return bitmask of vulnerabilities for a cipher suite ID. */
unsigned vuln_mask_for_cipher(uint16_t suite) {
    unsigned m = 0;
    switch (suite) {
        /* RC4 */
        case 0x0004: case 0x0005: case 0x0018: case 0x0019:
        case 0xC007: case 0xC011: case 0xC012: case 0xC016:
        case 0xC01B: case 0xC01E:
            m |= VULN_RC4 | VULN_RSA_KX | VULN_NO_PFS;
            break;
        /* 3DES */
        case 0x000A: case 0x0013: case 0x0016:
        case 0xC008:
            m |= VULN_3DES | VULN_RSA_KX | VULN_NO_PFS;
            break;
        /* CBC with ECDHE */
        case 0xC009: case 0xC00A: case 0xC013: case 0xC014:
        case 0xC023: case 0xC024: case 0xC027: case 0xC028:
            m |= VULN_CBC;
            break;
        /* CBC with RSA KX */
        case 0x002F: case 0x0035: case 0x003C:
            m |= VULN_CBC | VULN_RSA_KX | VULN_NO_PFS | VULN_SHA1;
            break;
        /* AES-GCM with RSA KX */
        case 0x009C: case 0x009D:
            m |= VULN_RSA_KX | VULN_NO_PFS;
            break;
        /* Static DH */
        case 0x0030: case 0x0031: case 0x0032: case 0x0033:
            m |= VULN_NO_PFS;
            break;
    }
    return m;
}

/** Human-readable description of a vulnerability category. */
const char *vuln_mask_name(unsigned bit) {
    switch (bit) {
        case VULN_RC4:     return "RC4 biases (CVE-2013-2566 / CVE-2015-2808)";
        case VULN_3DES:    return "Sweet32 (CVE-2016-2183)";
        case VULN_CBC:     return "Lucky13/BEAST/POODLE (CVE-2013-0169, CVE-2011-3389)";
        case VULN_RSA_KX:  return "ROBOT (CVE-2017-17382)";
        case VULN_SHA1:    return "SHAttered (CVE-2017-15947)";
        case VULN_NO_PFS:  return "no forward secrecy";
        case VULN_EXPORT:  return "FREAK/Logjam (export ciphers)";
    }
    return "unknown";
}

/** For each set bit in mask, call f(bit, name). */
void vuln_iterate(unsigned mask, void (*f)(unsigned bit, const char *name, void *ud), void *user) {
    for (unsigned i = 0; i < 8; i++) {
        unsigned bit = 1u << i;
        if (mask & bit) f(bit, vuln_mask_name(bit), user);
    }
}

/** Look up vulnerabilities for a TLS protocol version. */
const vuln_t *vuln_for_version(uint16_t version) {
    static const vuln_t v_ssl3[] = {
        {"POODLE", "CVE-2014-3566", "SSL 3.0 padding oracle"},
        {"RC4 only", NULL, "SSL 3.0 typically forces weak ciphers"},
        {"BEAST", "CVE-2011-3389", "CBC IV vulnerability"},
        {NULL, NULL, NULL}
    };
    static const vuln_t v_tls10[] = {
        {"BEAST", "CVE-2011-3389", "CBC IV predictability in TLS 1.0"},
        {"Deprecated", "RFC 8996", "TLS 1.0 deprecated by IETF"},
        {NULL, NULL, NULL}
    };
    static const vuln_t v_tls11[] = {
        {"Deprecated", "RFC 8996", "TLS 1.1 deprecated by IETF"},
        {NULL, NULL, NULL}
    };

    switch (version) {
        case 0x0300: return v_ssl3;
        case 0x0301: return v_tls10;
        case 0x0302: return v_tls11;
        default:     return NULL;
    }
}

static void print_vuln(unsigned bit, const char *name, void *ud) {
    (void)bit;
    (void)ud;
    fprintf(stderr, "[crisptls][VULN] %s\n", name);
}

/** Report vulnerabilities for a negotiated connection.
 * Returns count of issues found; writes descriptions to stderr. */
int vuln_report_connection(uint16_t version, uint16_t cipher_suite) {
    int issues = 0;
    const vuln_t *vv = vuln_for_version(version);
    if (vv) {
        for (size_t i = 0; vv[i].name; i++) {
            fprintf(stderr, "[crisptls][VULN] version: %s (%s) — %s\n",
                    vv[i].name, vv[i].cve ? vv[i].cve : "no CVE", vv[i].desc);
            issues++;
        }
    }
    unsigned m = vuln_mask_for_cipher(cipher_suite);
    for (unsigned i = 0; i < 8; i++) {
        unsigned bit = 1u << i;
        if (m & bit) {
            fprintf(stderr, "[crisptls][VULN] cipher 0x%04X: %s\n",
                    cipher_suite, vuln_mask_name(bit));
            issues++;
        }
    }
    (void)print_vuln;
    return issues;
}

/** Detect TLS 1.3 downgrade sentinel.
 * TLS 1.3 servers put a specific 8-byte value in the last 8 bytes of
 * ServerHello.random when they negotiate TLS 1.2 or below. */
int vuln_check_downgrade(uint16_t negotiated_version, const uint8_t server_random[32]) {
    /* RFC 8446 §4.1.3 */
    static const uint8_t downgrade_12[] = {0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x01};
    static const uint8_t downgrade_11[] = {0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x00};

    if (negotiated_version >= 0x0304) return 0;  /* no downgrade */

    if (memcmp(server_random + 24, downgrade_12, 8) == 0) {
        fprintf(stderr, "[crisptls][VULN] server downgrade sentinel: TLS 1.3 capable "
                        "but negotiated <=1.2\n");
        return 1;
    }
    if (memcmp(server_random + 24, downgrade_11, 8) == 0) {
        fprintf(stderr, "[crisptls][VULN] server downgrade sentinel: TLS 1.3 capable "
                        "but negotiated <=1.1\n");
        return 2;
    }
    return 0;
}
