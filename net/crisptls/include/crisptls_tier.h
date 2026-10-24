/** crisptls_tier.h — named policy tiers + the negotiation gate.
 *
 *  Philosophy: everything is possible, nothing weak happens by accident.
 *  Legacy protocols/ciphers are reachable only by naming a tier (or setting
 *  the individual allow_* flag), and every negotiated (version, suite) is
 *  checked against the policy AFTER the server picks, so "offered" can never
 *  silently become "accepted".
 *
 *    modern  TLS 1.2-1.3, AEAD + ECDHE only            (default)
 *    compat  + CBC (HMAC-SHA1/256/384), DHE            (browser-like)
 *    legacy  + TLS 1.0/1.1, 3DES, RC4, static RSA kx,
 *             SHA-1 signatures, DHE >= 1024            (old servers)
 *    ancient + SSL 3.0                                  (archaeology)
 */
#ifndef CRISPTLS_TIER_H
#define CRISPTLS_TIER_H

#include <stdint.h>
#include "crisptls_policy.h"

typedef enum {
    CRISPTLS_TIER_MODERN  = 0,
    CRISPTLS_TIER_COMPAT  = 1,
    CRISPTLS_TIER_LEGACY  = 2,
    CRISPTLS_TIER_ANCIENT = 3,
} crisptls_tier_t;

/** Gate result codes (0 = permitted). */
enum {
    CRISPTLS_GATE_OK        = 0,
    CRISPTLS_GATE_VERSION   = 1,   /* protocol version not permitted  -> alert protocol_version  */
    CRISPTLS_GATE_SUITE     = 2,   /* cipher suite not permitted      -> alert handshake_failure */
    CRISPTLS_GATE_DOWNGRADE = 3,   /* server signalled a downgrade    -> alert illegal_parameter */
};

/** Configure p for a tier (starts from crisptls_policy_default). */
void crisptls_policy_tier(crisptls_policy_t *p, crisptls_tier_t tier);
int  crisptls_policy_tier_from_name(const char *name, crisptls_tier_t *out);  /* 0 / -1 */
const char *crisptls_tier_name(crisptls_tier_t tier);

/** Is (version, suite) permitted by p? Unknown suites are denied.
 *  reason (optional) receives a static string for logs. */
int crisptls_policy_check(const crisptls_policy_t *p, uint16_t version,
                          uint16_t suite, const char **reason);

/** RFC 8446 §4.1.3 downgrade sentinel, only meaningful when we offered 1.3 (or 1.2). */
int crisptls_policy_check_downgrade(const crisptls_policy_t *p, uint16_t version,
                                    const uint8_t server_random[32], const char **reason);

/* Suite lists (0-terminated), defined in cipher_tiers.c */
extern const uint16_t CRISPTLS_CIPHERS_12_MODERN[];
extern const uint16_t CRISPTLS_CIPHERS_12_COMPAT[];
extern const uint16_t CRISPTLS_CIPHERS_12_LEGACY[];

#endif
