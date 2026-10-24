/** crisptls_fingerprint.h — JA3/JA4 computation and profile metadata. */

#ifndef CRISPTLS_FINGERPRINT_H
#define CRISPTLS_FINGERPRINT_H

#include "crisptls_types.h"
#include "crisptls_policy.h"

/** Compute the JA3 hash for a policy (what the ClientHello will look like).
 * Returns 0 on success, negative on error. */
int crisptls_ja3(const crisptls_policy_t *policy,
                 char *md5_hex_out, size_t cap);

/** Compute the JA4 fingerprint for a policy.
 * Format: "t13d1516h2_8daaf6152771_b186095e22b6" (or similar). */
int crisptls_ja4(const crisptls_policy_t *policy,
                 char *out, size_t cap);

/** JA4 from the raw ClientHello handshake message (best accuracy).
 *  `raw` = full handshake message: [type=1][len(3)][body]. */
int crisptls_ja4_from_raw(const uint8_t *raw, size_t raw_len,
                          char *out, size_t cap);

/** JA3 from the raw ClientHello (includes GREASE, per JA3 spec).
 *  Real Chrome's JA3 varies per connection because GREASE is random. */
int crisptls_ja3_from_raw(const uint8_t *raw, size_t raw_len,
                          char *md5_hex_out, size_t cap);

/** Compute the fingerprint of the ClientHello actually sent.
 * Only valid after a successful handshake. */
int crisptls_conn_ja3(crisptls_conn_t *conn, char *md5_hex_out, size_t cap);

/** Profile: named set of policy knobs. */
struct crisptls_profile {
    const char *name;              /* "chrome-120" */
    const char *display;           /* "Chrome 120 on Linux x86_64" */
    const char *user_agent_hint;   /* "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ..." */
    int         tls_min;
    int         tls_max;
    const uint16_t *ciphers;        /* TLS 1.3 cipher suites, wire order */
    const uint16_t *ciphers_12;     /* TLS 1.2 cipher suites, wire order */
    const uint16_t *extensions;
    const uint16_t *groups;
    const uint16_t *sigalgs;
    const char     *alpn;
    int             send_grease;    /* RFC 8701 */
    /* Add fields as needed — profiles evolve with browser releases. */
};

/** Look up a profile by name. Returns NULL if not found. */
const crisptls_profile_t *crisptls_profile_lookup(const char *name);

/** Load additional profiles from a config file. Returns count loaded. */
int crisptls_profile_load_file(const char *path);

#endif
