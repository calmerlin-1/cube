/** crisptls_policy.h — full policy struct. Every knob. */

#ifndef CRISPTLS_POLICY_H
#define CRISPTLS_POLICY_H

#include "crisptls_types.h"

/** Order in ClientHello matters for fingerprinting. These are the fields
 * that determine JA3/JA4. Change the order, change the fingerprint. */
typedef struct {
    /* Protocol versions */
    int      min_version;              /* CRISPTLS_VERSION_* */
    int      max_version;
    int      legacy_version_field;     /* what to send in ClientHello.version (usually 0x0303) */

    /* Cipher suites — NULL-terminated array of 16-bit suite IDs, sent in this order */
    const uint16_t *cipher_suites_13;
    const uint16_t *cipher_suites_12;
    /* If both NULL, use backend defaults. */

    /* Extensions — order matters for JA3/JA4 */
    const uint16_t *extensions;        /* NULL-terminated list of ext type IDs */
    /* Set by backend if NULL. */

    /* Groups (elliptic curves / key exchange) */
    const uint16_t *groups;            /* NULL-terminated list of group IDs */
    const uint8_t  *groups_ec_point_fmts; /* NULL-terminated list of point format bytes */

    /* Signature algorithms */
    const uint16_t *sigalgs;           /* NULL-terminated */
    const uint16_t *sigalgs_cert;      /* For certificate_request; may be NULL */

    /* ALPN — order determines what server picks. Comma-separated string. */
    const char     *alpn;              /* e.g. "h2,http/1.1" */

    /* SNI (Server Name Indication) */
    int             send_sni;          /* 1 = yes */
    int             send_encrypted_sni; /* TLS 1.3 ECH — usually 0 */

    /* Session */
    int             allow_session_cache;
    int             allow_session_tickets;
    int             allow_0rtt;

    /* Verification */
    int             verify_peer;
    int             verify_hostname;
    const char     *ca_bundle_path;    /* NULL = use backend default */
    const char     *ca_bundle_der;     /* alternative: DER blob, NULL if unused */
    size_t          ca_bundle_der_len;
    crisptls_verify_fn verify_cb;
    void           *verify_user;

    /* Timeouts */
    uint32_t        connect_timeout_ms;
    uint32_t        handshake_timeout_ms;
    uint32_t        read_timeout_ms;
    uint32_t        write_timeout_ms;

    /* Behaviour */
    int             allow_renegotiation; /* 0 = never (modern default) */
    int             allow_compression;   /* 0 = never */
    int             send_grease;         /* RFC 8701 random extension values */
    int             strict_alpn;         /* 1 = fail if server has no common proto */

    /* Options that affect wire bytes */
    int             send_session_ticket; /* send the "ticket" extension hint */
    int             send_padding;        /* add padding extension (Chrome does) */
    int             send_status_request; /* OCSP stapling request */
    int             send_sct;            /* Signed Certificate Timestamps */

    /* Extension order override (NULL = use RFC 8446 default).
     * NULL-terminated array of extension type IDs. */
    const uint16_t *extension_order;

    /* Vulnerability policy */
    int             allow_ssl3;          /* 1 = permit SSL 3.0 (POODLE) */
    int             allow_tls10;         /* 1 = permit TLS 1.0 */
    int             allow_tls11;         /* 1 = permit TLS 1.1 */
    int             allow_rc4;           /* 1 = permit RC4 (broken) */
    int             allow_3des;          /* 1 = permit 3DES (Sweet32) */
    int             allow_cbc;           /* 1 = permit CBC (Lucky13) */
    int             allow_rsa_kx;        /* 1 = permit RSA key exchange (ROBOT) */
    int             allow_sha1_sig;      /* 1 = permit SHA-1 signature */
    int             allow_dhe_lt_2048;   /* 1 = permit DHE < 2048 bits (Logjam) */

    /* Debug */
    int             dump_clienthello;    /* 1 = print ClientHello hex to stderr */
    int             warn_on_legacy;      /* 1 = emit warnings for weak negotiated params */

    /* Tier tag (crisptls_tier_t), set by crisptls_policy_tier(); see crisptls_tier.h */
    int             tier;
} crisptls_policy_t;

/** Set a policy to sane modern defaults (TLS 1.2+, ECDHE, AEAD, ALPN h2+http/1.1). */
void crisptls_policy_default(crisptls_policy_t *p);

/** Set a policy to "strictest modern" — TLS 1.3 only, X25519 only. */
void crisptls_policy_strict(crisptls_policy_t *p);

/** Set a policy matching a named profile ("chrome-120", "firefox-121", "curl-8"). */
int  crisptls_policy_from_profile(crisptls_policy_t *p, const char *profile_name);

/** List known profile names (NULL-terminated array of strings). */
const char *const *crisptls_policy_profile_names(void);

/** Legacy policy: allow SSL 3.0 through TLS 1.3, all ciphers. For OSINT only. */
void crisptls_policy_legacy(crisptls_policy_t *p);

/** TLS 1.3 only (modern minimum). */
void crisptls_policy_tls13(crisptls_policy_t *p);

/** TLS 1.2 only (for servers that don't do 1.3). */
void crisptls_policy_tls12(crisptls_policy_t *p);

/** Load a policy from a generated policy file (produced by tools/profile_gen).
 *  Starts from crisptls_policy_default, then overrides only the fields the
 *  file supplies. Returns CRISPTLS_OK on success, CRISPTLS_ERR_ARGS if the
 *  file cannot be opened or parsed. Caller must handle fallback to default. */
int crisptls_policy_from_generated(crisptls_policy_t *p, const char *path);

#endif
