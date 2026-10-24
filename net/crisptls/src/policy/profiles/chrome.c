/** chrome.c — Chrome 120 TLS fingerprint. */

#include "crisptls_fingerprint.h"

extern const uint16_t CRISPTLS_CIPHERS_13_CHROME[];
extern const uint16_t CRISPTLS_CIPHERS_12_CHROME[];
extern const uint16_t CRISPTLS_GROUPS_CHROME[];
extern const uint16_t CRISPTLS_SIGALGS_CHROME[];
extern const uint16_t CRISPTLS_EXTS_CHROME[];

const crisptls_profile_t CRISPTLS_PROFILE_CHROME_120 = {
    .name = "chrome-120",
    .display = "Chrome 120 on Linux x86_64",
    .user_agent_hint = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    .tls_min = CRISPTLS_VERSION_TLS12,
    .tls_max = CRISPTLS_VERSION_TLS13,
    .ciphers = CRISPTLS_CIPHERS_13_CHROME,
    .ciphers_12 = CRISPTLS_CIPHERS_12_CHROME,
    .extensions = CRISPTLS_EXTS_CHROME,
    .groups = CRISPTLS_GROUPS_CHROME,
    .sigalgs = CRISPTLS_SIGALGS_CHROME,
    .alpn = "h2,http/1.1",
    .send_grease = 1,
};

/* Chrome 120 extension order. */
const uint16_t CRISPTLS_EXTS_CHROME[] = {
    0,        /* server_name */
    23,       /* extended_master_secret */
    0xff01,   /* renegotiation_info */
    10,       /* supported_groups */
    13,       /* signature_algorithms */
    18,       /* signed_certificate_timestamp */
    16,       /* ALPN */
    5,        /* status_request */
    51,       /* key_share */
    45,       /* psk_key_exchange_modes */
    43,       /* supported_versions */
    27,       /* compress_certificate */
    35,       /* session_ticket */
    0x4469,   /* application_settings */
    0
};
