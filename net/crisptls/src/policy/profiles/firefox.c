/** firefox.c — Firefox 121 TLS fingerprint. */

#include "crisptls_fingerprint.h"

extern const uint16_t CRISPTLS_CIPHERS_13_FIREFOX[];
extern const uint16_t CRISPTLS_CIPHERS_12_FIREFOX[];
extern const uint16_t CRISPTLS_GROUPS_FIREFOX[];
extern const uint16_t CRISPTLS_SIGALGS_FIREFOX[];
extern const uint16_t CRISPTLS_EXTS_FIREFOX[];

const crisptls_profile_t CRISPTLS_PROFILE_FIREFOX_121 = {
    .name = "firefox-121",
    .display = "Firefox 121 on Linux x86_64",
    .user_agent_hint = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
                       "Gecko/20100101 Firefox/121.0",
    .tls_min = CRISPTLS_VERSION_TLS12,
    .tls_max = CRISPTLS_VERSION_TLS13,
    .ciphers = CRISPTLS_CIPHERS_13_FIREFOX,
    .ciphers_12 = CRISPTLS_CIPHERS_12_FIREFOX,
    .extensions = CRISPTLS_EXTS_FIREFOX,
    .groups = CRISPTLS_GROUPS_FIREFOX,
    .sigalgs = CRISPTLS_SIGALGS_FIREFOX,
    .alpn = "h2,http/1.1",
    .send_grease = 1,
};

/* Firefox 121 extension order. */
const uint16_t CRISPTLS_EXTS_FIREFOX[] = {
    0,        /* server_name */
    23,       /* extended_master_secret */
    0xff01,   /* renegotiation_info */
    10,       /* supported_groups */
    13,       /* signature_algorithms */
    16,       /* ALPN */
    5,        /* status_request */
    34,       /* delegated_credentials */
    51,       /* key_share */
    45,       /* psk_key_exchange_modes */
    43,       /* supported_versions */
    28,       /* record_size_limit */
    0
};
