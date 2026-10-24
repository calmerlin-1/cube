/** curl.c — curl 8 with OpenSSL TLS fingerprint. */

#include "crisptls_fingerprint.h"

extern const uint16_t CRISPTLS_CIPHERS_13_CURL[];
extern const uint16_t CRISPTLS_CIPHERS_12_CURL[];
extern const uint16_t CRISPTLS_GROUPS_CURL[];
extern const uint16_t CRISPTLS_SIGALGS_CURL[];
extern const uint16_t CRISPTLS_EXTS_CURL[];

const crisptls_profile_t CRISPTLS_PROFILE_CURL_8 = {
    .name = "curl-8",
    .display = "curl 8.x with OpenSSL",
    .user_agent_hint = "curl/8.5.0",
    .tls_min = CRISPTLS_VERSION_TLS12,
    .tls_max = CRISPTLS_VERSION_TLS13,
    .ciphers = CRISPTLS_CIPHERS_13_CURL,
    .ciphers_12 = CRISPTLS_CIPHERS_12_CURL,
    .extensions = CRISPTLS_EXTS_CURL,
    .groups = CRISPTLS_GROUPS_CURL,
    .sigalgs = CRISPTLS_SIGALGS_CURL,
    .alpn = "h2,http/1.1",
};

/* curl 8 / OpenSSL 3.x extension order — minimal. */
const uint16_t CRISPTLS_EXTS_CURL[] = {
    0,        /* server_name */
    23,       /* extended_master_secret */
    0xff01,   /* renegotiation_info */
    10,       /* supported_groups */
    13,       /* signature_algorithms */
    16,       /* ALPN */
    51,       /* key_share */
    45,       /* psk_key_exchange_modes */
    43,       /* supported_versions */
    0
};
