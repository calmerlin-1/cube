/** extra.c — additional mainstream browser profiles.
 *
 * New browser releases can be added here without touching the core:
 * each profile is just a named set of wire-order tables.
 */

#include "crisptls_fingerprint.h"

extern const uint16_t CRISPTLS_CIPHERS_13_CHROME[];
extern const uint16_t CRISPTLS_CIPHERS_12_CHROME[];
extern const uint16_t CRISPTLS_GROUPS_CHROME[];
extern const uint16_t CRISPTLS_SIGALGS_CHROME[];
extern const uint16_t CRISPTLS_EXTS_CHROME[];

extern const uint16_t CRISPTLS_CIPHERS_13_FIREFOX[];
extern const uint16_t CRISPTLS_CIPHERS_12_FIREFOX[];
extern const uint16_t CRISPTLS_GROUPS_FIREFOX[];
extern const uint16_t CRISPTLS_SIGALGS_FIREFOX[];
extern const uint16_t CRISPTLS_EXTS_FIREFOX[];

/* Safari 17 (macOS) — approximate public fingerprint. */
static const uint16_t SAFARI_CIPHERS_13[] = {
    0x1301, 0x1302, 0x1303, 0
};
static const uint16_t SAFARI_CIPHERS_12[] = {
    0xC02C, 0xC02B, 0xC030, 0xC02F,
    0xCCA9, 0xCCA8, 0xC024, 0xC023, 0xC028, 0xC027,
    0
};
static const uint16_t SAFARI_GROUPS[] = {
    0x001D, 0x0017, 0x0018, 0x0019, 0
};
static const uint16_t SAFARI_SIGALGS[] = {
    0x0403, 0x0503, 0x0603,
    0x0804, 0x0805, 0x0806,
    0x0401, 0x0501, 0x0601, 0x0807,
    0
};
static const uint16_t SAFARI_EXTS[] = {
    0, 23, 0xff01, 10, 13, 16, 5, 51, 45, 43, 0
};

const crisptls_profile_t CRISPTLS_PROFILE_CHROME_131 = {
    .name = "chrome-131",
    .display = "Chrome 131 on Linux x86_64",
    .user_agent_hint = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
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

const crisptls_profile_t CRISPTLS_PROFILE_FIREFOX_133 = {
    .name = "firefox-133",
    .display = "Firefox 133 on Linux x86_64",
    .user_agent_hint = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) "
                       "Gecko/20100101 Firefox/133.0",
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

const crisptls_profile_t CRISPTLS_PROFILE_EDGE_120 = {
    .name = "edge-120",
    .display = "Edge 120 on Windows x86_64",
    .user_agent_hint = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
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

const crisptls_profile_t CRISPTLS_PROFILE_SAFARI_17 = {
    .name = "safari-17",
    .display = "Safari 17 on macOS arm64",
    .user_agent_hint = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                       "Version/17.5 Safari/605.1.15",
    .tls_min = CRISPTLS_VERSION_TLS12,
    .tls_max = CRISPTLS_VERSION_TLS13,
    .ciphers = SAFARI_CIPHERS_13,
    .ciphers_12 = SAFARI_CIPHERS_12,
    .extensions = SAFARI_EXTS,
    .groups = SAFARI_GROUPS,
    .sigalgs = SAFARI_SIGALGS,
    .alpn = "h2,http/1.1",
    .send_grease = 1,
};
