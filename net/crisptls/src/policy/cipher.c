/** cipher.c — cipher suite ID tables per browser/stack.
 *
 * Order matters for JA3/JA4 fingerprinting. Each profile gets its own
 * table matching that client's actual wire order.
 *
 * Sources: tlsfingerprint.io, FoxIO JA4+ database, manual captures.
 */

#include "crisptls_policy.h"

/* ============================================================
 * Chrome 120 (Linux x86_64)
 * ============================================================
 * TLS 1.3: 3 suites, AES-128-GCM first (Chrome order)
 * TLS 1.2: ECDHE-AEAD, then ECDHE-CBC, then RSA
 */
const uint16_t CRISPTLS_CIPHERS_13_CHROME[] = {
    0x1301,  /* TLS_AES_128_GCM_SHA256 */
    0x1302,  /* TLS_AES_256_GCM_SHA384 */
    0x1303,  /* TLS_CHACHA20_POLY1305_SHA256 */
    0
};

const uint16_t CRISPTLS_CIPHERS_12_CHROME[] = {
    0xC02B,  /* ECDHE_ECDSA_AES_128_GCM_SHA256 */
    0xC02F,  /* ECDHE_RSA_AES_128_GCM_SHA256 */
    0xC02C,  /* ECDHE_ECDSA_AES_256_GCM_SHA384 */
    0xC030,  /* ECDHE_RSA_AES_256_GCM_SHA384 */
    0xCCA9,  /* ECDHE_ECDSA_CHACHA20_POLY1305 */
    0xCCA8,  /* ECDHE_RSA_CHACHA20_POLY1305 */
    0xC013,  /* ECDHE_RSA_AES_128_CBC_SHA */
    0xC014,  /* ECDHE_RSA_AES_256_CBC_SHA */
    0x009C,  /* RSA_AES_128_GCM_SHA256 */
    0x009D,  /* RSA_AES_256_GCM_SHA384 */
    0x002F,  /* RSA_AES_128_CBC_SHA */
    0x0035,  /* RSA_AES_256_CBC_SHA */
    0
};

/* ============================================================
 * Firefox 121 (Linux x86_64)
 * ============================================================
 * Order differs from Chrome: ChaCha20 before AES-256.
 * TLS 1.2: ECDHE-AEAD, ChaCha20 first
 */
const uint16_t CRISPTLS_CIPHERS_13_FIREFOX[] = {
    0x1301,  /* TLS_AES_128_GCM_SHA256 */
    0x1303,  /* TLS_CHACHA20_POLY1305_SHA256   <- Firefox order */
    0x1302,  /* TLS_AES_256_GCM_SHA384 */
    0
};

const uint16_t CRISPTLS_CIPHERS_12_FIREFOX[] = {
    0xC02B,  /* ECDHE_ECDSA_AES_128_GCM_SHA256 */
    0xC02F,  /* ECDHE_RSA_AES_128_GCM_SHA256 */
    0xCCA9,  /* ECDHE_ECDSA_CHACHA20_POLY1305   <- Firefox puts ChaCha high */
    0xCCA8,  /* ECDHE_RSA_CHACHA20_POLY1305 */
    0xC02C,  /* ECDHE_ECDSA_AES_256_GCM_SHA384 */
    0xC030,  /* ECDHE_RSA_AES_256_GCM_SHA384 */
    0xC009,  /* ECDHE_ECDSA_AES_128_CBC_SHA     <- Firefox keeps ECDSA-CBC */
    0xC00A,  /* ECDHE_ECDSA_AES_256_CBC_SHA */
    0xC013,  /* ECDHE_RSA_AES_128_CBC_SHA */
    0xC014,  /* ECDHE_RSA_AES_256_CBC_SHA */
    0x009C,  /* RSA_AES_128_GCM_SHA256 */
    0x009D,  /* RSA_AES_256_GCM_SHA384 */
    0x002F,  /* RSA_AES_128_CBC_SHA */
    0x0035,  /* RSA_AES_256_CBC_SHA */
    0
};

/* ============================================================
 * curl 8 / OpenSSL 3.x (Linux)
 * ============================================================
 * TLS 1.3: OpenSSL default order (ChaCha before AES-256).
 * No GREASE. Narrower cipher set.
 */
const uint16_t CRISPTLS_CIPHERS_13_CURL[] = {
    0x1301,  /* TLS_AES_128_GCM_SHA256 */
    0x1303,  /* TLS_CHACHA20_POLY1305_SHA256 */
    0x1302,  /* TLS_AES_256_GCM_SHA384 */
    0
};

const uint16_t CRISPTLS_CIPHERS_12_CURL[] = {
    0xC02B,  /* ECDHE_ECDSA_AES_128_GCM_SHA256 */
    0xC02F,  /* ECDHE_RSA_AES_128_GCM_SHA256 */
    0xC02C,  /* ECDHE_ECDSA_AES_256_GCM_SHA384 */
    0xC030,  /* ECDHE_RSA_AES_256_GCM_SHA384 */
    0xCCA9,  /* ECDHE_ECDSA_CHACHA20_POLY1305 */
    0xCCA8,  /* ECDHE_RSA_CHACHA20_POLY1305 */
    0xC013,  /* ECDHE_RSA_AES_128_CBC_SHA */
    0xC014,  /* ECDHE_RSA_AES_256_CBC_SHA */
    0
};

/** TLS 1.2 minimal — AEAD only. */
const uint16_t CRISPTLS_CIPHERS_12_STRICT[] = {
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0
};
