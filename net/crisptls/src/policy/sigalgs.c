/** sigalgs.c — signature algorithms per profile.
 *
 * Chrome puts ECDSA first, then RSA-PSS, then legacy.
 * Firefox has a slightly different order (more modern first).
 * curl/OpenSSL has a narrower set.
 */

#include "crisptls_policy.h"

/** Chrome 120 Linux order. */
const uint16_t CRISPTLS_SIGALGS_CHROME[] = {
    0x0403,  /* ecdsa_secp256r1_sha256 */
    0x0804,  /* rsa_pss_rsae_sha256 */
    0x0401,  /* rsa_pkcs1_sha256 */
    0x0503,  /* ecdsa_secp384r1_sha384 */
    0x0805,  /* rsa_pss_rsae_sha384 */
    0x0501,  /* rsa_pkcs1_sha384 */
    0x0806,  /* rsa_pss_rsae_sha512 */
    0x0601,  /* rsa_pkcs1_sha512 */
    0x0807,  /* ed25519 */
    0x0808,  /* ed448 */
    0x0809,  /* rsa_pss_pss_sha256 */
    0x080A,  /* rsa_pss_pss_sha384 */
    0x080B,  /* rsa_pss_pss_sha512 */
    0x0201,  /* rsa_pkcs1_sha1 (legacy) */
    0x0203,  /* ecdsa_sha1 (legacy) */
    0
};

/** Firefox 121 Linux order — same set, ECDSA + PSS pushed up. */
const uint16_t CRISPTLS_SIGALGS_FIREFOX[] = {
    0x0403,  /* ecdsa_secp256r1_sha256 */
    0x0503,  /* ecdsa_secp384r1_sha384 */
    0x0603,  /* ecdsa_secp521r1_sha512 */
    0x0804,  /* rsa_pss_rsae_sha256 */
    0x0805,  /* rsa_pss_rsae_sha384 */
    0x0806,  /* rsa_pss_rsae_sha512 */
    0x0401,  /* rsa_pkcs1_sha256 */
    0x0501,  /* rsa_pkcs1_sha384 */
    0x0601,  /* rsa_pkcs1_sha512 */
    0x0807,  /* ed25519 */
    0x0808,  /* ed448 */
    0x0809,  /* rsa_pss_pss_sha256 */
    0x080A,  /* rsa_pss_pss_sha384 */
    0x080B,  /* rsa_pss_pss_sha512 */
    0x0201,  /* rsa_pkcs1_sha1 */
    0
};

/** curl 8 / OpenSSL 3.x — narrower set. */
const uint16_t CRISPTLS_SIGALGS_CURL[] = {
    0x0403, 0x0503, 0x0603,
    0x0804, 0x0805, 0x0806,
    0x0807, 0x0808, 0x0809, 0x080A, 0x080B,
    0x0401, 0x0501, 0x0601,
    0
};
