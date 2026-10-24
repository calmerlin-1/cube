/** curves.c — key exchange groups per profile.
 *
 * Chrome/Firefox prefer X25519, then NIST P-curves. Firefox also
 * includes ffdhe groups. curl/OpenSSL uses a narrower set.
 */

#include "crisptls_policy.h"

const uint16_t CRISPTLS_GROUPS_CHROME[] = {
    0x001D,  /* x25519 */
    0x0017,  /* secp256r1 (P-256) */
    0x0018,  /* secp384r1 (P-384) */
    0
};

const uint16_t CRISPTLS_GROUPS_FIREFOX[] = {
    0x001D,  /* x25519 */
    0x0017,  /* secp256r1 (P-256) */
    0x0018,  /* secp384r1 (P-384) */
    0x0019,  /* secp521r1 (P-521) */
    0x0100,  /* ffdhe2048 */
    0x0101,  /* ffdhe3072 */
    0
};

const uint16_t CRISPTLS_GROUPS_CURL[] = {
    0x001D,  /* x25519 */
    0x0017,  /* secp256r1 (P-256) */
    0x0018,  /* secp384r1 (P-384) */
    0
};

/** EC point formats — uncompressed only. */
const uint8_t CRISPTLS_EC_POINT_UNCOMPRESSED[] = { 0x00, 0 };
