/** x25519.c — X25519 (RFC 7748) via libsodium.
 *  libsodium's crypto_scalarmult_curve25519 is constant-time,
 *  audited, and passes RFC 7748 test vectors.
 *
 *  When you're ready to drop libsodium, replace this file with a
 *  self-contained implementation that passes tests/x25519_test.c. */

#include "x25519.h"
#include <string.h>
#include <sodium.h>

int x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    if (!out || !scalar || !point) return -1;

    /* libsodium clamps the scalar internally per RFC 7748 §5.
     * crypto_scalarmult_curve25519 returns 0 on success, -1 on failure
     * (e.g. all-zero output = low-order point). */
    int rc = crypto_scalarmult_curve25519(out, scalar, point);
    return rc == 0 ? 0 : -1;
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    if (!out || !scalar) return;
    crypto_scalarmult_curve25519_base(out, scalar);
}

void x25519_clamp(uint8_t scalar[32]) {
    if (!scalar) return;
    scalar[0]  &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}
