/** x25519.h — self-contained X25519 (RFC 7748). Constant-time. Portable. */

#ifndef CRISPTLS_X25519_H
#define CRISPTLS_X25519_H

#include <stdint.h>

/** Scalar multiplication on Curve25519.
 *   out[32] = scalar * point
 * Returns 0 on success, -1 if the result is the all-zero point (low order). */
int x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/** Compute public key from a private scalar.
 *   out[32] = scalar * basepoint   (basepoint = 9) */
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/** Clamp a scalar in place per RFC 7748 §5. */
void x25519_clamp(uint8_t scalar[32]);

#endif
