/** crypto_p256.h — internal types for native P-256 (uint64_t[4] limbs).
 *  Public API (ct_p256_*) is declared in crypto.h. */
#ifndef CRISPTLS_CRYPTO_P256_H
#define CRISPTLS_CRYPTO_P256_H

#include <stdint.h>

typedef uint64_t fe64_t[4];
typedef struct { fe64_t X, Y, Z; } ge64_t;   /* Jacobian point */

#endif
