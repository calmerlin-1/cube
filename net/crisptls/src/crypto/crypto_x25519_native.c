/** crypto_x25519_native.c — bridge native x25519 to the crypto.h API. */

#include "crypto.h"
#include "x25519.h"
#include <string.h>

int ct_x25519_keypair(uint8_t priv[32], uint8_t pub[32]) {
    /* random private scalar */
    extern int ct_random(uint8_t *out, size_t n);
    if (ct_random(priv, 32) != CT_OK) return CT_ERR_CRYPTO;
    x25519_clamp(priv);
    x25519_base(pub, priv);
    return CT_OK;
}

int ct_x25519(uint8_t shared[32], const uint8_t priv[32], const uint8_t peer[32]) {
    return x25519(shared, priv, peer) == 0 ? CT_OK : CT_ERR_CRYPTO;
}
