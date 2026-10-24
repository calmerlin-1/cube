/** keyexchange.c — ECDHE key exchange. X25519 only for now. */

#include "handshake.h"
#include "crypto.h"
#include <string.h>

int keyexchange_x25519_keypair(uint8_t priv[32], uint8_t pub[32]) {
    if (!priv || !pub) return CT_ERR_ARGS;
    return ct_x25519_keypair(priv, pub);
}

int keyexchange_x25519_shared(uint8_t shared[32],
                              const uint8_t priv[32],
                              const uint8_t peer_pub[32]) {
    if (!shared || !priv || !peer_pub) return CT_ERR_ARGS;
    /* Reject all-zero peer pub (low-order point) */
    uint8_t zero[32] = {0};
    if (ct_memeq(peer_pub, zero, 32)) return CT_ERR_CRYPTO;
    return ct_x25519(shared, priv, peer_pub);
}
