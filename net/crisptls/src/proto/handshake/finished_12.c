/** finished_12.c — TLS 1.2 Finished. NOT IMPLEMENTED in this pass.
 *  The public API returns CRISPTLS_ERR_POLICY if a server selects 1.2. */

#include "handshake.h"

int finished_12_compute(const uint8_t master_secret[48],
                        const uint8_t *handshake_hash, size_t hash_len,
                        uint8_t out[12]) {
    (void)master_secret;
    (void)handshake_hash;
    (void)hash_len;
    (void)out;
    return -1;   /* not implemented */
}
