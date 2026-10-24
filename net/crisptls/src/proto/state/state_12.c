/** state_12.c — TLS 1.2 handshake. NOT IMPLEMENTED in this pass.
 *  Public API returns CRISPTLS_ERR_POLICY if a 1.2 server is picked. */

#include "state.h"

int state_12_step(hs_context_t *ctx, const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)ctx; (void)in; (void)in_len;
    (void)out; (void)out_cap;
    if (out_len) *out_len = 0;
    return -1;
}
