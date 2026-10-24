/** state_13.c — TLS 1.3 client handshake driver.
 *
 *  NOTE: the actual handshake driver lives in src/session/session.c
 *  because it needs the full crisptls_conn struct (transcript, keys,
 *  cert chain). This file exists to satisfy state.h's API — it is a
 *  thin pass-through used only if someone calls state_13_step directly.
 *  All real TLS 1.3 work is done by session_handshake(). */

#include "state.h"
#include "handshake.h"
#include "record.h"
#include "crypto.h"

int state_13_step(hs_context_t *ctx, const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)ctx; (void)in; (void)in_len;
    (void)out; (void)out_cap;
    if (out_len) *out_len = 0;
    return 0;
}
