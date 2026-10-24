/** state.h — handshake state machine. Which message to send/expect next. */

#ifndef CRISPTLS_STATE_H
#define CRISPTLS_STATE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HS_STATE_INIT = 0,
    HS_STATE_SENT_CLIENT_HELLO,
    HS_STATE_RECV_SERVER_HELLO,
    HS_STATE_RECV_ENCRYPTED_EXTENSIONS,
    HS_STATE_RECV_CERTIFICATE,
    HS_STATE_RECV_CERTIFICATE_VERIFY,
    HS_STATE_RECV_SERVER_FINISHED,
    HS_STATE_SENT_CLIENT_FINISHED,
    HS_STATE_ESTABLISHED,
    HS_STATE_CLOSED,
    HS_STATE_ERROR,
} hs_state_t;

typedef struct {
    hs_state_t state;
    uint16_t   version;         /* negotiated: 0x0303 or 0x0304 */
    uint16_t   cipher_suite;
    int        error_code;
    const char *error_msg;
} hs_context_t;

/** Advance state after sending a message. */
int hs_transition_send(hs_context_t *ctx, uint8_t msg_type);

/** Advance state after receiving a message. */
int hs_transition_recv(hs_context_t *ctx, uint8_t msg_type);

/** TLS 1.0/1.1/1.2 step (state_12.c). */
int state_12_step(hs_context_t *ctx, const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/** TLS 1.3 step (state_13.c). */
int state_13_step(hs_context_t *ctx, const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_cap, size_t *out_len);

#endif
