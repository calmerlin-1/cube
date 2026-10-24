/** state.c — handshake state transitions. */

#include "state.h"
#include <string.h>

int hs_transition_send(hs_context_t *ctx, uint8_t msg_type) {
    if (!ctx) return -1;
    switch (ctx->state) {
        case HS_STATE_INIT:
            if (msg_type == 1) { ctx->state = HS_STATE_SENT_CLIENT_HELLO; return 0; }
            break;
        case HS_STATE_RECV_SERVER_FINISHED:
            if (msg_type == 20) { ctx->state = HS_STATE_SENT_CLIENT_FINISHED; return 0; }
            break;
        default: break;
    }
    return -1;
}

int hs_transition_recv(hs_context_t *ctx, uint8_t msg_type) {
    if (!ctx) return -1;
    switch (ctx->state) {
        case HS_STATE_SENT_CLIENT_HELLO:
            if (msg_type == 2)  { ctx->state = HS_STATE_RECV_SERVER_HELLO; return 0; }
            break;
        case HS_STATE_RECV_SERVER_HELLO:
            if (msg_type == 8)  { ctx->state = HS_STATE_RECV_ENCRYPTED_EXTENSIONS; return 0; }
            if (msg_type == 11) { ctx->state = HS_STATE_RECV_CERTIFICATE; return 0; }
            break;
        case HS_STATE_RECV_ENCRYPTED_EXTENSIONS:
            if (msg_type == 11) { ctx->state = HS_STATE_RECV_CERTIFICATE; return 0; }
            if (msg_type == 20) { ctx->state = HS_STATE_RECV_SERVER_FINISHED; return 0; }
            break;
        case HS_STATE_RECV_CERTIFICATE:
            if (msg_type == 15) { ctx->state = HS_STATE_RECV_CERTIFICATE_VERIFY; return 0; }
            if (msg_type == 20) { ctx->state = HS_STATE_RECV_SERVER_FINISHED; return 0; }
            break;
        case HS_STATE_RECV_CERTIFICATE_VERIFY:
            if (msg_type == 20) { ctx->state = HS_STATE_RECV_SERVER_FINISHED; return 0; }
            break;
        case HS_STATE_SENT_CLIENT_FINISHED:
            if (msg_type == 20) { ctx->state = HS_STATE_ESTABLISHED; return 0; }
            break;
        default: break;
    }
    return -1;
}
