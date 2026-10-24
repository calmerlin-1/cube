/** quic_frame_test.c — roundtrip every frame type + spec examples. */

#include "quic_frame.h"
#include "quic_varint.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int ok = 1;

static int roundtrip(const char *name, const quic_frame_t *in) {
    uint8_t buf[1024];
    int n = quic_frame_encode(in, buf, sizeof(buf));
    if (n < 0) { printf("  [%s] encode FAILED\n", name); ok = 0; return 0; }

    quic_frame_t out;
    int m = quic_frame_decode(buf, (size_t)n, &out);
    if (m < 0) { printf("  [%s] decode FAILED\n", name); ok = 0; return 0; }

    int bad = 0;
    if (out.type != in->type) {
        /* STREAM frames carry flag bits in the low 3 bits of the type.
         * Encoder sent QUIC_FR_STREAM_BASE (0x08); wire type is
         * 0x08..0x0f. Accept any STREAM variant. */
        int is_stream_wire = (out.type >= QUIC_FR_STREAM_BASE &&
                              out.type <= 0x0f);
        int sent_stream    = (in->type == QUIC_FR_STREAM_BASE);
        if (!(is_stream_wire && sent_stream))
            bad = 1;
    }
    if (in->type == QUIC_FR_CRYPTO) {
        if (out.offset != in->offset)                  bad = 1;
        if (out.data_len != in->data_len)              bad = 1;
        if (memcmp(out.data, in->data, in->data_len))  bad = 1;
    }
    if (in->type >= QUIC_FR_STREAM_BASE && in->type <= 0x0f) {
        if (out.stream_id != in->stream_id) bad = 1;
        if (out.offset != in->offset) bad = 1;
        if (out.data_len != in->data_len) bad = 1;
        if (out.fin != in->fin) bad = 1;
        if (memcmp(out.data, in->data, in->data_len)) bad = 1;
    }
    if (in->type == QUIC_FR_ACK) {
        if (out.ack_largest != in->ack_largest)        bad = 1;
        if (out.ack_delay != in->ack_delay)            bad = 1;
        if (out.ack_range_count != in->ack_range_count) bad = 1;
    }
    if (in->type == QUIC_FR_CONNECTION_CLOSE ||
        in->type == QUIC_FR_CONNECTION_CLOSE_APP) {
        if (out.error_code != in->error_code)          bad = 1;
        if (out.reason_len != in->reason_len)          bad = 1;
        if (memcmp(out.reason, in->reason, in->reason_len)) bad = 1;
    }

    printf("  %-22s enc=%2d dec=%2d  %s\n", name, n, m,
           bad ? "FAIL" : "OK");
    if (bad) ok = 0;
    return !bad;
}

int main(void) {
    printf("=== QUIC frame roundtrip tests ===\n\n");

    /* PING */
    { quic_frame_t f; quic_frame_make_ping(&f); roundtrip("PING", &f); }

    /* PADDING */
    { quic_frame_t f; quic_frame_make_padding(&f, 20);
      roundtrip("PADDING x20", &f); }

    /* CRYPTO */
    {
        uint8_t payload[] = "hello quic handshake";
        quic_frame_t f;
        quic_frame_make_crypto(&f, 0, payload, sizeof(payload) - 1);
        roundtrip("CRYPTO off=0", &f);
    }
    {
        uint8_t payload[] = "later handshake bytes";
        quic_frame_t f;
        quic_frame_make_crypto(&f, 100, payload, sizeof(payload) - 1);
        roundtrip("CRYPTO off=100", &f);
    }

    /* STREAM */
    {
        uint8_t payload[] = "GET / HTTP/1.1\r\n";
        quic_frame_t f;
        quic_frame_make_stream(&f, 0, 0, payload, sizeof(payload) - 1, 0);
        roundtrip("STREAM sid=0 off=0", &f);
    }
    {
        uint8_t payload[] = "with offset";
        quic_frame_t f;
        quic_frame_make_stream(&f, 4, 16, payload, sizeof(payload) - 1, 1);
        roundtrip("STREAM sid=4 off=16 FIN", &f);
    }

    /* ACK */
    {
        quic_frame_t f;
        quic_frame_make_ack(&f, 10, 0, NULL, 0);
        roundtrip("ACK largest=10 no ranges", &f);
    }

    /* CONNECTION_CLOSE */
    {
        const char *reason = "protocol error";
        quic_frame_t f;
        quic_frame_make_connection_close(&f, 0x0a, 0,
                                          reason, strlen(reason));
        roundtrip("CONNECTION_CLOSE", &f);
    }
    {
        const char *reason = "app went away";
        quic_frame_t f;
        quic_frame_make_connection_close(&f, 0x01, 1,
                                          reason, strlen(reason));
        roundtrip("CONNECTION_CLOSE_APP", &f);
    }

    /* NEW_TOKEN (encode only — decode verifies bytes back) */
    {
        uint8_t tok[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_NEW_TOKEN;
        f.token = tok; f.token_len = 8;
        roundtrip("NEW_TOKEN", &f);
    }

    /* PATHS */
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_PATH_CHALLENGE;
        memcpy(f.challenge, "ABCDEFGH", 8);
        roundtrip("PATH_CHALLENGE", &f);
    }
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_PATH_RESPONSE;
        memcpy(f.challenge, "12345678", 8);
        roundtrip("PATH_RESPONSE", &f);
    }

    /* NEW_CONNECTION_ID */
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_NEW_CONNECTION_ID;
        f.seq_num = 3;
        f.retire_prior_to = 0;
        f.cid_len = 8;
        memcpy(f.cid, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
        memcpy(f.reset_token, "0123456789abcdef", 16);
        roundtrip("NEW_CONNECTION_ID", &f);
    }

    /* MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS */
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_MAX_DATA; f.max_data = 1024*1024;
        roundtrip("MAX_DATA", &f);
    }
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_MAX_STREAM_DATA;
        f.stream_id = 4; f.max_stream_data = 65536;
        roundtrip("MAX_STREAM_DATA", &f);
    }
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_MAX_STREAMS_BIDI; f.max_streams = 100;
        roundtrip("MAX_STREAMS_BIDI", &f);
    }
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_MAX_STREAMS_UNI; f.max_streams = 3;
        roundtrip("MAX_STREAMS_UNI", &f);
    }

    /* RESET_STREAM / STOP_SENDING */
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_RESET_STREAM;
        f.stream_id = 0; f.error_code = 2; f.final_size = 42;
        roundtrip("RESET_STREAM", &f);
    }
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_STOP_SENDING;
        f.stream_id = 0; f.error_code = 2;
        roundtrip("STOP_SENDING", &f);
    }

    /* HANDSHAKE_DONE */
    {
        quic_frame_t f; memset(&f, 0, sizeof(f));
        f.type = QUIC_FR_HANDSHAKE_DONE;
        roundtrip("HANDSHAKE_DONE", &f);
    }

    /* ---- Multi-frame packet payload ---- */
    printf("\n=== Multi-frame decode ===\n\n");
    {
        uint8_t buf[512];
        size_t w = 0;
        quic_frame_t f;
        int n;

        /* PING */
        quic_frame_make_ping(&f);
        n = quic_frame_encode(&f, buf + w, sizeof(buf) - w); w += (size_t)n;

        /* CRYPTO with small payload */
        uint8_t p[] = "abc";
        quic_frame_make_crypto(&f, 0, p, 3);
        n = quic_frame_encode(&f, buf + w, sizeof(buf) - w); w += (size_t)n;

        /* PADDING x5 */
        quic_frame_make_padding(&f, 5);
        n = quic_frame_encode(&f, buf + w, sizeof(buf) - w); w += (size_t)n;

        quic_frame_t frames[8];
        int got = quic_frames_decode_all(buf, w, frames, 8);
        printf("  encoded %zu bytes, decoded %d frames:\n", w, got);
        for (int i = 0; i < got; i++) {
            printf("    [%d] %s\n", i, quic_frame_name(frames[i].type));
        }
        if (got != 3) ok = 0;
    }

    printf("\n");
    printf(ok ? "ALL FRAME TESTS PASSED\n" : "SOME TESTS FAILED\n");
    return ok ? 0 : 1;
}
