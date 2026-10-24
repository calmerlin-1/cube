/** h2_conn.c — HTTP/2 connection setup + control frames. */

#include "h2_internal.h"
#include "http_client.h"
#include <string.h>
#include <stdlib.h>
#include "trace.h"
#include <stdio.h>

extern int g_h2_trace;
#define H2_TRACE(...) do { if (g_h2_trace) fprintf(stderr, __VA_ARGS__); } while (0)

/* Send the client connection preface + our SETTINGS frame. */
int h2_conn_preface(const http_io_t *io) {
    TRACE_ENTER("build+send client preface+SETTINGS");
    /* Build ENTIRE client preface (preface + SETTINGS + WU) into one
     * buffer, send as ONE write → ONE TLS record. */
    uint8_t buf[256];
    size_t  w = 0;

    /* Magic (24 bytes) */
    static const char PREFACE[] = H2_CONNECTION_PREFACE;
    memcpy(buf + w, PREFACE, H2_CONNECTION_PREFACE_LEN);
    w += H2_CONNECTION_PREFACE_LEN;

    /* SETTINGS: frame header (9) + payload (24) = 33 bytes */
    /* Header: 00 00 18 04 00 00 00 00 00 */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x18;
    buf[w++] = 0x04;
    buf[w++] = 0x00;
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x00;
    /* Payload: */
    buf[w++] = 0x00; buf[w++] = 0x01;  /* HEADER_TABLE_SIZE */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x10; buf[w++] = 0x00;
    buf[w++] = 0x00; buf[w++] = 0x03;  /* MAX_CONCURRENT_STREAMS */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x64;
    buf[w++] = 0x00; buf[w++] = 0x04;  /* INITIAL_WINDOW_SIZE */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0xff; buf[w++] = 0xff;
    buf[w++] = 0x00; buf[w++] = 0x05;  /* MAX_FRAME_SIZE */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x40; buf[w++] = 0x00;

    /* NOTE: WINDOW_UPDATE deliberately removed from the initial flight.
     * curl/nghttp2 send only preface + SETTINGS first, then wait for the
     * server's SETTINGS, then send WU + HEADERS.
     * If we send WU before the server's SETTINGS, some servers reject
     * with 'unexpected_message'. */

    H2_TRACE("[h2_preface] writing %zu bytes as ONE record\n", w);
    if (h2_io_write_all(io, buf, w) != 0) {
        H2_TRACE("[h2_preface] FAILED\n");
        return -1;
    }
    H2_TRACE("[h2_preface] sent\n");
    return 0;
}

/* Read and discard frames until we see the server's SETTINGS, then
 * send an ACK. Returns 0 on success. */
int h2_conn_wait_settings(const http_io_t *io) {
    TRACE_ENTER("read server SETTINGS, ack");
    for (;;) {
        h2_frame_hdr_t h;
        if (h2_frame_read_hdr(io, &h) != 0) {
            H2_TRACE("[h2] read_hdr failed\n");
            return -1;
        }
        H2_TRACE("[h2] frame type=%u flags=0x%02x stream=%u len=%u\n",
                 h.type, h.flags, h.stream_id, h.length);

        if (h.type == H2_SETTINGS) {
            /* Consume payload */
            uint8_t buf[64];
            uint32_t left = h.length;
            while (left > 0) {
                uint32_t chunk = left > sizeof(buf) ? (uint32_t)sizeof(buf) : left;
                if (h2_io_read_exact(io, buf, chunk) != 0) return -1;
                left -= chunk;
            }
            if (!(h.flags & H2_FLAG_ACK)) {
                /* Acknowledge */
                if (h2_frame_write(io, H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0) != 0)
                    return -1;
            }
            return 0;
        } else if (h.type == H2_PING) {
            uint8_t buf[8];
            if (h.length == 8) {
                if (h2_io_read_exact(io, buf, 8) != 0) return -1;
                if (h2_frame_write(io, H2_PING, H2_FLAG_ACK, 0, buf, 8) != 0)
                    return -1;
            } else {
                return -1;
            }
        } else if (h.type == H2_WINDOW_UPDATE) {
            uint8_t buf[4];
            if (h.length == 4) {
                if (h2_io_read_exact(io, buf, 4) != 0) return -1;
            } else {
                return -1;
            }
        } else if (h.type == H2_GOAWAY) {
            uint8_t buf[8];
            if (h.length >= 8) {
                if (h2_io_read_exact(io, buf, 8) != 0) return -1;
                uint32_t skip = h.length - 8;
                while (skip > 0) {
                    uint8_t tmp[64];
                    uint32_t c = skip > sizeof(tmp) ? (uint32_t)sizeof(tmp) : skip;
                    if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                    skip -= c;
                }
            }
            return -1;   /* server said go away — abort */
        } else {
            /* Skip unknown frame */
            uint32_t left = h.length;
            uint8_t tmp[256];
            while (left > 0) {
                uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                left -= c;
            }
        }
    }
}


/** Send connection-level WINDOW_UPDATE once the server's SETTINGS
 *  has been received. Matches curl/nghttp2 flight order. */
int h2_conn_send_window_update(const http_io_t *io) {
    TRACE_ENTER("send WINDOW_UPDATE");
    uint8_t buf[13];
    size_t w = 0;

    /* WINDOW_UPDATE frame: header (9) + payload (4) */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x04;   /* length = 4 */
    buf[w++] = 0x08;                                      /* type = WINDOW_UPDATE */
    buf[w++] = 0x00;                                      /* flags */
    buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x00; buf[w++] = 0x00;  /* stream_id = 0 */

    uint32_t delta = 16 * 1024 * 1024 - 65535;
    buf[w++] = (uint8_t)((delta >> 24) & 0x7f);
    buf[w++] = (uint8_t)(delta >> 16);
    buf[w++] = (uint8_t)(delta >> 8);
    buf[w++] = (uint8_t)delta;

    H2_TRACE("[h2_preface] sending WU after SETTINGS (%zu bytes)\n", w);
    if (h2_io_write_all(io, buf, w) != 0) {
        H2_TRACE("[h2_preface] WU FAILED\n");
        return -1;
    }
    return 0;
}
