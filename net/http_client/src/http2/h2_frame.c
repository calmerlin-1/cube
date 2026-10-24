/** h2_frame.c — HTTP/2 frame layer + small buffer helpers. */

#include "h2_internal.h"
#include "http_client.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/* ---- h2_buf_t ---- */

int h2_buf_reserve(h2_buf_t *b, size_t need) {
    if (b->len + need <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + need) ncap *= 2;
    uint8_t *nd = realloc(b->data, ncap);
    if (!nd) return -1;
    b->data = nd;
    b->cap  = ncap;
    return 0;
}

int h2_buf_append(h2_buf_t *b, const void *src, size_t n) {
    if (h2_buf_reserve(b, n) != 0) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

int h2_buf_append_u8(h2_buf_t *b, uint8_t v) {
    return h2_buf_append(b, &v, 1);
}

int h2_buf_append_u16(h2_buf_t *b, uint16_t v) {
    uint8_t x[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return h2_buf_append(b, x, 2);
}

int h2_buf_append_u24(h2_buf_t *b, uint32_t v) {
    uint8_t x[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    return h2_buf_append(b, x, 3);
}

int h2_buf_append_u32(h2_buf_t *b, uint32_t v) {
    uint8_t x[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8), (uint8_t)v };
    return h2_buf_append(b, x, 4);
}

void h2_buf_free(h2_buf_t *b) {
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* ---- I/O ---- */

#include <stdio.h>
#include "trace.h"
extern int g_h2_trace;
#define H2_TRACE(...) do { if (g_h2_trace) fprintf(stderr, __VA_ARGS__); } while (0)
int h2_io_read_exact(const http_io_t *io, void *buf, size_t n) {
    TRACE_ENTER("exact read", "n=%zu", n);
    size_t got = 0;
    while (got < n) {
        ssize_t r = io->read(io->ctx, (uint8_t *)buf + got, n - got);
        H2_TRACE("[h2_read] want=%zu got=%zd total=%zu\n", n, r, got);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

int h2_io_write_all(const http_io_t *io, const void *buf, size_t n) {
    TRACE_ENTER("write all", "n=%zu", n);
    H2_TRACE("[h2_write] ENTER n=%zu\n", n);
    size_t w = 0;
    while (w < n) {
        ssize_t r = io->write(io->ctx, (const uint8_t *)buf + w, n - w);
        H2_TRACE("[h2_write] io->write returned %zd\n", r);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        w += (size_t)r;
    }
    H2_TRACE("[h2_write] done, wrote %zu bytes\n", w);
    return 0;
}

/* ---- Frame layer ---- */

int h2_frame_read_hdr(const http_io_t *io, h2_frame_hdr_t *h) {
    TRACE_ENTER("read 9-byte frame header");
    uint8_t buf[9];
    if (h2_io_read_exact(io, buf, 9) != 0) return -1;
    h->length    = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
    h->type      = buf[3];
    h->flags     = buf[4];
    h->stream_id = ((uint32_t)(buf[5] & 0x7f) << 24) |
                   ((uint32_t)buf[6] << 16) |
                   ((uint32_t)buf[7] << 8)  | buf[8];
    return 0;
}

int h2_frame_write_hdr(const http_io_t *io, uint32_t length,
                        uint8_t type, uint8_t flags, uint32_t stream_id) {
    uint8_t buf[9];
    buf[0] = (uint8_t)(length >> 16);
    buf[1] = (uint8_t)(length >> 8);
    buf[2] = (uint8_t)(length);
    buf[3] = type;
    buf[4] = flags;
    buf[5] = (uint8_t)((stream_id >> 24) & 0x7f);
    buf[6] = (uint8_t)(stream_id >> 16);
    buf[7] = (uint8_t)(stream_id >> 8);
    buf[8] = (uint8_t)(stream_id);
    return h2_io_write_all(io, buf, 9);
}

int h2_frame_write(const http_io_t *io, uint8_t type, uint8_t flags,
                   uint32_t stream_id, const void *payload, uint32_t len) {
    TRACE_ENTER("write frame", "type=%u flags=0x%02x sid=%u", type, flags, stream_id);
    if (len > 16384) return -1;

    /* Coalesce header + payload into one buffer so the frame goes out as
     * a single write (one TLS record). Splitting the 9-byte header from
     * the payload across writes triggers strict servers. */
    uint8_t frame[16384 + 9];
    frame[0] = (uint8_t)(len >> 16);
    frame[1] = (uint8_t)(len >> 8);
    frame[2] = (uint8_t)(len);
    frame[3] = type;
    frame[4] = flags;
    frame[5] = (uint8_t)((stream_id >> 24) & 0x7f);
    frame[6] = (uint8_t)(stream_id >> 16);
    frame[7] = (uint8_t)(stream_id >> 8);
    frame[8] = (uint8_t)(stream_id);
    if (len && payload) memcpy(frame + 9, payload, len);

    H2_TRACE("[h2_tx] type=%u flags=0x%02x sid=%u len=%u total=%u\n",
             type, flags, stream_id, len, (unsigned)(9 + len));

    return h2_io_write_all(io, frame, 9 + len);
}
