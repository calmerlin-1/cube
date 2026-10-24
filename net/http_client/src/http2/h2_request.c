/** h2_request.c — HTTP/2 request + response for one stream. */

#include "h2_internal.h"
#include "http_client.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern int g_h2_trace;
#define H2_TRACE(...) do { if (g_h2_trace) fprintf(stderr, __VA_ARGS__); } while (0)
#include "trace.h"

/* Forward decls from h2_conn.c */
int h2_conn_preface(const http_io_t *io);
int h2_conn_wait_settings(const http_io_t *io);
int h2_conn_send_window_update(const http_io_t *io);

/* Build the pseudo-header set + user headers into a temp list,
 * HPACK-encode, and send as a HEADERS frame. */
static int h2_send_headers(const http_io_t *io, uint32_t stream_id,
                            const char *scheme, const char *host,
                            const http_request_t *req, int end_stream) {
    TRACE_ENTER("send HEADERS frame", "sid=%u", stream_id);
    http_headers_t hdrs;
    http_headers_init(&hdrs);

    /* Pseudo-headers MUST come first (RFC 9113 §8.3.1). */
    char authority[280];
    snprintf(authority, sizeof(authority), "%s", host ? host : "");

    http_headers_set(&hdrs, ":method", req->method ? req->method : "GET");
    http_headers_set(&hdrs, ":scheme", scheme ? scheme : "https");
    http_headers_set(&hdrs, ":path",   req->path   ? req->path   : "/");
    http_headers_set(&hdrs, ":authority", authority);

    /* User headers — skip Host (in :authority) and any connection-specific
     * header, which is a PROTOCOL_ERROR in HTTP/2 (RFC 9113 §8.2.2). */
    for (size_t i = 0; i < req->headers.count; i++) {
        const char *n = req->headers.items[i].name;
        if (strcasecmp(n, "Host") == 0) continue;
        if (strcasecmp(n, "Connection") == 0) continue;
        if (strcasecmp(n, "Keep-Alive") == 0) continue;
        if (strcasecmp(n, "Proxy-Connection") == 0) continue;
        if (strcasecmp(n, "Transfer-Encoding") == 0) continue;
        if (strcasecmp(n, "Upgrade") == 0) continue;
        if (strcasecmp(n, "TE") == 0) continue;
        /* Header names must be lowercase in HTTP/2. */
        char lname[256];
        size_t nl = strlen(n);
        if (nl >= sizeof(lname)) nl = sizeof(lname) - 1;
        for (size_t j = 0; j < nl; j++) {
            char c = n[j];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            lname[j] = c;
        }
        lname[nl] = 0;
        http_headers_set(&hdrs, lname, req->headers.items[i].value);
    }

    /* HPACK-encode */
    h2_buf_t block;
    memset(&block, 0, sizeof(block));
    if (h2_hpack_encode(&hdrs, &block) != 0) {
        http_headers_free(&hdrs);
        h2_buf_free(&block);
        return -1;
    }

    uint8_t flags = H2_FLAG_END_HEADERS;
    if (end_stream) flags |= H2_FLAG_END_STREAM;

    int rc = h2_frame_write(io, H2_HEADERS, flags, stream_id,
                             block.data, (uint32_t)block.len);

    h2_buf_free(&block);
    http_headers_free(&hdrs);
    return rc;
}

/* Send a DATA frame with END_STREAM. */
static int h2_send_data(const http_io_t *io, uint32_t stream_id,
                         const void *body, size_t n) {
    uint8_t flags = H2_FLAG_END_STREAM;
    return h2_frame_write(io, H2_DATA, flags, stream_id, body, (uint32_t)n);
}

/* Consume a HEADERS frame's payload; decode HPACK into hdrs_out. */
static int h2_read_headers_payload(const http_io_t *io,
                                    const h2_frame_hdr_t *h,
                                    http_headers_t *out) {
    /* Padding + priority — skip if present */
    size_t pad = 0;
    size_t prio = 0;
    if (h->flags & H2_FLAG_PADDED)  pad  = 1;
    if (h->flags & H2_FLAG_PRIORITY) prio = 5;

    size_t hdr_pad = pad + prio;
    if (h->length < hdr_pad) return -1;

    size_t payload = h->length - hdr_pad;
    uint8_t *buf = malloc(h->length);
    if (!buf) return -1;
    if (h2_io_read_exact(io, buf, h->length) != 0) { free(buf); return -1; }

    size_t off = 0;
    size_t padlen = 0;
    if (h->flags & H2_FLAG_PADDED) padlen = buf[off++];
    off += prio;
    if (off + payload < padlen) { free(buf); return -1; }

    int rc = h2_hpack_decode(buf + off, payload - padlen, out);
    free(buf);
    return rc;
}

/* Response accumulator state — simple, single request. */
typedef struct {
    http_response_t *out;
    h2_buf_t         body;
    int              headers_seen;
    int              done;
    int64_t          content_length;   /* -1 if not set */
} h2_rsp_state_t;

/* Handle one frame. Return 0 if we should keep reading, -1 on error,
 * 1 if stream complete. */
static int h2_handle_frame(const http_io_t *io, const h2_frame_hdr_t *h,
                            uint32_t our_stream, h2_rsp_state_t *st) {
    H2_TRACE("[h2_handle_frame] type=%u flags=0x%02x sid=%u len=%u\n",
             h->type, h->flags, h->stream_id, h->length);
    switch (h->type) {
        case H2_HEADERS: {
            if (h->stream_id != our_stream) break;
            if (h2_read_headers_payload(io, h, &st->out->headers) != 0) {
                H2_TRACE("[h2_handle_frame] HEADERS parse failed\n");
                return -1;
            }
            st->headers_seen = 1;

            /* Pull :status from the just-decoded headers */
            const char *status = http_headers_get(&st->out->headers, ":status");
            if (status) {
                st->out->status_code = atoi(status);
            }
            const char *cl = http_headers_get(&st->out->headers, "content-length");
            if (cl) st->content_length = strtoll(cl, NULL, 10);
            if (h->flags & H2_FLAG_END_STREAM) {
                st->done = 1;
                return 1;
            }
            return 0;
        }
        case H2_DATA: {
            if (h->stream_id != our_stream) {
                /* Consume + discard, but still WINDOW_UPDATE for the
                 * discarded bytes so the peer isn't blocked. */
                uint32_t left = h->length;
                uint8_t tmp[512];
                while (left > 0) {
                    uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                    if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                    left -= c;
                }
                /* Increment connection-level window for discarded data. */
                uint32_t inc = h->length;
                uint8_t wu[4] = {
                    (uint8_t)((inc >> 24) & 0x7f),
                    (uint8_t)(inc >> 16),
                    (uint8_t)(inc >> 8),
                    (uint8_t)inc,
                };
                h2_frame_write(io, H2_WINDOW_UPDATE, 0, 0, wu, 4);
                break;
            }
            size_t pad = 0;
            size_t data_len = h->length;
            uint8_t *buf = malloc(h->length ? h->length : 1);
            if (!buf) return -1;
            if (h->length > 0 &&
                h2_io_read_exact(io, buf, h->length) != 0) {
                free(buf);
                return -1;
            }
            size_t off = 0;
            if (h->flags & H2_FLAG_PADDED) {
                pad = buf[off];
                off = 1;
            }
            if (off + pad > data_len) { free(buf); return -1; }
            data_len -= off + pad;
            if (h2_buf_append(&st->body, buf + off, data_len) != 0) {
                free(buf);
                return -1;
            }
            if (st->content_length >= 0 &&
                (int64_t)st->body.len >= st->content_length) {
                free(buf);
                st->done = 1;
                return 1;
            }
            free(buf);
            /* Send WINDOW_UPDATE for both the stream and the connection
             * so the server keeps sending. RFC 9113 §6.9. */
            {
                uint32_t inc = (uint32_t)data_len;
                if (inc > 0) {
                    uint8_t wu[4] = {
                        (uint8_t)((inc >> 24) & 0x7f),
                        (uint8_t)(inc >> 16),
                        (uint8_t)(inc >> 8),
                        (uint8_t)inc,
                    };
                    /* Connection-level window */
                    h2_frame_write(io, H2_WINDOW_UPDATE, 0, 0, wu, 4);
                    /* Stream-level window */
                    h2_frame_write(io, H2_WINDOW_UPDATE, 0, our_stream, wu, 4);
                }
            }
            if (h->flags & H2_FLAG_END_STREAM) {
                st->done = 1;
                return 1;
            }
            return 0;
        }
        case H2_RST_STREAM: {
            uint8_t buf[4];
            uint32_t ecode = 0;
            if (h->length >= 4) {
                h2_io_read_exact(io, buf, 4);
                ecode = ((uint32_t)buf[0]<<24)|((uint32_t)buf[1]<<16)|((uint32_t)buf[2]<<8)|buf[3];
            }
            H2_TRACE("[h2_handle_frame] RST_STREAM sid=%u code=%u\n", h->stream_id, ecode);
            if (h->stream_id == our_stream) return -1;
            break;
        }
        case H2_SETTINGS: {
            uint8_t buf[64];
            uint32_t left = h->length;
            while (left > 0) {
                uint32_t c = left > sizeof(buf) ? (uint32_t)sizeof(buf) : left;
                if (h2_io_read_exact(io, buf, c) != 0) return -1;
                left -= c;
            }
            if (!(h->flags & H2_FLAG_ACK)) {
                if (h2_frame_write(io, H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0) != 0)
                    return -1;
            }
            break;
        }
        case H2_PING: {
            uint8_t buf[8];
            if (h->length == 8) {
                if (h2_io_read_exact(io, buf, 8) != 0) return -1;
                if (!(h->flags & H2_FLAG_ACK)) {
                    if (h2_frame_write(io, H2_PING, H2_FLAG_ACK, 0, buf, 8) != 0)
                        return -1;
                }
            } else {
                uint32_t left = h->length;
                uint8_t tmp[8];
                while (left > 0) {
                    uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                    if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                    left -= c;
                }
            }
            break;
        }
        case H2_WINDOW_UPDATE:
        case H2_PRIORITY: {
            uint32_t left = h->length;
            uint8_t tmp[64];
            while (left > 0) {
                uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                left -= c;
            }
            break;
        }
        case H2_GOAWAY:
        case H2_PUSH_PROMISE:
        case H2_CONTINUATION: {
            uint32_t left = h->length;
            uint8_t tmp[512];
            while (left > 0) {
                uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                left -= c;
            }
            if (h->type == H2_GOAWAY) {
                H2_TRACE("[h2_handle_frame] GOAWAY received\n");
                return -1;
            }
            break;
        }
        default:
            /* Unknown frame type — skip payload */
            {
                uint32_t left = h->length;
                uint8_t tmp[512];
                while (left > 0) {
                    uint32_t c = left > sizeof(tmp) ? (uint32_t)sizeof(tmp) : left;
                    if (h2_io_read_exact(io, tmp, c) != 0) return -1;
                    left -= c;
                }
            }
            break;
    }
    return 0;
}

int http2_send_io(const http_io_t        *io,
                  const char             *host,
                  uint16_t                port,
                  const char             *scheme,
                  const http_request_t   *req,
                  http_response_t        *out)
{
    TRACE_ENTER("HTTP/2 request/response", "host=%s", host);
    if (!io || !host || !req || !out) return -1;
    (void)port;

    memset(out, 0, sizeof(*out));
    http_headers_init(&out->headers);
    out->version = HTTP_2;

    uint32_t stream_id = H2_CLIENT_STREAM_ID_START;

    /* 1. Preface + SETTINGS, then wait for server SETTINGS */
    if (h2_conn_preface(io) != 0) { http_response_free(out); return -2; }
    if (h2_conn_wait_settings(io) != 0) { http_response_free(out); return -3; }
    /* 2. WU now that server SETTINGS is received */
    if (h2_conn_send_window_update(io) != 0) {
        http_response_free(out); return -3;
    }

    /* 2. HEADERS */
    int has_body = req->body && req->body_len > 0;
    if (h2_send_headers(io, stream_id, scheme, host, req,
                         has_body ? 0 : 1) != 0) {
        http_response_free(out);
        return -4;
    }

    /* 3. DATA (if any) */
    if (has_body) {
        if (h2_send_data(io, stream_id, req->body, req->body_len) != 0) {
            http_response_free(out);
            return -5;
        }
    }

    /* 4. Read frames until END_STREAM */
    h2_rsp_state_t st;
    memset(&st, 0, sizeof(st));
    st.out = out;
    st.content_length = -1;

    int rc = 0;
    while (!st.done) {
        h2_frame_hdr_t h;
        if (h2_frame_read_hdr(io, &h) != 0) { rc = -6; break; }
        int r = h2_handle_frame(io, &h, stream_id, &st);
        if (r < 0) { rc = -7; break; }
        if (r == 1) break;
    }

    if (rc != 0) {
        h2_buf_free(&st.body);
        http_response_free(out);
        return rc;
    }

    /* Move body into response */
    out->body     = st.body.data;
    out->body_len = st.body.len;

    /* Fill in reason phrase from status map */
    out->reason = strdup("");

    /* Also copy the static response headers we extracted (minus :status) */
    http_headers_t filtered;
    http_headers_init(&filtered);
    for (size_t i = 0; i < out->headers.count; i++) {
        const char *n = out->headers.items[i].name;
        if (n[0] == ':') continue;   /* drop pseudo-headers */
        http_headers_add(&filtered, n, out->headers.items[i].value);
    }
    http_headers_free(&out->headers);
    out->headers = filtered;

    return 0;
}
