/** h2_internal.h — HTTP/2 types and constants. */

#ifndef CUBE_H2_INTERNAL_H
#define CUBE_H2_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "http_client.h"

/* ---- Frame types (RFC 9113 §6) ---- */
#define H2_DATA          0x0
#define H2_HEADERS       0x1
#define H2_PRIORITY      0x2
#define H2_RST_STREAM    0x3
#define H2_SETTINGS      0x4
#define H2_PUSH_PROMISE  0x5
#define H2_PING          0x6
#define H2_GOAWAY        0x7
#define H2_WINDOW_UPDATE 0x8
#define H2_CONTINUATION  0x9

/* ---- Frame flags ---- */
#define H2_FLAG_END_STREAM  0x1
#define H2_FLAG_ACK         0x1
#define H2_FLAG_END_HEADERS 0x4
#define H2_FLAG_PADDED      0x8
#define H2_FLAG_PRIORITY    0x20

/* ---- SETTINGS IDs ---- */
#define H2_SET_HEADER_TABLE_SIZE      0x1
#define H2_SET_ENABLE_PUSH            0x2
#define H2_SET_MAX_CONCURRENT_STREAMS 0x3
#define H2_SET_INITIAL_WINDOW_SIZE    0x4
#define H2_SET_MAX_FRAME_SIZE         0x5
#define H2_SET_MAX_HEADER_LIST_SIZE   0x6

/* ---- Error codes ---- */
#define H2_NO_ERROR            0x0
#define H2_PROTOCOL_ERROR      0x1
#define H2_INTERNAL_ERROR      0x2
#define H2_FLOW_CONTROL_ERROR  0x3
#define H2_SETTINGS_TIMEOUT    0x4
#define H2_STREAM_CLOSED       0x5
#define H2_FRAME_SIZE_ERROR    0x6
#define H2_REFUSED_STREAM      0x7
#define H2_CANCEL              0x8
#define H2_COMPRESSION_ERROR   0x9
#define H2_CONNECT_ERROR       0xa
#define H2_ENHANCE_YOUR_CALM   0xb
#define H2_INADEQUATE_SECURITY 0xc
#define H2_HTTP_1_1_REQUIRED   0xd

/* ---- Defaults ---- */
#define H2_MAX_FRAME_SIZE_DEFAULT     16384
#define H2_INITIAL_WINDOW_SIZE        65535
#define H2_CONNECTION_PREFACE         "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_CONNECTION_PREFACE_LEN     24

#define H2_CLIENT_STREAM_ID_START     1
#define H2_STREAM_ID_STEP             2

/* ---- One frame header ---- */
typedef struct {
    uint32_t length;     /* 24 bits */
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;  /* 31 bits, R bit dropped */
} h2_frame_hdr_t;

/* ---- Minimal growable byte buffer (local to h2) ---- */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} h2_buf_t;

int h2_buf_reserve(h2_buf_t *b, size_t need);
int h2_buf_append(h2_buf_t *b, const void *src, size_t n);
int h2_buf_append_u8(h2_buf_t *b, uint8_t v);
int h2_buf_append_u16(h2_buf_t *b, uint16_t v);
int h2_buf_append_u24(h2_buf_t *b, uint32_t v);
int h2_buf_append_u32(h2_buf_t *b, uint32_t v);
void h2_buf_free(h2_buf_t *b);

/* ---- I/O helpers on http_io_t ---- */
struct http_io;
int h2_io_read_exact(const struct http_io *io, void *buf, size_t n);
int h2_io_write_all(const struct http_io *io, const void *buf, size_t n);

/* ---- Frame layer ---- */
int h2_frame_read_hdr(const struct http_io *io, h2_frame_hdr_t *h);
int h2_frame_write_hdr(const struct http_io *io, uint32_t length,
                        uint8_t type, uint8_t flags, uint32_t stream_id);
int h2_frame_write(const struct http_io *io, uint8_t type, uint8_t flags,
                    uint32_t stream_id, const void *payload, uint32_t len);

/* ---- HPACK ---- */
int h2_hpack_encode(const http_headers_t *hdrs, h2_buf_t *out);
int h2_hpack_decode(const uint8_t *in, size_t in_len,
                    http_headers_t *out);

#endif /* CUBE_H2_INTERNAL_H */
