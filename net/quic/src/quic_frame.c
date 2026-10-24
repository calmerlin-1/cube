/** quic_frame.c — QUIC frame encode/decode (RFC 9000 §19). */

#include "quic_frame.h"
#include "quic_varint.h"
#include <string.h>

/* ---- helpers ---- */

static int w_u8(uint8_t *b, size_t cap, size_t *w, uint8_t v) {
    if (*w + 1 > cap) return -1;
    b[(*w)++] = v;
    return 0;
}

static int w_var(uint8_t *b, size_t cap, size_t *w, uint64_t v) {
    int n = quic_varint_encode(v, b + *w, cap - *w);
    if (n < 0) return -1;
    *w += (size_t)n;
    return 0;
}

static int w_bytes(uint8_t *b, size_t cap, size_t *w,
                   const void *src, size_t n) {
    if (*w + n > cap) return -1;
    memcpy(b + *w, src, n);
    *w += n;
    return 0;
}

static int r_var(const uint8_t *b, size_t cap, size_t *r, uint64_t *out) {
    int n = quic_varint_decode(b + *r, cap - *r, out);
    if (n < 0) return -1;
    *r += (size_t)n;
    return n;
}

/* ---- encode ---- */

int quic_frame_encode(const quic_frame_t *f, uint8_t *buf, size_t cap) {
    if (!f || !buf) return -1;
    size_t w = 0;

    switch (f->type) {
        case QUIC_FR_PADDING: {
            /* Each PADDING frame is exactly one byte. Encode N zero bytes. */
            uint64_t n = f->padding_count ? f->padding_count : 1;
            if (w + n > cap) return -1;
            memset(buf, 0, n);
            return (int)n;
        }
        case QUIC_FR_PING:
            return w_u8(buf, cap, &w, QUIC_FR_PING) == 0 ? (int)w : -1;

        case QUIC_FR_CRYPTO:
            if (w_var(buf, cap, &w, QUIC_FR_CRYPTO) < 0) return -1;
            if (w_var(buf, cap, &w, f->offset) < 0) return -1;
            if (w_var(buf, cap, &w, f->data_len) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->data, f->data_len) < 0) return -1;
            return (int)w;

        case QUIC_FR_STREAM_BASE ... 0x0f: {
            uint8_t t = (uint8_t)f->type;
            if (f->fin)        t |= QUIC_STREAM_FIN;
            if (f->data_len || f->has_len) t |= QUIC_STREAM_LEN;
            if (f->offset || f->has_offset) t |= QUIC_STREAM_OFF;

            if (w_u8(buf, cap, &w, t) < 0) return -1;
            if (w_var(buf, cap, &w, f->stream_id) < 0) return -1;
            if ((t & QUIC_STREAM_OFF) && w_var(buf, cap, &w, f->offset) < 0)
                return -1;
            if (t & QUIC_STREAM_LEN) {
                if (w_var(buf, cap, &w, f->data_len) < 0) return -1;
                if (w_bytes(buf, cap, &w, f->data, f->data_len) < 0) return -1;
            } else {
                /* Length omitted → data extends to end of packet.
                 * We always write LEN for safety. */
                if (w_bytes(buf, cap, &w, f->data, f->data_len) < 0) return -1;
            }
            return (int)w;
        }

        case QUIC_FR_ACK:
        case QUIC_FR_ACK_ECN: {
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->ack_largest) < 0) return -1;
            if (w_var(buf, cap, &w, f->ack_delay) < 0) return -1;
            if (w_var(buf, cap, &w, f->ack_range_count) < 0) return -1;
            if (w_var(buf, cap, &w, 0) < 0) return -1;   /* first ACK range len = 0 */

            for (uint64_t i = 0; i < f->ack_range_count; i++) {
                /* gap = (prev_smallest - current_largest) - 2 */
                uint64_t gap = (i == 0)
                    ? (f->ack_largest - f->ack_ranges[0].largest - 2)
                    : (f->ack_ranges[i-1].smallest - f->ack_ranges[i].largest - 2);
                uint64_t len = f->ack_ranges[i].largest - f->ack_ranges[i].smallest;
                if (w_var(buf, cap, &w, gap) < 0) return -1;
                if (w_var(buf, cap, &w, len) < 0) return -1;
            }
            if (f->type == QUIC_FR_ACK_ECN) {
                if (w_var(buf, cap, &w, f->ect0) < 0) return -1;
                if (w_var(buf, cap, &w, f->ect1) < 0) return -1;
                if (w_var(buf, cap, &w, f->ce) < 0) return -1;
            }
            return (int)w;
        }

        case QUIC_FR_RESET_STREAM:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->stream_id) < 0) return -1;
            if (w_var(buf, cap, &w, f->error_code) < 0) return -1;
            if (w_var(buf, cap, &w, f->final_size) < 0) return -1;
            return (int)w;

        case QUIC_FR_STOP_SENDING:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->stream_id) < 0) return -1;
            if (w_var(buf, cap, &w, f->error_code) < 0) return -1;
            return (int)w;

        case QUIC_FR_NEW_TOKEN:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->token_len) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->token, f->token_len) < 0) return -1;
            return (int)w;

        case QUIC_FR_MAX_DATA:
        case QUIC_FR_DATA_BLOCKED:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->max_data) < 0) return -1;
            return (int)w;

        case QUIC_FR_MAX_STREAM_DATA:
        case QUIC_FR_STREAM_DATA_BLOCKED:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->stream_id) < 0) return -1;
            if (w_var(buf, cap, &w, f->max_stream_data) < 0) return -1;
            return (int)w;

        case QUIC_FR_MAX_STREAMS_BIDI:
        case QUIC_FR_MAX_STREAMS_UNI:
        case QUIC_FR_STREAMS_BLOCKED_BIDI:
        case QUIC_FR_STREAMS_BLOCKED_UNI:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->max_streams) < 0) return -1;
            return (int)w;

        case QUIC_FR_NEW_CONNECTION_ID:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->seq_num) < 0) return -1;
            if (w_var(buf, cap, &w, f->retire_prior_to) < 0) return -1;
            if (w_u8(buf, cap, &w, f->cid_len) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->cid, f->cid_len) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->reset_token, 16) < 0) return -1;
            return (int)w;

        case QUIC_FR_RETIRE_CONNECTION_ID:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->seq_num) < 0) return -1;
            return (int)w;

        case QUIC_FR_PATH_CHALLENGE:
        case QUIC_FR_PATH_RESPONSE:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->challenge, 8) < 0) return -1;
            return (int)w;

        case QUIC_FR_CONNECTION_CLOSE:
        case QUIC_FR_CONNECTION_CLOSE_APP:
            if (w_var(buf, cap, &w, f->type) < 0) return -1;
            if (w_var(buf, cap, &w, f->error_code) < 0) return -1;
            if (f->type == QUIC_FR_CONNECTION_CLOSE) {
                if (w_var(buf, cap, &w, 0) < 0) return -1;  /* frame_type = 0 */
            }
            if (w_var(buf, cap, &w, f->reason_len) < 0) return -1;
            if (w_bytes(buf, cap, &w, f->reason, f->reason_len) < 0) return -1;
            return (int)w;

        case QUIC_FR_HANDSHAKE_DONE:
            return w_u8(buf, cap, &w, QUIC_FR_HANDSHAKE_DONE) == 0 ? (int)w : -1;

        default:
            return -1;
    }
}

/* ---- decode ---- */

int quic_frame_decode(const uint8_t *buf, size_t cap, quic_frame_t *f) {
    if (!buf || !f) return -1;
    memset(f, 0, sizeof(*f));

    size_t r = 0;
    uint64_t type = 0;
    if (r_var(buf, cap, &r, &type) < 0) return -1;
    f->type = type;

    switch (type) {
        case QUIC_FR_PADDING: {
            /* Consume consecutive 0x00 bytes as one PADDING frame */
            size_t start = 0;
            while (start < cap && buf[start] == 0) start++;
            f->padding_count = start;
            return (int)start;
        }
        case QUIC_FR_PING:
            return (int)r;

        case QUIC_FR_CRYPTO: {
            uint64_t off, len;
            if (r_var(buf, cap, &r, &off) < 0) return -1;
            if (r_var(buf, cap, &r, &len) < 0) return -1;
            if (r + len > cap) return -1;
            f->offset = off;
            f->data = buf + r;
            f->data_len = (size_t)len;
            r += (size_t)len;
            return (int)r;
        }

        case QUIC_FR_STREAM_BASE ... 0x0f: {
            int has_off = (type & QUIC_STREAM_OFF) != 0;
            int has_len = (type & QUIC_STREAM_LEN) != 0;
            f->fin = (type & QUIC_STREAM_FIN) != 0;
            f->has_offset = has_off;
            f->has_len = has_len;

            uint64_t sid;
            if (r_var(buf, cap, &r, &sid) < 0) return -1;
            f->stream_id = sid;

            if (has_off) {
                uint64_t off;
                if (r_var(buf, cap, &r, &off) < 0) return -1;
                f->offset = off;
            }
            if (has_len) {
                uint64_t len;
                if (r_var(buf, cap, &r, &len) < 0) return -1;
                if (r + len > cap) return -1;
                f->data = buf + r;
                f->data_len = (size_t)len;
                r += (size_t)len;
            } else {
                f->data = buf + r;
                f->data_len = cap - r;
                r = cap;
            }
            return (int)r;
        }

        case QUIC_FR_ACK:
        case QUIC_FR_ACK_ECN: {
            uint64_t largest, delay, count, first_range;
            if (r_var(buf, cap, &r, &largest) < 0) return -1;
            if (r_var(buf, cap, &r, &delay) < 0) return -1;
            if (r_var(buf, cap, &r, &count) < 0) return -1;
            if (r_var(buf, cap, &r, &first_range) < 0) return -1;
            f->ack_largest = largest;
            f->ack_delay = delay;
            f->ack_range_count = count;

            /* First range */
            uint64_t prev_smallest = largest - first_range;
            if (count > 0 && count <= QUIC_MAX_ACK_RANGES) {
                f->ack_ranges[0].smallest = prev_smallest;
                f->ack_ranges[0].largest = largest;
            }
            /* Additional ranges */
            for (uint64_t i = 0; i < count; i++) {
                uint64_t gap, len;
                if (r_var(buf, cap, &r, &gap) < 0) return -1;
                if (r_var(buf, cap, &r, &len) < 0) return -1;
                uint64_t new_largest = prev_smallest - gap - 2;
                uint64_t new_smallest = new_largest - len;
                if (i + 1 < QUIC_MAX_ACK_RANGES) {
                    f->ack_ranges[i+1].smallest = new_smallest;
                    f->ack_ranges[i+1].largest = new_largest;
                }
                prev_smallest = new_smallest;
            }

            if (type == QUIC_FR_ACK_ECN) {
                if (r_var(buf, cap, &r, &f->ect0) < 0) return -1;
                if (r_var(buf, cap, &r, &f->ect1) < 0) return -1;
                if (r_var(buf, cap, &r, &f->ce) < 0) return -1;
            }
            return (int)r;
        }

        case QUIC_FR_RESET_STREAM: {
            uint64_t sid, ec, fs;
            if (r_var(buf, cap, &r, &sid) < 0) return -1;
            if (r_var(buf, cap, &r, &ec) < 0) return -1;
            if (r_var(buf, cap, &r, &fs) < 0) return -1;
            f->stream_id = sid;
            f->error_code = ec;
            f->final_size = fs;
            return (int)r;
        }

        case QUIC_FR_STOP_SENDING: {
            uint64_t sid, ec;
            if (r_var(buf, cap, &r, &sid) < 0) return -1;
            if (r_var(buf, cap, &r, &ec) < 0) return -1;
            f->stream_id = sid;
            f->error_code = ec;
            return (int)r;
        }

        case QUIC_FR_NEW_TOKEN: {
            uint64_t len;
            if (r_var(buf, cap, &r, &len) < 0) return -1;
            if (r + len > cap) return -1;
            f->token = buf + r;
            f->token_len = (size_t)len;
            r += (size_t)len;
            return (int)r;
        }

        case QUIC_FR_MAX_DATA:
        case QUIC_FR_DATA_BLOCKED: {
            uint64_t m;
            if (r_var(buf, cap, &r, &m) < 0) return -1;
            f->max_data = m;
            return (int)r;
        }

        case QUIC_FR_MAX_STREAM_DATA:
        case QUIC_FR_STREAM_DATA_BLOCKED: {
            uint64_t sid, m;
            if (r_var(buf, cap, &r, &sid) < 0) return -1;
            if (r_var(buf, cap, &r, &m) < 0) return -1;
            f->stream_id = sid;
            f->max_stream_data = m;
            return (int)r;
        }

        case QUIC_FR_MAX_STREAMS_BIDI:
        case QUIC_FR_MAX_STREAMS_UNI:
        case QUIC_FR_STREAMS_BLOCKED_BIDI:
        case QUIC_FR_STREAMS_BLOCKED_UNI: {
            uint64_t m;
            if (r_var(buf, cap, &r, &m) < 0) return -1;
            f->max_streams = m;
            return (int)r;
        }

        case QUIC_FR_NEW_CONNECTION_ID: {
            uint64_t seq, retire;
            if (r_var(buf, cap, &r, &seq) < 0) return -1;
            if (r_var(buf, cap, &r, &retire) < 0) return -1;
            if (r >= cap) return -1;
            uint8_t cid_len = buf[r++];
            if (cid_len < 1 || cid_len > 20) return -1;
            if (r + cid_len + 16 > cap) return -1;
            f->seq_num = seq;
            f->retire_prior_to = retire;
            f->cid_len = cid_len;
            memcpy(f->cid, buf + r, cid_len);
            r += cid_len;
            memcpy(f->reset_token, buf + r, 16);
            r += 16;
            return (int)r;
        }

        case QUIC_FR_RETIRE_CONNECTION_ID: {
            uint64_t seq;
            if (r_var(buf, cap, &r, &seq) < 0) return -1;
            f->seq_num = seq;
            return (int)r;
        }

        case QUIC_FR_PATH_CHALLENGE:
        case QUIC_FR_PATH_RESPONSE: {
            if (r + 8 > cap) return -1;
            memcpy(f->challenge, buf + r, 8);
            r += 8;
            return (int)r;
        }

        case QUIC_FR_CONNECTION_CLOSE:
        case QUIC_FR_CONNECTION_CLOSE_APP: {
            uint64_t ec;
            if (r_var(buf, cap, &r, &ec) < 0) return -1;
            f->error_code = ec;
            f->is_app_error = (type == QUIC_FR_CONNECTION_CLOSE_APP);
            if (type == QUIC_FR_CONNECTION_CLOSE) {
                uint64_t ft;
                if (r_var(buf, cap, &r, &ft) < 0) return -1;
            }
            uint64_t rlen;
            if (r_var(buf, cap, &r, &rlen) < 0) return -1;
            if (r + rlen > cap) return -1;
            f->reason = (const char *)(buf + r);
            f->reason_len = (size_t)rlen;
            r += (size_t)rlen;
            return (int)r;
        }

        case QUIC_FR_HANDSHAKE_DONE:
            return (int)r;

        default:
            return -1;
    }
}

int quic_frames_decode_all(const uint8_t *buf, size_t cap,
                            quic_frame_t *out, size_t max_frames) {
    size_t r = 0;
    size_t n = 0;
    while (r < cap) {
        if (n >= max_frames) return -1;
        int used = quic_frame_decode(buf + r, cap - r, &out[n]);
        if (used < 0) return -1;
        r += (size_t)used;
        n++;
    }
    return (int)n;
}

/* ---- convenience constructors ---- */

void quic_frame_make_ping(quic_frame_t *f) {
    memset(f, 0, sizeof(*f));
    f->type = QUIC_FR_PING;
}

void quic_frame_make_padding(quic_frame_t *f, uint64_t count) {
    memset(f, 0, sizeof(*f));
    f->type = QUIC_FR_PADDING;
    f->padding_count = count;
}

void quic_frame_make_crypto(quic_frame_t *f, uint64_t offset,
                             const uint8_t *data, size_t data_len) {
    memset(f, 0, sizeof(*f));
    f->type = QUIC_FR_CRYPTO;
    f->offset = offset;
    f->data = data;
    f->data_len = data_len;
}

void quic_frame_make_stream(quic_frame_t *f, uint64_t stream_id,
                             uint64_t offset, const uint8_t *data,
                             size_t data_len, int fin) {
    memset(f, 0, sizeof(*f));
    f->type = QUIC_FR_STREAM_BASE;
    f->stream_id = stream_id;
    f->offset = offset;
    f->data = data;
    f->data_len = data_len;
    f->fin = fin;
    f->has_len = data_len > 0;
    f->has_offset = offset > 0;
}

void quic_frame_make_ack(quic_frame_t *f, uint64_t largest, uint64_t delay,
                          const quic_ack_range_t *ranges, size_t n) {
    memset(f, 0, sizeof(*f));
    f->type = QUIC_FR_ACK;
    f->ack_largest = largest;
    f->ack_delay = delay;
    f->ack_range_count = n;
    for (size_t i = 0; i < n && i < QUIC_MAX_ACK_RANGES; i++)
        f->ack_ranges[i] = ranges[i];
}

void quic_frame_make_connection_close(quic_frame_t *f, uint64_t error_code,
                                        int is_app, const char *reason,
                                        size_t reason_len) {
    memset(f, 0, sizeof(*f));
    f->type = is_app ? QUIC_FR_CONNECTION_CLOSE_APP : QUIC_FR_CONNECTION_CLOSE;
    f->error_code = error_code;
    f->is_app_error = is_app;
    f->reason = reason;
    f->reason_len = reason_len;
}

const char *quic_frame_name(uint64_t t) {
    switch (t) {
        case QUIC_FR_PADDING: return "PADDING";
        case QUIC_FR_PING: return "PING";
        case QUIC_FR_ACK: return "ACK";
        case QUIC_FR_ACK_ECN: return "ACK_ECN";
        case QUIC_FR_RESET_STREAM: return "RESET_STREAM";
        case QUIC_FR_STOP_SENDING: return "STOP_SENDING";
        case QUIC_FR_CRYPTO: return "CRYPTO";
        case QUIC_FR_NEW_TOKEN: return "NEW_TOKEN";
        case QUIC_FR_MAX_DATA: return "MAX_DATA";
        case QUIC_FR_MAX_STREAM_DATA: return "MAX_STREAM_DATA";
        case QUIC_FR_MAX_STREAMS_BIDI: return "MAX_STREAMS_BIDI";
        case QUIC_FR_MAX_STREAMS_UNI: return "MAX_STREAMS_UNI";
        case QUIC_FR_DATA_BLOCKED: return "DATA_BLOCKED";
        case QUIC_FR_STREAM_DATA_BLOCKED: return "STREAM_DATA_BLOCKED";
        case QUIC_FR_STREAMS_BLOCKED_BIDI: return "STREAMS_BLOCKED_BIDI";
        case QUIC_FR_STREAMS_BLOCKED_UNI: return "STREAMS_BLOCKED_UNI";
        case QUIC_FR_NEW_CONNECTION_ID: return "NEW_CONNECTION_ID";
        case QUIC_FR_RETIRE_CONNECTION_ID: return "RETIRE_CONNECTION_ID";
        case QUIC_FR_PATH_CHALLENGE: return "PATH_CHALLENGE";
        case QUIC_FR_PATH_RESPONSE: return "PATH_RESPONSE";
        case QUIC_FR_CONNECTION_CLOSE: return "CONNECTION_CLOSE";
        case QUIC_FR_CONNECTION_CLOSE_APP: return "CONNECTION_CLOSE_APP";
        case QUIC_FR_HANDSHAKE_DONE: return "HANDSHAKE_DONE";
        default:
            if (t >= QUIC_FR_STREAM_BASE && t <= 0x0f) return "STREAM";
            return "UNKNOWN";
    }
}
