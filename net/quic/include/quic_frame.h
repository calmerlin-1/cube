/** quic_frame.h — QUIC frame types (RFC 9000 §19).
 *
 * Frames are the units of QUIC packet payloads. Each frame has a
 * type (varint) followed by type-specific fields.
 *
 * This module encodes/decodes frames into a flat byte buffer. It does
 * not deal with packets or connections — that's a layer above.
 */

#ifndef QUIC_FRAME_H
#define QUIC_FRAME_H

#include <stdint.h>
#include <stddef.h>

/* Frame type numbers (RFC 9000 §19) */
#define QUIC_FR_PADDING              0x00
#define QUIC_FR_PING                 0x01
#define QUIC_FR_ACK                  0x02
#define QUIC_FR_ACK_ECN              0x03
#define QUIC_FR_RESET_STREAM         0x04
#define QUIC_FR_STOP_SENDING         0x05
#define QUIC_FR_CRYPTO               0x06
#define QUIC_FR_NEW_TOKEN            0x07
#define QUIC_FR_STREAM_BASE          0x08  /* 0x08..0x0f */
#define QUIC_FR_MAX_DATA             0x10
#define QUIC_FR_MAX_STREAM_DATA      0x11
#define QUIC_FR_MAX_STREAMS_BIDI     0x12
#define QUIC_FR_MAX_STREAMS_UNI      0x13
#define QUIC_FR_DATA_BLOCKED         0x14
#define QUIC_FR_STREAM_DATA_BLOCKED  0x15
#define QUIC_FR_STREAMS_BLOCKED_BIDI 0x16
#define QUIC_FR_STREAMS_BLOCKED_UNI  0x17
#define QUIC_FR_NEW_CONNECTION_ID    0x18
#define QUIC_FR_RETIRE_CONNECTION_ID 0x19
#define QUIC_FR_PATH_CHALLENGE       0x1a
#define QUIC_FR_PATH_RESPONSE        0x1b
#define QUIC_FR_CONNECTION_CLOSE     0x1c  /* transport-level */
#define QUIC_FR_CONNECTION_CLOSE_APP 0x1d  /* application-level */
#define QUIC_FR_HANDSHAKE_DONE       0x1e

/* STREAM frame flags (low 3 bits of type) */
#define QUIC_STREAM_FIN   0x01
#define QUIC_STREAM_LEN   0x02
#define QUIC_STREAM_OFF   0x04
#define QUIC_STREAM_BITS  0x07

/* Max ACK ranges we keep in a frame (spec unbounded, we cap) */
#define QUIC_MAX_ACK_RANGES 32

/* One ACK range: packets [smallest, largest] inclusive */
typedef struct {
    uint64_t smallest;
    uint64_t largest;
} quic_ack_range_t;

/* A decoded frame */
typedef struct {
    uint64_t type;

    /* STREAM / CRYPTO */
    uint64_t        offset;
    uint64_t        stream_id;      /* STREAM only */
    int             fin;            /* STREAM only */
    int             has_len;
    int             has_offset;
    const uint8_t  *data;           /* points into the decode buffer */
    size_t          data_len;

    /* ACK / ACK_ECN */
    uint64_t        ack_largest;
    uint64_t        ack_delay;
    uint64_t        ack_range_count;   /* additional ranges after largest */
    quic_ack_range_t ack_ranges[QUIC_MAX_ACK_RANGES];
    uint64_t        ect0, ect1, ce;    /* ACK_ECN only */

    /* RESET_STREAM / STOP_SENDING / CONNECTION_CLOSE */
    uint64_t        error_code;
    uint64_t        final_size;        /* RESET_STREAM */
    int             is_app_error;      /* CONNECTION_CLOSE */
    const char     *reason;            /* points into decode buffer */
    size_t          reason_len;

    /* MAX_DATA, MAX_STREAM_DATA, etc. */
    uint64_t        max_data;
    uint64_t        max_stream_data;
    uint64_t        max_streams;
    uint64_t        stream_id_or_dir;  /* for MAX_STREAM_DATA / DATA_BLOCKED */

    /* NEW_CONNECTION_ID */
    uint64_t        seq_num;
    uint64_t        retire_prior_to;
    uint8_t         cid_len;
    uint8_t         cid[20];
    uint8_t         reset_token[16];

    /* PATH_CHALLENGE / PATH_RESPONSE */
    uint8_t         challenge[8];

    /* NEW_TOKEN */
    const uint8_t  *token;
    size_t          token_len;

    /* PADDING count (number of padding bytes collapsed) */
    uint64_t        padding_count;
} quic_frame_t;

/* Encode a frame into buf[cap]. Returns bytes written or -1.
 * For PADDING, `padding_count` bytes of 0x00 are written. */
int quic_frame_encode(const quic_frame_t *f, uint8_t *buf, size_t cap);

/* Decode one frame from buf[cap]. Returns bytes consumed or -1.
 * `f->data` / `f->reason` / `f->token` point into buf (not owned). */
int quic_frame_decode(const uint8_t *buf, size_t cap, quic_frame_t *f);

/* Decode a whole packet's payload (sequence of frames). Appends each
 * decoded frame to `out_frames` (up to max_frames). Returns number of
 * frames decoded, or -1 on error.
 *
 * Frames' `data` / `reason` / `token` point into `buf` — the caller must
 * keep `buf` alive as long as the frames are used. */
int quic_frames_decode_all(const uint8_t *buf, size_t cap,
                            quic_frame_t *out_frames, size_t max_frames);

/* Convenience constructors */
void quic_frame_make_ping(quic_frame_t *f);
void quic_frame_make_padding(quic_frame_t *f, uint64_t count);
void quic_frame_make_crypto(quic_frame_t *f, uint64_t offset,
                             const uint8_t *data, size_t data_len);
void quic_frame_make_stream(quic_frame_t *f, uint64_t stream_id,
                             uint64_t offset, const uint8_t *data,
                             size_t data_len, int fin);
void quic_frame_make_ack(quic_frame_t *f, uint64_t largest, uint64_t delay,
                          const quic_ack_range_t *ranges, size_t n);
void quic_frame_make_connection_close(quic_frame_t *f, uint64_t error_code,
                                        int is_app, const char *reason,
                                        size_t reason_len);

const char *quic_frame_name(uint64_t type);

#endif /* QUIC_FRAME_H */
