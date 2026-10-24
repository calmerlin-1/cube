/** quic_varint.h — QUIC variable-length integers (RFC 9000 §16).
 *
 * QUIC uses 1, 2, 4, or 8-byte integers encoded based on the top
 * 2 bits of the first byte:
 *   0b00xxxxxx  -> 1-byte  (0..63)
 *   0b01xxxxxx  -> 2-byte  (0..16383)
 *   0b10xxxxxx  -> 4-byte  (0..2^30 - 1)
 *   0b11xxxxxx  -> 8-byte  (0..2^62 - 1)
 *
 * The "value" is the low 6 bits of byte 0 concatenated with bytes 1..n.
 * Values >= 2^62 are illegal.
 */

#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_VARINT_MAX  ((1ULL << 62) - 1)

/* How many bytes does this value need on the wire? */
int  quic_varint_len(uint64_t v);        /* 1, 2, 4, or 8 */

/* Encode v into buf[cap]. Returns bytes written (1/2/4/8) or -1. */
int  quic_varint_encode(uint64_t v, uint8_t *buf, size_t cap);

/* Decode from buf[cap]. Returns bytes read (1/2/4/8), sets *out, or -1. */
int  quic_varint_decode(const uint8_t *buf, size_t cap, uint64_t *out);

/* Decode with length forced to `len` bytes (1, 2, 4, or 8). The top 2
 * bits of buf[0] must match `len`. Returns bytes read or -1. */
int  quic_varint_decode_len(const uint8_t *buf, size_t cap, size_t len,
                            uint64_t *out);

#endif /* QUIC_VARINT_H */
