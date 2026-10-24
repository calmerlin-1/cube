/** quic_packet.h — QUIC packet header framing (RFC 9000 §17).
 *
 * This module handles the *unencrypted* packet header:
 *   - Long header: Initial / Handshake / 0-RTT
 *   - Short header: 1-RTT
 *   - Packet number encode / decode with truncation
 *
 * Encryption/decryption of the payload happens in crisptls's
 * quic_packet.c (crisptls_quic_packet_encrypt / decrypt).
 * Header protection is applied *after* encryption via
 * crisptls_quic_apply_hp.
 *
 * This module only manages bytes and structure.
 */

#ifndef QUIC_PACKET_H
#define QUIC_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Long packet type bits (in the first byte, after 0x80 | 0x40) */
#define QUIC_LONG_INITIAL   0x00
#define QUIC_LONG_0RTT      0x10
#define QUIC_LONG_HANDSHAKE 0x20
#define QUIC_LONG_RETRY     0x30

/* First byte masks */
#define QUIC_HDR_LONG       0x80   /* 1 = long header, 0 = short */
#define QUIC_HDR_FIXED      0x40   /* fixed bit — must be 1 */
#define QUIC_HDR_TYPE_MASK  0x30   /* long header: 2-bit type */

/* Short header (1-RTT) first byte layout:
 *   1 S R R K P P
 * where S = spin, RR = reserved, K = key phase, PP = PN length - 1
 */
#define QUIC_HDR_SPIN       0x20
#define QUIC_HDR_RESERVED   0x18
#define QUIC_HDR_KEY_PHASE  0x04
#define QUIC_HDR_PN_LEN_MASK 0x03

#define QUIC_MAX_CID_LEN 20

/* Long header packet header (Initial / Handshake / 0-RTT) */
typedef struct {
    uint8_t  first_byte;       /* 0x80 | 0x40 | type | pn_len - 1 */
    uint32_t version;
    uint8_t  dcid_len;
    uint8_t  dcid[QUIC_MAX_CID_LEN];
    uint8_t  scid_len;
    uint8_t  scid[QUIC_MAX_CID_LEN];
    /* Initial only: */
    int      has_token;
    uint64_t token_len;
    const uint8_t *token;
    /* Length field: covers PN + payload (only for long headers) */
    uint64_t length;
    /* Packet number (unencoded, up to 4 bytes) */
    uint8_t  pn_len;           /* 1..4 */
    uint32_t packet_number;    /* truncated to pn_len bytes on the wire */
} quic_long_hdr_t;

/* Short header packet header (1-RTT) */
typedef struct {
    uint8_t  first_byte;
    uint8_t  dcid_len;         /* implicit — from connection state */
    uint8_t  dcid[QUIC_MAX_CID_LEN];
    uint8_t  pn_len;
    uint32_t packet_number;
} quic_short_hdr_t;

/* ---- Variable-length packet number (RFC 9000 §17.1) ----
 *
 * Only the low `pn_len` bytes of the packet number are on the wire.
 * The receiver reconstructs the full number from the largest ACKed
 * packet number it has seen.
 */

/* How many bytes are needed to encode a PN delta from `largest_acked`?
 * Returns 1, 2, 3, or 4. */
int quic_pn_len_for(uint64_t full_pn, uint64_t largest_acked);

/* Reconstruct the full packet number from the truncated one.
 * `truncated` is the low `pn_len` bytes as a uint32.
 * `largest_pn` is the largest PN the receiver has processed (or 0). */
uint64_t quic_pn_reconstruct(uint32_t truncated, size_t pn_len,
                              uint64_t largest_pn);

/* ---- Long header encode/decode ---- */

/* Write the long header into buf. Returns header length or -1.
 * Does NOT include the payload. The `length` field must already
 * be set to (pn_len + ciphertext_len + 16). */
int quic_long_hdr_encode(const quic_long_hdr_t *h,
                          uint8_t *buf, size_t cap);

/* Read the long header from buf. Fills h. Returns header length
 * (position of first payload byte) or -1. */
int quic_long_hdr_decode(const uint8_t *buf, size_t cap,
                          quic_long_hdr_t *h);

/* ---- Short header encode/decode ---- */

int quic_short_hdr_encode(const quic_short_hdr_t *h,
                           uint8_t *buf, size_t cap);

int quic_short_hdr_decode(const uint8_t *buf, size_t cap,
                           size_t dcid_len, quic_short_hdr_t *h);

#endif /* QUIC_PACKET_H */
