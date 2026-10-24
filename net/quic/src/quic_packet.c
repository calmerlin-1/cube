/** quic_packet.c — QUIC packet header framing. */

#include "quic_packet.h"
#include "quic_varint.h"
#include <string.h>

/* ---- packet number helpers ---- */

int quic_pn_len_for(uint64_t full_pn, uint64_t largest_acked) {
    /* RFC 9000 §17.1: encode enough bytes to distinguish full_pn
     * from any already-acked PN. Simplest safe bound: at least
     * 1 byte, more if the delta is large. */
    uint64_t delta = full_pn > largest_acked
                     ? full_pn - largest_acked
                     : 1;
    if (delta < (1ULL << 7))  return 1;
    if (delta < (1ULL << 15)) return 2;
    if (delta < (1ULL << 23)) return 3;
    return 4;
}

uint64_t quic_pn_reconstruct(uint32_t truncated, size_t pn_len,
                              uint64_t largest_pn) {
    /* RFC 9000 §A.3: reconstruct full packet number from truncated. */
    uint64_t pn_win = 1ULL << (pn_len * 8);
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;

    uint64_t candidate = (largest_pn & ~pn_mask) | truncated;
    if (candidate + pn_hwin <= largest_pn &&
        candidate < (1ULL << 62) - pn_win) {
        return candidate + pn_win;
    }
    if (candidate > largest_pn + pn_hwin && candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

/* ---- helpers ---- */

static int w_u8(uint8_t *b, size_t cap, size_t *w, uint8_t v) {
    if (*w + 1 > cap) return -1;
    b[(*w)++] = v;
    return 0;
}
static int w_u32be(uint8_t *b, size_t cap, size_t *w, uint32_t v) {
    if (*w + 4 > cap) return -1;
    b[(*w)++] = (uint8_t)(v >> 24);
    b[(*w)++] = (uint8_t)(v >> 16);
    b[(*w)++] = (uint8_t)(v >> 8);
    b[(*w)++] = (uint8_t)(v);
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

/* ---- long header ---- */

int quic_long_hdr_encode(const quic_long_hdr_t *h,
                          uint8_t *buf, size_t cap) {
    if (!h || !buf) return -1;
    if (h->dcid_len > QUIC_MAX_CID_LEN) return -1;
    if (h->scid_len > QUIC_MAX_CID_LEN) return -1;
    if (h->pn_len < 1 || h->pn_len > 4) return -1;

    size_t w = 0;

    /* First byte: 1 1 type(2) pn_len-1(2) */
    uint8_t fb = 0xc0 | (h->first_byte & QUIC_HDR_TYPE_MASK) |
                 (uint8_t)(h->pn_len - 1);
    if (w_u8(buf, cap, &w, fb) < 0) return -1;

    /* Version */
    if (w_u32be(buf, cap, &w, h->version) < 0) return -1;

    /* DCID */
    if (w_u8(buf, cap, &w, h->dcid_len) < 0) return -1;
    if (w_bytes(buf, cap, &w, h->dcid, h->dcid_len) < 0) return -1;

    /* SCID */
    if (w_u8(buf, cap, &w, h->scid_len) < 0) return -1;
    if (w_bytes(buf, cap, &w, h->scid, h->scid_len) < 0) return -1;

    /* Token (Initial only) */
    if (h->has_token) {
        if (w_var(buf, cap, &w, h->token_len) < 0) return -1;
        if (h->token_len > 0 && h->token)
            if (w_bytes(buf, cap, &w, h->token, h->token_len) < 0) return -1;
    }

    /* Length field: PN + ciphertext + tag */
    if (w_var(buf, cap, &w, h->length) < 0) return -1;

    /* Packet number (truncated) */
    for (int i = h->pn_len - 1; i >= 0; i--) {
        if (w_u8(buf, cap, &w,
                 (uint8_t)(h->packet_number >> (8 * i))) < 0) return -1;
    }
    return (int)w;
}

int quic_long_hdr_decode(const uint8_t *buf, size_t cap,
                          quic_long_hdr_t *h) {
    if (!buf || !h || cap < 7) return -1;
    memset(h, 0, sizeof(*h));

    size_t r = 0;
    uint8_t fb = buf[r++];
    if (!(fb & QUIC_HDR_LONG)) return -1;
    if (!(fb & QUIC_HDR_FIXED)) return -1;

    h->first_byte = fb;
    h->pn_len = (fb & QUIC_HDR_PN_LEN_MASK) + 1;

    /* Version */
    if (r + 4 > cap) return -1;
    h->version = ((uint32_t)buf[r] << 24) | ((uint32_t)buf[r+1] << 16) |
                 ((uint32_t)buf[r+2] << 8) | buf[r+3];
    r += 4;

    /* DCID */
    if (r >= cap) return -1;
    h->dcid_len = buf[r++];
    if (h->dcid_len > QUIC_MAX_CID_LEN) return -1;
    if (r + h->dcid_len > cap) return -1;
    memcpy(h->dcid, buf + r, h->dcid_len);
    r += h->dcid_len;

    /* SCID */
    if (r >= cap) return -1;
    h->scid_len = buf[r++];
    if (h->scid_len > QUIC_MAX_CID_LEN) return -1;
    if (r + h->scid_len > cap) return -1;
    memcpy(h->scid, buf + r, h->scid_len);
    r += h->scid_len;

    /* Token (Initial only) */
    uint8_t type = (fb & QUIC_HDR_TYPE_MASK);
    if (type == QUIC_LONG_INITIAL) {
        uint64_t tlen = 0;
        if (r_var(buf, cap, &r, &tlen) < 0) return -1;
        if (r + tlen > cap) return -1;
        h->has_token = 1;
        h->token_len = tlen;
        h->token = buf + r;
        r += (size_t)tlen;
    }

    /* Length */
    uint64_t len = 0;
    if (r_var(buf, cap, &r, &len) < 0) return -1;
    h->length = len;

    /* Packet number */
    if (h->pn_len > 4) return -1;
    if (r + h->pn_len > cap) return -1;
    uint32_t pn = 0;
    for (uint8_t i = 0; i < h->pn_len; i++) {
        pn = (pn << 8) | buf[r++];
    }
    h->packet_number = pn;

    return (int)r;
}

/* ---- short header ---- */

int quic_short_hdr_encode(const quic_short_hdr_t *h,
                           uint8_t *buf, size_t cap) {
    if (!h || !buf) return -1;
    if (h->dcid_len > QUIC_MAX_CID_LEN) return -1;
    if (h->pn_len < 1 || h->pn_len > 4) return -1;

    size_t w = 0;
    /* First byte: 0 1 spin res res keyphase pn_len-1 */
    uint8_t fb = QUIC_HDR_FIXED |
                 (h->first_byte & (QUIC_HDR_SPIN | QUIC_HDR_KEY_PHASE)) |
                 (uint8_t)(h->pn_len - 1);
    if (w_u8(buf, cap, &w, fb) < 0) return -1;

    if (w_bytes(buf, cap, &w, h->dcid, h->dcid_len) < 0) return -1;

    for (int i = h->pn_len - 1; i >= 0; i--) {
        if (w_u8(buf, cap, &w,
                 (uint8_t)(h->packet_number >> (8 * i))) < 0) return -1;
    }
    return (int)w;
}

int quic_short_hdr_decode(const uint8_t *buf, size_t cap,
                           size_t dcid_len, quic_short_hdr_t *h) {
    if (!buf || !h || cap < 1 + dcid_len) return -1;
    memset(h, 0, sizeof(*h));

    size_t r = 0;
    uint8_t fb = buf[r++];
    if (fb & QUIC_HDR_LONG) return -1;   /* not short header */
    if (!(fb & QUIC_HDR_FIXED)) return -1;

    h->first_byte = fb;
    h->pn_len = (fb & QUIC_HDR_PN_LEN_MASK) + 1;

    if (dcid_len > QUIC_MAX_CID_LEN) return -1;
    h->dcid_len = (uint8_t)dcid_len;
    memcpy(h->dcid, buf + r, dcid_len);
    r += dcid_len;

    if (h->pn_len > 4) return -1;
    if (r + h->pn_len > cap) return -1;
    uint32_t pn = 0;
    for (uint8_t i = 0; i < h->pn_len; i++) {
        pn = (pn << 8) | buf[r++];
    }
    h->packet_number = pn;

    return (int)r;
}
