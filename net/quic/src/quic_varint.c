/** quic_varint.c — RFC 9000 §16 variable-length integers. */

#include "quic_varint.h"

int quic_varint_len(uint64_t v) {
    if (v > QUIC_VARINT_MAX) return -1;
    if (v < 64)            return 1;
    if (v < 16384)         return 2;
    if (v < (1ULL << 30))  return 4;
    return 8;
}

int quic_varint_encode(uint64_t v, uint8_t *buf, size_t cap) {
    if (!buf) return -1;
    if (v > QUIC_VARINT_MAX) return -1;

    int len = quic_varint_len(v);
    if ((size_t)len > cap) return -1;

    switch (len) {
        case 1:
            buf[0] = (uint8_t)v;
            break;
        case 2:
            buf[0] = (uint8_t)(0x40 | (v >> 8));
            buf[1] = (uint8_t)(v);
            break;
        case 4:
            buf[0] = (uint8_t)(0x80 | (v >> 24));
            buf[1] = (uint8_t)(v >> 16);
            buf[2] = (uint8_t)(v >> 8);
            buf[3] = (uint8_t)(v);
            break;
        case 8:
            buf[0] = (uint8_t)(0xc0 | (v >> 56));
            buf[1] = (uint8_t)(v >> 48);
            buf[2] = (uint8_t)(v >> 40);
            buf[3] = (uint8_t)(v >> 32);
            buf[4] = (uint8_t)(v >> 24);
            buf[5] = (uint8_t)(v >> 16);
            buf[6] = (uint8_t)(v >> 8);
            buf[7] = (uint8_t)(v);
            break;
        default:
            return -1;
    }
    return len;
}

int quic_varint_decode_len(const uint8_t *buf, size_t cap, size_t len,
                            uint64_t *out) {
    if (!buf || !out) return -1;
    if ((size_t)len > cap) return -1;

    uint64_t v = 0;
    switch (len) {
        case 1:
            if ((buf[0] & 0xc0) != 0x00) return -1;
            v = buf[0] & 0x3f;
            break;
        case 2:
            if ((buf[0] & 0xc0) != 0x40) return -1;
            v = ((uint64_t)(buf[0] & 0x3f) << 8) | buf[1];
            break;
        case 4:
            if ((buf[0] & 0xc0) != 0x80) return -1;
            v = ((uint64_t)(buf[0] & 0x3f) << 24) |
                ((uint64_t)buf[1] << 16) |
                ((uint64_t)buf[2] << 8)  | buf[3];
            break;
        case 8:
            if ((buf[0] & 0xc0) != 0xc0) return -1;
            v = ((uint64_t)(buf[0] & 0x3f) << 56) |
                ((uint64_t)buf[1] << 48) |
                ((uint64_t)buf[2] << 40) |
                ((uint64_t)buf[3] << 32) |
                ((uint64_t)buf[4] << 24) |
                ((uint64_t)buf[5] << 16) |
                ((uint64_t)buf[6] << 8)  | buf[7];
            break;
        default:
            return -1;
    }
    if (v > QUIC_VARINT_MAX) return -1;
    *out = v;
    return (int)len;
}

int quic_varint_decode(const uint8_t *buf, size_t cap, uint64_t *out) {
    if (!buf || cap < 1) return -1;
    size_t len = (size_t)1 << (buf[0] >> 6);  /* 1, 2, 4, or 8 */
    return quic_varint_decode_len(buf, cap, len, out);
}
