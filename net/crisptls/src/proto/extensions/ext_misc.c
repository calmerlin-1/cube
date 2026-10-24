/** ext_misc.c — padding, session_ticket, psk_key_exchange_modes, etc. */

#include "extensions.h"

size_t ext_empty_build(uint8_t *out, size_t cap) {
    (void)out; (void)cap;
    return 0;
}

size_t ext_write(uint16_t type, const uint8_t *body, uint16_t body_len,
                 uint8_t *out, size_t cap) {
    if (4 + body_len > cap) return 0;
    out[0] = (uint8_t)(type >> 8);
    out[1] = (uint8_t)(type & 0xFF);
    out[2] = (uint8_t)(body_len >> 8);
    out[3] = (uint8_t)(body_len & 0xFF);
    if (body_len) {
        extern void *memcpy(void *, const void *, unsigned long);
        memcpy(out + 4, body, body_len);
    }
    return 4 + body_len;
}
