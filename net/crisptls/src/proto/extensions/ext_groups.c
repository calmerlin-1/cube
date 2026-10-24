/** ext_groups.c — supported_groups, key_share. */

#include "extensions.h"

/** Build supported_groups extension body (RFC 8446 §4.2.7). */
size_t ext_supported_groups_build(const uint16_t *groups, uint8_t *out, size_t cap) {
    if (!groups) return 0;
    size_t count = 0;
    while (groups[count]) count++;
    size_t body_len = 2 + count * 2;
    if (body_len + 2 > cap) return 0;
    size_t w = 0;
    out[w++] = (uint8_t)((count * 2) >> 8);
    out[w++] = (uint8_t)((count * 2) & 0xFF);
    for (size_t i = 0; i < count; i++) {
        out[w++] = (uint8_t)(groups[i] >> 8);
        out[w++] = (uint8_t)(groups[i] & 0xFF);
    }
    return w;
}
