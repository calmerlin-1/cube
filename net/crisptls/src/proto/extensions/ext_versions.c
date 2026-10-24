/** ext_versions.c — supported_versions (TLS 1.3). */

#include "extensions.h"

size_t ext_supported_versions_build(const uint16_t *versions, uint8_t *out, size_t cap) {
    if (!versions) return 0;
    size_t count = 0;
    while (versions[count]) count++;
    if (1 + count * 2 > cap) return 0;
    size_t w = 0;
    out[w++] = (uint8_t)(count * 2);
    for (size_t i = 0; i < count; i++) {
        out[w++] = (uint8_t)(versions[i] >> 8);
        out[w++] = (uint8_t)(versions[i] & 0xFF);
    }
    return w;
}
