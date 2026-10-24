/** ext_sigalgs.c — signature_algorithms. */

#include "extensions.h"

size_t ext_sigalgs_build(const uint16_t *sigalgs, uint8_t *out, size_t cap) {
    if (!sigalgs) return 0;
    size_t count = 0;
    while (sigalgs[count]) count++;
    if (2 + count * 2 > cap) return 0;
    size_t w = 0;
    out[w++] = (uint8_t)((count * 2) >> 8);
    out[w++] = (uint8_t)((count * 2) & 0xFF);
    for (size_t i = 0; i < count; i++) {
        out[w++] = (uint8_t)(sigalgs[i] >> 8);
        out[w++] = (uint8_t)(sigalgs[i] & 0xFF);
    }
    return w;
}
