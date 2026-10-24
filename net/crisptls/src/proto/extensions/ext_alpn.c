/** ext_alpn.c — ALPN. */

#include "extensions.h"
#include <string.h>

/** Build ALPN extension body from comma-separated list. */
size_t ext_alpn_build(const char *protocols, uint8_t *out, size_t cap) {
    if (!protocols) return 0;
    size_t w = 2;   /* reserve 2 bytes for total length */
    const char *p = protocols;
    while (*p && w < cap) {
        const char *comma = strchr(p, ',');
        size_t l = comma ? (size_t)(comma - p) : strlen(p);
        if (l > 255) break;
        if (w + 1 + l > cap) break;
        out[w++] = (uint8_t)l;
        memcpy(out + w, p, l);
        w += l;
        if (!comma) break;
        p = comma + 1;
    }
    size_t body_len = w - 2;
    out[0] = (uint8_t)(body_len >> 8);
    out[1] = (uint8_t)(body_len & 0xFF);
    return w;
}
