/** ext_sni.c — Server Name Indication. */

#include "extensions.h"
#include <string.h>

/** Build SNI extension body. */
size_t ext_sni_build(const char *hostname, uint8_t *out, size_t cap) {
    if (!hostname) return 0;
    size_t hlen = strlen(hostname);
    if (hlen > 255) return 0;
    if (cap < 2 + 1 + 2 + hlen) return 0;
    size_t w = 0;
    out[w++] = 0;                       /* name_type: host_name */
    out[w++] = (uint8_t)(hlen >> 8);
    out[w++] = (uint8_t)(hlen & 0xFF);
    memcpy(out + w, hostname, hlen);
    w += hlen;
    /* prepend 2-byte list length */
    size_t total = w;
    if (total + 2 > cap) return 0;
    memmove(out + 2, out, total);
    out[0] = (uint8_t)(total >> 8);
    out[1] = (uint8_t)(total & 0xFF);
    return total + 2;
}
