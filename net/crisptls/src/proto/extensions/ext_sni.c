/** ext_sni.c — Server Name Indication. */

#include "extensions.h"
#include <string.h>

/** Build SNI extension body. */
size_t ext_sni_build(const char *hostname, uint8_t *out, size_t cap) {
    if (!hostname || !*hostname) return 0;

    /* RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted in
     * HostName." Skip SNI for IP literals — return 0 so the caller omits
     * the extension entirely. Bracketed IPv6 ([::1]) and dotted-quad IPv4
     * both qualify. */
    if (hostname[0] == '[') return 0;                 /* bracketed IPv6 */
    {
        int dots = 0, digits = 0, all_ipv4 = 1;
        for (const char *p = hostname; *p; p++) {
            if (*p == '.') { if (digits == 0) { all_ipv4 = 0; break; } dots++; digits = 0; }
            else if (*p >= '0' && *p <= '9') digits++;
            else { all_ipv4 = 0; break; }
        }
        if (all_ipv4 && dots == 3 && digits > 0) return 0;  /* dotted-quad IPv4 */
    }

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
