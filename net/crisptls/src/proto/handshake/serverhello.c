/** serverhello.c — parse ServerHello. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    uint16_t legacy_version;
    uint8_t  random[32];
    uint8_t  session_id_len;
    const uint8_t *session_id;
    uint16_t cipher_suite;
    uint8_t  compression;
    const uint8_t *extensions;
    size_t   extensions_len;
    /* parsed extension values */
    uint16_t selected_version;   /* from supported_versions */
    uint16_t selected_group;     /* from key_share */
    const uint8_t *server_pubkey;/* from key_share, 32 bytes */
    size_t   server_pubkey_len;
} server_hello_t;

/** Parse ServerHello. Returns 0 on success. */
int serverhello_parse(const uint8_t *buf, size_t len, server_hello_t *out) {
    if (!buf || !out || len < 38) return -1;
    memset(out, 0, sizeof(*out));

    const uint8_t *p = buf;
    const uint8_t *end = buf + len;

    out->legacy_version = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    memcpy(out->random, p, 32); p += 32;

    if (p >= end) return -1;
    out->session_id_len = *p++;
    if (p + out->session_id_len > end) return -1;
    out->session_id = p;
    p += out->session_id_len;

    if (p + 3 > end) return -1;
    out->cipher_suite = (uint16_t)((p[0] << 8) | p[1]); p += 2;
    out->compression = *p++;

    if (p + 2 <= end) {
        uint16_t ext_total = (uint16_t)((p[0] << 8) | p[1]); p += 2;
        if (p + ext_total > end) return -1;
        out->extensions = p;
        out->extensions_len = ext_total;

        const uint8_t *ep = p;
        const uint8_t *ee = p + ext_total;
        while (ep + 4 <= ee) {
            uint16_t type = (uint16_t)((ep[0] << 8) | ep[1]);
            uint16_t elen = (uint16_t)((ep[2] << 8) | ep[3]);
            ep += 4;
            if (ep + elen > ee) break;
            switch (type) {
                case 43: /* supported_versions */
                    if (elen == 2)
                        out->selected_version = (uint16_t)((ep[0] << 8) | ep[1]);
                    break;
                case 51: /* key_share */
                    if (elen >= 4) {
                        out->selected_group = (uint16_t)((ep[0] << 8) | ep[1]);
                        uint16_t klen = (uint16_t)((ep[2] << 8) | ep[3]);
                        if (4 + klen <= elen) {
                            out->server_pubkey = ep + 4;
                            out->server_pubkey_len = klen;
                        }
                    }
                    break;
            }
            ep += elen;
        }
    }

    if (out->selected_version == 0) {
        out->selected_version = out->legacy_version;
    }
    return 0;
}
