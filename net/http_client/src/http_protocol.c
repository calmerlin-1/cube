/** http_protocol.c — protocol capability registry. */

#include "http_protocol.h"
#include <string.h>
#include <ctype.h>

static const http_protocol_t P_HTTP1 = {
    HTTP_PROTO_HTTP1, "http/1.1", "http/1.1",
    HTTP_PCAP_TLS | HTTP_PCAP_ALPN, "tcp"
};
static const http_protocol_t P_H2 = {
    HTTP_PROTO_H2, "h2", "h2",
    HTTP_PCAP_TLS | HTTP_PCAP_ALPN | HTTP_PCAP_STREAM, "tcp"
};
static const http_protocol_t P_H3 = {
    HTTP_PROTO_H3, "h3", "h3",
    HTTP_PCAP_TLS | HTTP_PCAP_ALPN | HTTP_PCAP_STREAM | HTTP_PCAP_QUIC |
    HTTP_PCAP_EXPERIMENTAL, "quic"
};

static const http_protocol_t *const TABLE[] = {
    &P_HTTP1, &P_H2, &P_H3, NULL
};

static int ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++, cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

const http_protocol_t *const *http_protocol_all(void) { return TABLE; }

const http_protocol_t *http_protocol_by_name(const char *name) {
    if (!name) return NULL;
    for (int i = 0; TABLE[i]; i++)
        if (ci_eq(TABLE[i]->name, name) || ci_eq(TABLE[i]->alpn, name))
            return TABLE[i];
    return NULL;
}

int http_protocol_available(const char *name) {
    const http_protocol_t *p = http_protocol_by_name(name);
    if (!p) return 0;
    /* QUIC/H3 framing is registered; sender is experimental
     * (h3_send_io) and not yet interop with real H3 servers. */
    if (p->caps & HTTP_PCAP_QUIC) return 0;
    return 1;
}

const http_protocol_t *http_protocol_for_alpn(const char *alpn) {
    if (alpn && ci_eq(alpn, "h2")) return &P_H2;
    if (alpn && ci_eq(alpn, "h3")) return &P_H3;
    return &P_HTTP1;
}
