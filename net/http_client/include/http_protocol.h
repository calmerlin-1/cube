/** http_protocol.h — protocol registry.
 *
 * Adding a new HTTP mapping (e.g. a future h4) is one table row plus a
 * sender hook; callers should query capabilities instead of hardcoding
 * version checks.
 */
#ifndef CUBE_HTTP_PROTOCOL_H
#define CUBE_HTTP_PROTOCOL_H

typedef enum {
    HTTP_PROTO_HTTP1 = 0,
    HTTP_PROTO_H2,
    HTTP_PROTO_H3
} http_proto_id_t;

#define HTTP_PCAP_TLS       (1u << 0)
#define HTTP_PCAP_ALPN      (1u << 1)
#define HTTP_PCAP_STREAM    (1u << 2)
#define HTTP_PCAP_QUIC      (1u << 3)
#define HTTP_PCAP_EXPERIMENTAL (1u << 4)

typedef struct {
    http_proto_id_t id;
    const char     *name;     /* "http/1.1", "h2", "h3" */
    const char     *alpn;     /* wire ALPN token */
    unsigned        caps;
    const char     *transport;
} http_protocol_t;

/** NULL-terminated table of all registered protocols. */
const http_protocol_t *const *http_protocol_all(void);

/** Look up by name or ALPN token (case-insensitive). NULL if unknown. */
const http_protocol_t *http_protocol_by_name(const char *name);

/** 1 if this build can actually send over the protocol, 0 otherwise. */
int http_protocol_available(const char *name);

/** Best protocol for a negotiated ALPN token; HTTP/1.1 fallback. */
const http_protocol_t *http_protocol_for_alpn(const char *alpn);

#endif
