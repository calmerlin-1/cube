/** dns_doh.c — DNS-over-HTTPS transport (RFC 8484).
 *
 * Uses cube's own TLS (crisptls). POST a binary DNS query to the
 * /dns-query endpoint of a DoH server. The server returns a binary
 * DNS response. HTTP/1.1 with Connection: close.
 */

#include "dns_transport.h"
#include "crisptls.h"
#include "crisptls_policy.h"
#include "crisptls_types.h"

#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int starts_with_ci(const char *s, const char *prefix) {
    while (*prefix) {
        char a = *s, b = *prefix;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
        s++; prefix++;
    }
    return 1;
}

static int tcp_dial(const char *host, uint16_t port, uint32_t timeout_ms) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;

        if (timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int dns_transport_doh(const char *url,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns)
{
    if (!url || !query || !resp) return -1;

    if (!starts_with_ci(url, "https://")) return -1;
    const char *p = url + 8;
    const char *host_start = p;
    const char *path_start = NULL;
    const char *port_start = NULL;
    while (*p && *p != '/' && *p != ':') p++;
    if (*p == ':') { port_start = p + 1; while (*p && *p != '/') p++; }
    if (*p == '/') path_start = p;

    char host[256];
    size_t hlen = (port_start ? (size_t)(port_start - 1 - host_start)
                              : (path_start ? (size_t)(path_start - host_start)
                                            : strlen(host_start)));
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    uint16_t port = 443;
    if (port_start) port = (uint16_t)atoi(port_start);
    const char *path = path_start ? path_start : "/dns-query";

    int fd = tcp_dial(host, port, timeout_ms);
    if (fd < 0) return -1;

    crisptls_policy_t pol;
    crisptls_policy_default(&pol);
    pol.alpn = "http/1.1";
    pol.handshake_timeout_ms = timeout_ms;
    pol.read_timeout_ms      = timeout_ms;
    pol.write_timeout_ms     = timeout_ms;

    crisptls_ctx_t *ctx = crisptls_ctx_new(&pol);
    if (!ctx) { close(fd); return -1; }

    uint64_t t0 = now_ns();
    crisptls_conn_t *conn = crisptls_connect(ctx, fd, host);
    if (!conn) {
        crisptls_ctx_free(ctx);
        close(fd);
        return -1;
    }

    char headers[1024];
    int hlen2 = snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: flywheel-dns/1.0\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, qlen);

    if (hlen2 < 0 || hlen2 >= (int)sizeof(headers) ||
        crisptls_write(conn, headers, (size_t)hlen2) != hlen2 ||
        crisptls_write(conn, query, qlen) != (ssize_t)qlen)
    {
        crisptls_close(conn);
        crisptls_ctx_free(ctx);
        close(fd);
        return -1;
    }

    uint8_t buf[65536];
    size_t total = 0;
    for (;;) {
        ssize_t n = crisptls_read(conn, buf + total, sizeof(buf) - total - 1);
        if (n <= 0) break;      /* EOF or error */
        total += (size_t)n;
        if (total >= sizeof(buf) - 1) break;
    }

    crisptls_close(conn);
    crisptls_ctx_free(ctx);
    close(fd);

    if (total < 16) return -1;
    buf[total] = '\0';

    char *hdr_end = strstr((char *)buf, "\r\n\r\n");
    if (!hdr_end) return -1;
    size_t hdr_len = (size_t)(hdr_end - (char *)buf) + 4;

    if (memcmp(buf, "HTTP/1.", 7) != 0) return -1;
    char *sp = (char *)buf + 8;
    while (*sp && *sp != ' ') sp++;
    if (*sp) sp++;
    int status = atoi(sp);
    if (status != 200) return -1;

    uint8_t *body = buf + hdr_len;
    size_t body_len = total - hdr_len;
    if (body_len < 12) return -1;

    if (!(body[2] & 0x80)) return -1;

    size_t copy = body_len < resp_cap ? body_len : resp_cap;
    memcpy(resp, body, copy);

    if (out_latency_ns) *out_latency_ns = now_ns() - t0;
    return (int)copy;
}
