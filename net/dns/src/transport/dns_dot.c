/** dns_dot.c — DNS-over-TLS transport (RFC 7858).
 *
 * Uses cube's own TLS (crisptls), not OpenSSL. Same policy system as
 * the rest of the browser. DoT framing: 2-byte big-endian length prefix
 * before the query, same for the response.
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
#include <errno.h>
#include <time.h>
#include <netdb.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* TCP connect with optional timeout. Returns fd or -1. */
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

/* Read exactly `want` bytes via crisptls, waiting up to timeout_ms
 * between reads. poll() on the raw fd tells us when the next TLS
 * record arrives. */
static int read_full(crisptls_conn_t *conn, int fd,
                     uint8_t *buf, size_t want, uint32_t timeout_ms)
{
    /* crisptls buffers whole TLS records internally. After the first
     * crisptls_read, the socket may be empty while bytes remain in the
     * conn buffer. Never poll the raw fd — just call crisptls_read in
     * a loop; it respects pol.read_timeout_ms internally. */
    (void)fd; (void)timeout_ms;
    size_t got = 0;
    while (got < want) {
        ssize_t n = crisptls_read(conn, buf + got, want - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

int dns_transport_dot(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns)
{
    if (!host || !query || !resp) return -1;
    if (port == 0) port = 853;

    int fd = tcp_dial(host, port, timeout_ms);
    if (fd < 0) return -1;

    /* Build a DoT policy: default profile, no ALPN (raw DNS-over-TLS). */
    crisptls_policy_t pol;
    crisptls_policy_default(&pol);
    pol.alpn = NULL;
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

    /* RFC 7858 §3.3: 2-byte big-endian length prefix before the query. */
    uint8_t hdr[2];
    hdr[0] = (uint8_t)(qlen >> 8);
    hdr[1] = (uint8_t)(qlen & 0xFF);

    if (crisptls_write(conn, hdr, 2) != 2 ||
        crisptls_write(conn, query, qlen) != (ssize_t)qlen)
    {
        crisptls_close(conn);
        crisptls_ctx_free(ctx);
        close(fd);
        return -1;
    }

    /* read the response length prefix */
    uint8_t lenb[2];
    if (read_full(conn, fd, lenb, 2, timeout_ms) != 0) {
        crisptls_close(conn);
        crisptls_ctx_free(ctx);
        close(fd);
        return 0;   /* timeout — 0 signals "no answer" to the caller */
    }

    uint16_t rlen = (uint16_t)((lenb[0] << 8) | lenb[1]);
    if (rlen > resp_cap ||
        read_full(conn, fd, resp, rlen, timeout_ms) != 0)
    {
        crisptls_close(conn);
        crisptls_ctx_free(ctx);
        close(fd);
        return -1;
    }

    uint64_t t1 = now_ns();
    crisptls_close(conn);
    crisptls_ctx_free(ctx);
    close(fd);

    if (out_latency_ns) *out_latency_ns = t1 - t0;
    return (int)rlen;
}
