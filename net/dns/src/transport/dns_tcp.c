/** dns_tcp.c — TCP transport for DNS (fallback on truncation). */

#include "dns_transport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <poll.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int read_full(int fd, uint8_t *buf, size_t want, uint32_t timeout_ms) {
    size_t got = 0;
    while (got < want) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0) return -1;
        ssize_t n = recv(fd, buf + got, want - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

int dns_transport_tcp(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    uint64_t t0 = now_ns();

    /* 2-byte length prefix */
    uint8_t hdr[2];
    hdr[0] = (uint8_t)(qlen >> 8);
    hdr[1] = (uint8_t)(qlen & 0xFF);
    if (send(fd, hdr, 2, 0) != 2) { close(fd); return -1; }
    if (send(fd, query, qlen, 0) != (ssize_t)qlen) { close(fd); return -1; }

    uint8_t lenb[2];
    if (read_full(fd, lenb, 2, timeout_ms) != 0) { close(fd); return 0; }
    uint16_t rlen = (uint16_t)((lenb[0] << 8) | lenb[1]);
    if (rlen > resp_cap) { close(fd); return -1; }
    if (read_full(fd, resp, rlen, timeout_ms) != 0) { close(fd); return 0; }
    uint64_t t1 = now_ns();
    close(fd);
    if (out_latency_ns) *out_latency_ns = t1 - t0;
    return (int)rlen;
}
