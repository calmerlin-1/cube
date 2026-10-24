/** dns_udp.c — UDP transport for DNS queries. */

#include "dns_transport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

int dns_transport_udp(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    struct addrinfo *r;
    for (r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    uint64_t t0 = now_ns();
    if (send(fd, query, qlen, 0) != (ssize_t)qlen) {
        close(fd);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0) { close(fd); return 0; }

    ssize_t n = recv(fd, resp, resp_cap, 0);
    uint64_t t1 = now_ns();
    close(fd);
    if (n <= 0) return -1;
    if (out_latency_ns) *out_latency_ns = t1 - t0;
    return (int)n;
}
