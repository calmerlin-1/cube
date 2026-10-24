/** quic_udp.c — UDP socket wrapper for QUIC. */

#include "quic_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

uint64_t quic_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int quic_udp_open(quic_udp_t *u, int family) {
    if (!u) return -1;
    memset(u, 0, sizeof(*u));
    u->fd = socket(family, SOCK_DGRAM, 0);
    if (u->fd < 0) return -1;
    u->family = family;
    return 0;
}

int quic_udp_connect(quic_udp_t *u, const char *ip, uint16_t port) {
    if (!u || u->fd < 0 || !ip) return -1;

    if (u->family == AF_INET) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;
        if (connect(u->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
            return -1;
    } else {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &sa.sin6_addr) != 1) return -1;
        if (connect(u->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
            return -1;
    }
    return 0;
}

int quic_udp_set_timeout(quic_udp_t *u, int timeout_ms) {
    if (!u || u->fd < 0) return -1;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(u->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    if (setsockopt(u->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    return 0;
}

int quic_udp_send(quic_udp_t *u, const void *buf, size_t len) {
    if (!u || u->fd < 0) return -1;
    ssize_t r = send(u->fd, buf, len, 0);
    if (r < 0) return -1;
    u->last_send_ns = quic_now_ns();
    return (int)r;
}

int quic_udp_recv(quic_udp_t *u, void *buf, size_t cap,
                   struct sockaddr_storage *peer_addr_out,
                   socklen_t *peer_len_out) {
    if (!u || u->fd < 0) return -1;

    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    ssize_t r = recvfrom(u->fd, buf, cap, 0,
                          (struct sockaddr *)&peer, &peer_len);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;   /* timeout */
        if (errno == EINTR) return 0;
        return -1;
    }
    u->last_recv_ns = quic_now_ns();
    if (peer_addr_out) memcpy(peer_addr_out, &peer, peer_len);
    if (peer_len_out)  *peer_len_out = peer_len;
    return (int)r;
}

void quic_udp_close(quic_udp_t *u) {
    if (!u) return;
    if (u->fd >= 0) {
        close(u->fd);
        u->fd = -1;
    }
}
