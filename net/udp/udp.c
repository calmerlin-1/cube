/** udp.c — minimal UDP socket layer for QUIC. */
#include "udp.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

int udp_socket(int family) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

int udp_connect(int fd, const char *ip, int family, uint16_t port,
                uint32_t timeout_ms) {
    (void)timeout_ms;
    if (family == AF_INET) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;
        return connect(fd, (struct sockaddr *)&sa, sizeof sa);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &sa.sin6_addr) != 1) return -1;
        return connect(fd, (struct sockaddr *)&sa, sizeof sa);
    }
    return -1;
}

int udp_send(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms) {
    struct pollfd pfd = { fd, POLLOUT, 0 };
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0) return -1;
    ssize_t n = send(fd, buf, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

ssize_t udp_recv(int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    struct pollfd pfd = { fd, POLLIN, 0 };
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0) return -1;
    return recv(fd, buf, cap, 0);
}

void udp_close(int fd) {
    if (fd >= 0) close(fd);
}
