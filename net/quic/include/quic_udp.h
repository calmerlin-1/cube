/** quic_udp.h — UDP socket wrapper for QUIC.
 *
 * QUIC runs over UDP. This module provides a thin, nonblocking-ish
 * wrapper with:
 *   - bind/connect helpers
 *   - send/recv with timeout
 *   - timestamping (for RTT measurement)
 *
 * No DNS resolution here — caller provides a resolved IP.
 */

#ifndef QUIC_UDP_H
#define QUIC_UDP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

typedef struct {
    int      fd;
    uint64_t last_send_ns;
    uint64_t last_recv_ns;
    int      family;   /* AF_INET or AF_INET6 */
} quic_udp_t;

/* Create an unbound UDP socket for `family` (AF_INET / AF_INET6). */
int quic_udp_open(quic_udp_t *u, int family);

/* Connect to a peer at `ip` (dotted string) `port`. */
int quic_udp_connect(quic_udp_t *u, const char *ip, uint16_t port);

/* Set recv timeout in milliseconds (0 = blocking). */
int quic_udp_set_timeout(quic_udp_t *u, int timeout_ms);

/* Send `len` bytes. Returns bytes sent or -1. */
int quic_udp_send(quic_udp_t *u, const void *buf, size_t len);

/* Receive up to `cap` bytes. Returns bytes received, 0 on timeout, -1 on error.
 * If peer_addr_out is non-NULL, fills the sender's address and its length. */
int quic_udp_recv(quic_udp_t *u, void *buf, size_t cap,
                   struct sockaddr_storage *peer_addr_out,
                   socklen_t *peer_len_out);

/* Close. Safe to call twice. */
void quic_udp_close(quic_udp_t *u);

/* Get a monotonic nanosecond timestamp. */
uint64_t quic_now_ns(void);

#endif /* QUIC_UDP_H */
