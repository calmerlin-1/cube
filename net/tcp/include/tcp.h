/** tcp.h — TCP connect for cube.
 *
 * Scope: take an already-resolved IP (v4 or v6), open a socket, connect,
 * return the raw fd. No DNS, no TLS, no URL parsing.
 *
 * Exposes everything: the fd is returned as a plain int. Tuning knobs
 * (nodelay, keepalive, non-blocking, buffer sizes) are separate calls.
 * I/O helpers wrap read/write with timeouts; callers may ignore them
 * and use raw read/write/poll on the fd.
 *
 * Accepts:
 *   "1.2.3.4"                     dotted quad
 *   "2606:4700::6814:179a"        IPv6 (any form)
 *   "::1"                          loopback v6
 *   "127.0.0.1"                    loopback v4
 *   "0.0.0.0"  "::"                wildcard (for listen, not used here)
 *   "10.0.0.0-10.0.0.255"          range (first address used; caller may
 *                                  iterate by calling tcp_expand_range)
 *
 * Rejects (returns -1 with errno = EINVAL):
 *   "example.com"                  hostname — DNS is a separate module
 *   "1.2.3"                        incomplete IPv4
 *   ""
 */
#ifndef CUBE_NET_TCP_H
#define CUBE_NET_TCP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ─── Connect ─────────────────────────────────────────────────────── */

/* Connect to an already-resolved IP.
 * - ip:         "1.2.3.4" or an IPv6 string. NOT a hostname.
 * - family:     AF_INET, AF_INET6, or AF_UNSPEC (auto from ip syntax).
 * - port:       1..65535.
 * - timeout_ms: total budget for socket + connect. 0 = block forever.
 * - err:        if non-NULL, human-readable reason on failure.
 * Returns fd >= 0 on success, -1 on failure (errno also set). */
int tcp_connect(const char *ip, int family, uint16_t port,
                uint32_t timeout_ms,
                char *err, size_t err_cap);

/* ─── Tuning ──────────────────────────────────────────────────────── */

int tcp_set_nodelay    (int fd, int on);   /* TCP_NODELAY         */
int tcp_set_keepalive  (int fd, int on);   /* SO_KEEPALIVE        */
int tcp_set_nonblocking(int fd, int on);   /* O_NONBLOCK          */
int tcp_set_rcvbuf     (int fd, int bytes);/* SO_RCVBUF           */
int tcp_set_sndbuf     (int fd, int bytes);/* SO_SNDBUF           */
int tcp_set_reuseaddr  (int fd, int on);   /* SO_REUSEADDR (pre-bind) */

/* ─── I/O with per-call timeout ───────────────────────────────────── */

/* Return bytes transferred, 0 on clean close (read only), -1 on error.
 * timeout_ms: 0 = block indefinitely. Otherwise use poll() internally. */
ssize_t tcp_read (int fd, void *buf, size_t n, uint32_t timeout_ms);
ssize_t tcp_write(int fd, const void *buf, size_t n, uint32_t timeout_ms);

/* Read/write exactly n bytes, looping. Returns 0 on success, -1 on error
 * or if fewer than n bytes could be read before close/timeout. */
int tcp_read_exact (int fd, void *buf, size_t n, uint32_t timeout_ms);
int tcp_write_all  (int fd, const void *buf, size_t n, uint32_t timeout_ms);

/* ─── Half-close / close ──────────────────────────────────────────── */

/* SHUT_WR: send FIN, keep reading. Some protocols need this (HTTP/1.0). */
int tcp_shutdown_write(int fd);

/* Close (idempotent; safe with fd < 0). */
void tcp_close(int fd);

/* ─── Peer / local info ───────────────────────────────────────────── */

/* Fill ip (dotted or v6) and port. Returns 0 on success, -1 on error.
 * ip_cap should be at least 46 bytes (INET6_ADDRSTRLEN). */
int tcp_peer (int fd, char *ip, size_t ip_cap, uint16_t *port);
int tcp_local(int fd, char *ip, size_t ip_cap, uint16_t *port);

/* ─── IP validation & helpers ─────────────────────────────────────── */

/* Return AF_INET, AF_INET6, or -1 if not a valid IP literal. */
int tcp_ip_family(const char *ip);

/* Range parsing: "10.0.0.1-10.0.0.10" → count = 10; fill start IP.
 * Only IPv4 ranges are supported in v1 (IPv6 ranges are enormous).
 * Returns number of addresses in the range (>= 1), or -1 if invalid. */
long tcp_parse_range(const char *spec, char *start_ip, size_t cap);

/* Given a start IP and an offset (0-based), write the Nth IP of the range.
 * Returns 0 on success, -1 on invalid input. */
int tcp_range_nth(const char *start_ip, long n, char *out, size_t cap);

/* Hostname check: returns 1 if `s` looks like a hostname (letters, dots,
 * hyphens, no valid IP syntax). Returns 0 if it's a valid IP or clearly
 * invalid. Useful for callers who want to route DNS vs. direct. */
int tcp_looks_like_hostname(const char *s);

#endif /* CUBE_NET_TCP_H */
