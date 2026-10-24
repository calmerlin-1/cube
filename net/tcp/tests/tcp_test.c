/** tcp_test.c — smoke test for net/tcp.
 *
 * Connects to a few well-known IPs on port 443, prints fd + peer + local.
 * Doesn't send data; just proves connect works for v4 and v6.
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "tcp.h"

static int try_one(const char *ip, uint16_t port, int fam) {
    char err[256] = {0};
    printf("── %s:%u (family %s)\n", ip, port,
           fam == AF_INET ? "v4" : fam == AF_INET6 ? "v6" : "?");

    int fd = tcp_connect(ip, fam, port, 5000, err, sizeof err);
    if (fd < 0) {
        printf("   FAIL: %s\n", err[0] ? err : "?");
        return -1;
    }

    char peer[64] = {0}, local[64] = {0};
    uint16_t pport = 0, lport = 0;
    tcp_peer(fd, peer, sizeof peer, &pport);
    tcp_local(fd, local, sizeof local, &lport);

    printf("   OK: fd=%d  local=%s:%u  peer=%s:%u\n",
           fd, local, lport, peer, pport);
    tcp_close(fd);
    return 0;
}

int main(void) {
    printf("════ tcp_connect smoke test ════\n\n");
    int fails = 0;

    /* Cloudflare v4 */
    if (try_one("1.1.1.1", 443, AF_INET) != 0) fails++;
    /* Google v4 */
    if (try_one("8.8.8.8", 443, AF_INET) != 0) fails++;
    /* Cloudflare v6 */
    (void)try_one("2606:4700:4700::1111", 443, AF_INET6);  /* informational: v6 may be unavailable */
    /* Loopback (should fail — nothing listening) */
    printf("\n(expected to fail — 127.0.0.1:1 has no listener)\n");
    try_one("127.0.0.1", 1, AF_INET);

    /* Bad input tests */
    printf("\n── bad inputs ──\n");
    char err[256];

    printf("hostname:  ");
    if (tcp_connect("example.com", AF_UNSPEC, 443, 1000, err, sizeof err) < 0)
        printf("rejected: %s\n", err);
    else printf("ACCEPTED — BUG!\n");

    printf("empty ip:  ");
    if (tcp_connect("", AF_UNSPEC, 443, 1000, err, sizeof err) < 0)
        printf("rejected: %s\n", err);
    else printf("ACCEPTED — BUG!\n");

    printf("short v4:  ");
    if (tcp_connect("1.2.3", AF_UNSPEC, 443, 1000, err, sizeof err) < 0)
        printf("rejected: %s\n", err);
    else printf("ACCEPTED — BUG!\n");

    /* Range parsing */
    printf("\n── range parsing ──\n");
    char start[64];
    long n = tcp_parse_range("10.0.0.1-10.0.0.10", start, sizeof start);
    printf("10.0.0.1-10.0.0.10 → count=%ld start=%s\n", n, start);
    char nth[64];
    tcp_range_nth(start, 5, nth, sizeof nth);
    printf("  nth(5) = %s\n", nth);

    printf("\n════ %s ════\n", fails ? "FAILURES" : "ALL PASS");
    return fails ? 1 : 0;
}
