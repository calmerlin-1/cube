/** quic_udp_test.c — loopback UDP send/recv. No network needed. */

#include "quic_udp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void) {
    int ok = 1;

    /* Receiver: bind to 127.0.0.1:0 to get an ephemeral port */
    int rx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx_fd < 0) { printf("socket failed\n"); return 1; }

    struct sockaddr_in rx_addr;
    memset(&rx_addr, 0, sizeof(rx_addr));
    rx_addr.sin_family = AF_INET;
    rx_addr.sin_port = 0;
    rx_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(rx_fd, (struct sockaddr *)&rx_addr, sizeof(rx_addr)) != 0) {
        printf("bind failed\n"); close(rx_fd); return 1;
    }
    socklen_t alen = sizeof(rx_addr);
    getsockname(rx_fd, (struct sockaddr *)&rx_addr, &alen);
    uint16_t port = ntohs(rx_addr.sin_port);
    printf("rx port: %u\n", port);

    /* Sender: use our wrapper */
    quic_udp_t tx;
    if (quic_udp_open(&tx, AF_INET) != 0) { printf("open failed\n"); return 1; }
    if (quic_udp_connect(&tx, "127.0.0.1", port) != 0) {
        printf("connect failed\n"); return 1;
    }

    /* Send a test payload */
    const char *msg = "hello quic udp";
    int sent = quic_udp_send(&tx, msg, strlen(msg));
    printf("sent %d bytes\n", sent);
    if (sent != (int)strlen(msg)) ok = 0;

    /* Receive on the raw socket */
    char buf[64];
    ssize_t r = recv(rx_fd, buf, sizeof(buf) - 1, 0);
    if (r > 0) {
        buf[r] = 0;
        printf("rx: '%s'\n", buf);
        if (strcmp(buf, msg) != 0) ok = 0;
    } else {
        printf("rx failed\n");
        ok = 0;
    }

    /* Now test our recv path: send back from rx_fd to tx.fd */
    int tx_port = 0;
    {
        struct sockaddr_in tx_addr;
        socklen_t tl = sizeof(tx_addr);
        if (getsockname(tx.fd, (struct sockaddr *)&tx_addr, &tl) == 0)
            tx_port = ntohs(tx_addr.sin_port);
    }
    struct sockaddr_in tx_peer;
    memset(&tx_peer, 0, sizeof(tx_peer));
    tx_peer.sin_family = AF_INET;
    tx_peer.sin_port = htons((uint16_t)tx_port);
    tx_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const char *reply = "reply from rx";
    sendto(rx_fd, reply, strlen(reply), 0,
           (struct sockaddr *)&tx_peer, sizeof(tx_peer));

    quic_udp_set_timeout(&tx, 500);
    struct sockaddr_storage peer;
    socklen_t peer_len = 0;
    int got = quic_udp_recv(&tx, buf, sizeof(buf) - 1, &peer, &peer_len);
    if (got > 0) {
        buf[got] = 0;
        printf("tx recv: '%s'\n", buf);
        if (strcmp(buf, reply) != 0) ok = 0;
    } else {
        printf("tx recv failed (got=%d)\n", got);
        ok = 0;
    }

    /* Timeout path: recv again, should return 0 on timeout */
    int t = quic_udp_recv(&tx, buf, sizeof(buf), NULL, NULL);
    printf("timeout test: got=%d (expect 0)\n", t);
    if (t != 0) ok = 0;

    quic_udp_close(&tx);
    close(rx_fd);

    printf("\n");
    printf(ok ? "ALL UDP TESTS PASSED\n" : "SOME UDP TESTS FAILED\n");
    return ok ? 0 : 1;
}
