/** quic_live_test.c — send a real QUIC ClientInitial to a live server. */
#include "quic_conn.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <ip> [port]\n", argv[0]); return 1; }
    const char *ip = argv[1];
    uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 443;

    quic_conn_t c;
    printf("[*] init conn to %s:%u\n", ip, port);
    if (quic_conn_init(&c, ip, port) != 0) { fprintf(stderr, "[!] init failed\n"); return 1; }

    printf("[+] scid=");
    for (int i = 0; i < c.scid_len; i++) printf("%02x", c.scid[i]);
    printf(" dcid=");
    for (int i = 0; i < c.dcid_len; i++) printf("%02x", c.dcid[i]);
    printf("\n");

    printf("[*] sending ClientInitial...\n");
    if (quic_conn_send_initial(&c) != 0) {
        fprintf(stderr, "[!] send_initial failed\n");
        quic_conn_free(&c);
        return 1;
    }
    printf("[+] sent %llu bytes\n", (unsigned long long)c.bytes_sent);

    printf("[*] waiting for response (timeout 500ms x 6)...\n");
    uint8_t buf[2048];
    int got = 0;
    for (int i = 0; i < 6; i++) {
        struct sockaddr_storage peer; socklen_t peer_len = 0;
        int r = quic_udp_recv(&c.udp, buf, sizeof(buf), &peer, &peer_len);
        if (r > 0) {
            printf("[+] received %d bytes\n", r);
            printf("    first 32 bytes: ");
            for (int j = 0; j < 32 && j < r; j++) printf("%02x", buf[j]);
            printf("\n");
            got = 1;
            break;
        } else if (r == 0) {
            printf("    (timeout)\n");
        } else {
            printf("[!] recv error\n");
            break;
        }
    }
    if (!got) printf("[-] no response\n");

    quic_conn_free(&c);
    printf("[*] done\n");
    return got ? 0 : 2;
}
