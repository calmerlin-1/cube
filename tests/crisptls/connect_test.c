/** connect_test.c — live TLS 1.3 handshake against a real server.
 *  Resolution via cube_dns (net/dns), handshake via crisptls. */

#include "crisptls.h"
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* ---------------------------------------------------------------
 * Resolve `host` using cube_dns, return first usable IP string.
 * Prefers IPv4; falls back to IPv6 if no A record.
 * --------------------------------------------------------------- */
static int resolve_host(const char *host, char *ip_out, size_t ip_cap,
                        int *family_out) {
    dns_resolver_t *r = dns_resolver_new_default();
    if (!r) { fprintf(stderr, "[dns] resolver_new failed\n"); return -1; }

    dns_answer_t ans;
    memset(&ans, 0, sizeof(ans));

    int rc = dns_resolve_dual(r, host, &ans);
    if (rc != DNS_OK) {
        fprintf(stderr, "[dns] resolve_dual(%s) failed: %s (%d)\n",
                host, dns_err_name(rc), rc);
        dns_resolver_free(r);
        return -1;
    }

    printf("[dns] %s -> %zu records (rcode=%u)\n", host, ans.count, ans.rcode);

    int found = 0;
    /* Prefer IPv4 */
    for (size_t i = 0; i < ans.count; i++) {
        if (ans.records[i].type == DNS_TYPE_A) {
            inet_ntop(AF_INET, ans.records[i].u.a.addr, ip_out, ip_cap);
            *family_out = AF_INET;
            printf("[dns]   A     %s  ttl=%u\n", ip_out, ans.records[i].ttl);
            found = 1;
            break;
        }
    }
    if (!found) {
        for (size_t i = 0; i < ans.count; i++) {
            if (ans.records[i].type == DNS_TYPE_AAAA) {
                inet_ntop(AF_INET6, ans.records[i].u.aaaa.addr, ip_out, ip_cap);
                *family_out = AF_INET6;
                printf("[dns]   AAAA  %s  ttl=%u\n", ip_out, ans.records[i].ttl);
                found = 1;
                break;
            }
        }
    }

    dns_answer_free(&ans);
    dns_resolver_free(r);
    return found ? 0 : -1;
}

static int tcp_connect_ip(const char *ip, int family, const char *port) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (family == AF_INET) {
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)atoi(port));
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            fprintf(stderr, "[tcp] connect %s:%s failed: %s\n", ip, port, strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 sa = {0};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons((uint16_t)atoi(port));
        if (inet_pton(AF_INET6, ip, &sa.sin6_addr) != 1) { close(fd); return -1; }
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            fprintf(stderr, "[tcp] connect [%s]:%s failed: %s\n", ip, port, strerror(errno));
            close(fd);
            return -1;
        }
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <host> [port]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    const char *port = argc > 2 ? argv[2] : "443";

    printf("[*] resolving %s via cube_dns\n", host);
    char ip[INET6_ADDRSTRLEN] = {0};
    int family = AF_UNSPEC;
    if (resolve_host(host, ip, sizeof(ip), &family) != 0) {
        fprintf(stderr, "[!] DNS resolution failed\n");
        return 2;
    }

    printf("[*] connecting to %s:%s\n", ip, port);
    int fd = tcp_connect_ip(ip, family, port);
    if (fd < 0) { fprintf(stderr, "[!] tcp connect failed\n"); return 3; }
    printf("[+] tcp connected\n");

    crisptls_policy_t pol;
    crisptls_policy_default(&pol);
    pol.verify_peer = 0;
    pol.verify_hostname = 0;
    pol.alpn = "http/1.1";

    crisptls_ctx_t *ctx = crisptls_ctx_new(&pol);
    if (!ctx) { fprintf(stderr, "[!] ctx_new failed\n"); return 4; }

    printf("[*] handshaking...\n");
    crisptls_conn_t *conn = crisptls_connect(ctx, fd, host);
    if (!conn) {
        fprintf(stderr, "[!] handshake failed\n");
        crisptls_ctx_free(ctx);
        close(fd);
        return 5;
    }

    printf("[+] handshake OK\n");
    printf("    version    : 0x%04x\n", crisptls_get_version(conn));
    printf("    cipher     : %s\n", crisptls_get_cipher(conn));
    printf("    sni        : %s\n", crisptls_get_sni(conn) ? crisptls_get_sni(conn) : "(none)");
    printf("    alpn       : %s\n", crisptls_get_alpn(conn) ? crisptls_get_alpn(conn) : "(none)");
    printf("    verify     : %d\n", crisptls_verify_status(conn));

    {
        uint8_t der[8192];
        size_t der_len = 0;
        if (crisptls_get_peer_cert_der(conn, der, sizeof(der), &der_len) == 0) {
            printf("    cert DER   : %zu bytes\n", der_len);
            printf("    cert head  : ");
            for (size_t i = 0; i < 16 && i < der_len; i++) printf("%02x ", der[i]);
            printf("\n");
        } else {
            printf("    cert DER   : (none)\n");
        }
    }

    char req[512];
    int rlen = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: crisptls-test/1.0\r\n"
        "Connection: close\r\n"
        "\r\n", host);

    printf("[*] sending HTTP GET / (%d bytes)\n", rlen);
    ssize_t w = crisptls_write(conn, req, rlen);
    if (w <= 0) {
        fprintf(stderr, "[!] write failed: %zd\n", w);
    } else {
        printf("[+] wrote %zd bytes, reading response...\n", w);
        uint8_t buf[4096];
        ssize_t total = 0;
        for (int i = 0; i < 8; i++) {
            ssize_t r = crisptls_read(conn, buf, sizeof(buf) - 1);
            if (r <= 0) { printf("[*] read returned %zd\n", r); break; }
            buf[r] = 0;
            printf("--- read %zd bytes ---\n", r);
            fwrite(buf, 1, r, stdout);
            printf("\n");
            total += r;
        }
        printf("[+] total: %zd bytes\n", total);
    }

    crisptls_close(conn);
    crisptls_ctx_free(ctx);
    close(fd);
    printf("[*] done\n");
    return 0;
}
