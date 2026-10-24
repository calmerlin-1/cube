/** core.c — crisptls TLS test harness.
 *
 * Exposes TLS policy knobs and does a minimal GET / to prove the
 * handshake works end-to-end. This is NOT an HTTP client — HTTP
 * lives in net/http/. Here we just speak enough HTTP to fetch a byte.
 *
 * usage: crisptls [tls-flags] <host>[:port]
 */

#include "crisptls.h"
#include "crisptls_policy.h"
#include "crisptls_types.h"
#include "dns.h"
#include "color.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

typedef struct {
    const char *host;
    const char *port;
    const char *sni;
    const char *alpn;
    const char *profile;
    const char *min_version;
    const char *max_version;

    int strict;
    int legacy;
    int use_generated;   /* --use-generated: load policy.generated.txt */
    int insecure;
    int no_sni;
    int show_cert;
    int ja3;
    int ja4;
    int verbose;
    int quiet;
    int no_fetch;   /* handshake only */

    uint32_t handshake_timeout_ms;
    uint32_t read_timeout_ms;
} opts_t;

static void usage(const char *p) {
    fprintf(stderr,
"usage: %s [tls-flags] <host>[:port]\n"
"\n"
"TLS policy:\n"
"  --profile NAME           chrome-120 | firefox-121 | curl-8\n"
"  --min-version V          ssl3 | tls10 | tls11 | tls12 | tls13\n"
"  --max-version V          ssl3 | tls10 | tls11 | tls12 | tls13\n"
"  --alpn LIST              comma-separated (default: http/1.1)\n"
"  --sni HOST               override SNI (default: host)\n"
"  --no-sni                 omit SNI extension\n"
"  --strict                 TLS 1.3 only, strict ALPN\n"
    "  --legacy                 allow SSL3/TLS10/TLS11 + RC4/3DES/CBC\n"
    "  --use-generated          load cache/policy.generated.txt instead of default\n"
"  --insecure               skip cert verification\n"
"\n"
"Output:\n"
"  --show-cert              print leaf cert DER head\n"
"  --ja3                    print JA3 (stub — zeros for now)\n"
"  --ja4                    print JA4 (stub — zeros for now)\n"
"  --no-fetch               handshake only, no HTTP GET\n"
"  -v, --verbose            more output\n"
"  -q, --quiet              less output\n"
"  -h, --help               this help\n"
"\n", p);
}

static int parse_version(const char *s, int *out) {
    if (!strcmp(s, "ssl3"))  { *out = CRISPTLS_VERSION_SSL3;  return 0; }
    if (!strcmp(s, "tls10")) { *out = CRISPTLS_VERSION_TLS10; return 0; }
    if (!strcmp(s, "tls11")) { *out = CRISPTLS_VERSION_TLS11; return 0; }
    if (!strcmp(s, "tls12")) { *out = CRISPTLS_VERSION_TLS12; return 0; }
    if (!strcmp(s, "tls13")) { *out = CRISPTLS_VERSION_TLS13; return 0; }
    return -1;
}

static int parse_args(int argc, char **argv, opts_t *o) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); exit(0); }

        if (!strcmp(a, "--strict"))    { o->strict = 1; continue; }
        if (!strcmp(a, "--legacy"))    { o->legacy = 1; continue; }
        if (!strcmp(a, "--use-generated")) { o->use_generated = 1; continue; }
        if (!strcmp(a, "--insecure"))  { o->insecure = 1; continue; }
        if (!strcmp(a, "--no-sni"))    { o->no_sni = 1; continue; }
        if (!strcmp(a, "--show-cert")) { o->show_cert = 1; continue; }
        if (!strcmp(a, "--ja3"))       { o->ja3 = 1; continue; }
        if (!strcmp(a, "--ja4"))       { o->ja4 = 1; continue; }
        if (!strcmp(a, "--no-fetch"))  { o->no_fetch = 1; continue; }
        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) { o->verbose = 1; continue; }
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))   { o->quiet = 1; continue; }

        if (!strcmp(a, "--profile"))     { if (++i >= argc) return -1; o->profile = argv[i]; continue; }
        if (!strcmp(a, "--alpn"))        { if (++i >= argc) return -1; o->alpn = argv[i]; continue; }
        if (!strcmp(a, "--sni"))         { if (++i >= argc) return -1; o->sni = argv[i]; continue; }
        if (!strcmp(a, "--min-version")) { if (++i >= argc) return -1; o->min_version = argv[i]; continue; }
        if (!strcmp(a, "--max-version")) { if (++i >= argc) return -1; o->max_version = argv[i]; continue; }

        if (a[0] == '-') { fprintf(stderr, "error: unknown option %s\n", a); return -1; }

        if (!o->host) {
            static char hostbuf[512];
            const char *colon = strrchr(a, ':');
            if (colon && colon != a && colon[1]) {
                size_t hl = (size_t)(colon - a);
                if (hl >= sizeof(hostbuf)) hl = sizeof(hostbuf) - 1;
                memcpy(hostbuf, a, hl);
                hostbuf[hl] = 0;
                o->host = hostbuf;
                o->port = colon + 1;
            } else {
                o->host = a;
            }
            continue;
        }
        fprintf(stderr, "error: unexpected argument %s\n", a);
        return -1;
    }
    if (!o->host) { usage(argv[0]); return -1; }
    return 0;
}

static int resolve(const char *host, char *ip_out, size_t cap, int *fam_out) {
    /* Fast path: host is already an IP literal. Skip DNS entirely. */
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        snprintf(ip_out, cap, "%s", host);
        *fam_out = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        snprintf(ip_out, cap, "%s", host);
        *fam_out = AF_INET6;
        return 0;
    }

    /* Otherwise ask cube's DNS resolver. */
    dns_resolver_t *r = dns_resolver_new_default();
    if (!r) return -1;
    dns_resolver_set_persist(r, "/data/data/com.termux/files/home/osint/cube/net/dns/cache/upstream_scores.txt");
    dns_resolver_set_cache_path(r, "/data/data/com.termux/files/home/osint/cube/net/dns/cache/hostname_cache.txt");
    dns_answer_t ans; memset(&ans, 0, sizeof(ans));
    if (dns_resolve_dual(r, host, &ans) != DNS_OK) { dns_resolver_free(r); return -1; }
    int found = 0;
    for (size_t i = 0; i < ans.count && !found; i++) {
        if (ans.records[i].type == DNS_TYPE_A) {
            inet_ntop(AF_INET, ans.records[i].u.a.addr, ip_out, cap);
            *fam_out = AF_INET; found = 1;
        }
    }
    for (size_t i = 0; i < ans.count && !found; i++) {
        if (ans.records[i].type == DNS_TYPE_AAAA) {
            inet_ntop(AF_INET6, ans.records[i].u.aaaa.addr, ip_out, cap);
            *fam_out = AF_INET6; found = 1;
        }
    }
    dns_answer_free(&ans);
    dns_resolver_free(r);
    return found ? 0 : -1;
}

static int tcp_connect(const char *ip, int fam, const char *port) {
    int fd = socket(fam, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (fam == AF_INET) {
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)atoi(port));
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
        if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    } else {
        struct sockaddr_in6 sa = {0};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons((uint16_t)atoi(port));
        if (inet_pton(AF_INET6, ip, &sa.sin6_addr) != 1) { close(fd); return -1; }
        if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    }
    return fd;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    /* Enable color if stdout is a terminal. */
    col_enable();

    opts_t o;
    memset(&o, 0, sizeof(o));
    o.port = "443";
    o.alpn = "http/1.1";

    if (parse_args(argc, argv, &o) != 0) return 1;

    char ip[INET6_ADDRSTRLEN] = {0};
    int fam = AF_UNSPEC;
    if (!o.quiet) fprintf(stderr, "[*] resolving %s\n", o.host);
    if (resolve(o.host, ip, sizeof(ip), &fam) != 0) {
        fprintf(stderr, "%s[!] DNS failed%s\n", col_red(), col_reset()); return 2;
    }
    if (!o.quiet) fprintf(stderr, "[*] %s -> %s\n", o.host, ip);

    int fd = tcp_connect(ip, fam, o.port);
    if (fd < 0) { fprintf(stderr, "%s[!] tcp connect failed%s\n", col_red(), col_reset()); return 3; }
    if (!o.quiet) fprintf(stderr, "[+] tcp connected\n");

    crisptls_policy_t pol;
    if (o.profile) {
        if (crisptls_policy_from_profile(&pol, o.profile) != CRISPTLS_OK) {
            fprintf(stderr, "[!] unknown profile %s\n", o.profile); close(fd); return 4;
        }
    } else if (o.use_generated) {
        if (crisptls_policy_from_generated(&pol, "cache/policy.generated.txt") != CRISPTLS_OK) {
            fprintf(stderr, "[!] generated policy not usable, falling back to default\n");
            crisptls_policy_default(&pol);
        } else if (!o.quiet) {
            fprintf(stderr, "[*] using generated policy\n");
        }
    } else if (o.legacy) {
        crisptls_policy_legacy(&pol);
    } else if (o.strict) {
        crisptls_policy_strict(&pol);
    } else {
        crisptls_policy_default(&pol);
    }

    if (o.alpn)      pol.alpn = o.alpn;
    if (o.no_sni)    pol.send_sni = 0;
    if (o.insecure)  { pol.verify_peer = 0; pol.verify_hostname = 0; }
    if (o.min_version) {
        int v;
        if (parse_version(o.min_version, &v) == 0) {
            pol.min_version = v;
            pol.legacy_version_field = (v < 0x0303) ? v : 0x0303;
        }
    }
    if (o.max_version) { int v; if (parse_version(o.max_version, &v) == 0) pol.max_version = v; }

    crisptls_ctx_t *ctx = crisptls_ctx_new(&pol);
    if (!ctx) { close(fd); return 4; }

    if (!o.quiet) fprintf(stderr, "[*] handshaking...\n");
    const char *sni = o.sni ? o.sni : o.host;
    crisptls_conn_t *conn = crisptls_connect(ctx, fd, sni);
    if (!conn) {
        fprintf(stderr, "%s[!] handshake failed%s\n", col_red(), col_reset());
        crisptls_ctx_free(ctx); close(fd); return 5;
    }

    printf("%s[+] handshake OK%s\n", col_green(), col_reset());
    printf("    version    : %s0x%04x%s\n",
           col_cyan(), crisptls_get_version(conn), col_reset());
    printf("    cipher     : %s%s%s\n",
           col_cyan(), crisptls_get_cipher(conn), col_reset());
    printf("    sni        : %s%s%s\n",
           col_bright_white(),
           crisptls_get_sni(conn) ? crisptls_get_sni(conn) : "(none)",
           col_reset());
    printf("    alpn       : %s%s%s\n",
           col_bright_white(),
           crisptls_get_alpn(conn) ? crisptls_get_alpn(conn) : "(none)",
           col_reset());
    int vs = crisptls_verify_status(conn);
    printf("    verify     : %s%d%s\n",
           vs == 0 ? col_green() : col_red(), vs, col_reset());

    if (o.show_cert) {
        uint8_t der[16384]; size_t dl = 0;
        if (crisptls_get_peer_cert_der(conn, der, sizeof(der), &dl) == CRISPTLS_OK) {
            printf("    cert DER   : %zu bytes\n", dl);
            printf("    cert head  : ");
            for (size_t i = 0; i < 16 && i < dl; i++) printf("%02x ", der[i]);
            printf("\n");
        } else printf("    cert DER   : (none)\n");
    }
    if (o.ja3) {
        char b[64];
        crisptls_conn_ja3_hash(conn, b, sizeof(b));
        printf("    ja3        : %s%s%s\n", col_yellow(), b, col_reset());
    }
    if (o.ja4) {
        char b[64];
        crisptls_conn_ja4_hash(conn, b, sizeof(b));
        printf("    ja4        : %s%s%s\n", col_yellow(), b, col_reset());
    }

    if (!o.no_fetch) {
        char req[512];
        int n = snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", o.host);
        if (crisptls_write(conn, req, (size_t)n) <= 0) {
            fprintf(stderr, "[!] write failed\n");
        } else {
            if (!o.quiet) fprintf(stderr, "[*] sent GET /\n");
            uint8_t buf[4096];
            for (int i = 0; i < 16; i++) {
                ssize_t r = crisptls_read(conn, buf, sizeof(buf) - 1);
                if (r <= 0) break;
                buf[r] = 0;
                fwrite(buf, 1, (size_t)r, stdout);
            }
            fflush(stdout);
        }
    }

    crisptls_close(conn);
    crisptls_ctx_free(ctx);
    close(fd);
    return 0;
}
