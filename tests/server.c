/** server.c — tiny legacy-protocol test server for cube.
 *
 * Serves HTTP/1.0 and HTTP/1.1 edge cases on 127.0.0.1:
 *   /            plain 200
 *   /gzip        gzip content-encoding (if built with zlib)
 *   /deflate     deflate content-encoding (if built with zlib)
 *   /chunked     chunked transfer-encoding
 *   /redirect    302 -> /final
 *   /final       plain 200
 *   /eof         HTTP/1.0 body terminated by EOF
 *   /404         not found
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

static int send_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) {
        int w = (int)send(fd, p, (int)n, 0);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static void send_head(int fd, int code, const char *reason,
                      const char *ctype, long len, const char *extra) {
    char b[512];
    int n = snprintf(b, sizeof b,
        "HTTP/1.1 %d %s\r\nServer: cube-test\r\nConnection: close\r\n"
        "Content-Type: %s\r\n", code, reason, ctype);
    if (len >= 0) n += snprintf(b + n, sizeof b - (size_t)n, "Content-Length: %ld\r\n", len);
    if (extra) n += snprintf(b + n, sizeof b - (size_t)n, "%s", extra);
    snprintf(b + n, sizeof b - (size_t)n, "\r\n");
    send_all(fd, b, strlen(b));
}

static void plain(int fd, int code, const char *reason, const char *body) {
    send_head(fd, code, reason, "text/plain", (long)strlen(body), NULL);
    send_all(fd, body, strlen(body));
}

#ifdef HAVE_ZLIB
static int compress_body(const char *in, size_t in_len, int wbits,
                         unsigned char *out, size_t out_cap, size_t *out_len) {
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) return -1;
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    zs.next_out = out;
    zs.avail_out = (uInt)out_cap;
    int rc = deflate(&zs, Z_FINISH);
    *out_len = out_cap - zs.avail_out;
    deflateEnd(&zs);
    return rc == Z_STREAM_END ? 0 : -1;
}
#endif

static void respond(int fd, const char *method, const char *path) {
    int head = !strcasecmp(method, "HEAD");
    if (!strcmp(path, "/") || !strcmp(path, "/final")) {
        const char *body = path[1] ? "final\n" : "hello\n";
        send_head(fd, 200, "OK", "text/plain", (long)strlen(body), NULL);
        if (!head) send_all(fd, body, strlen(body));
    } else if (!strcmp(path, "/gzip") || !strcmp(path, "/deflate")) {
        const char *body = !strcmp(path, "/gzip") ? "hello gzip\n" : "hello deflate\n";
        int gz = !strcmp(path, "/gzip");
#ifdef HAVE_ZLIB
        unsigned char out[512]; size_t out_len = 0;
        if (compress_body(body, strlen(body), gz ? 31 : 15, out, sizeof out, &out_len) == 0) {
            send_head(fd, 200, "OK", "text/plain", (long)out_len,
                      gz ? "Content-Encoding: gzip\r\n" : "Content-Encoding: deflate\r\n");
            if (!head) send_all(fd, out, out_len);
            return;
        }
#endif
        plain(fd, 200, "OK", body);
    } else if (!strcmp(path, "/chunked")) {
        send_head(fd, 200, "OK", "text/plain", -1, "Transfer-Encoding: chunked\r\n");
        if (!head) {
            send_all(fd, "6\r\nalpha\n\r\n", 11);
            send_all(fd, "5\r\nbeta\n\r\n", 10);
            send_all(fd, "0\r\n\r\n", 5);
        }
    } else if (!strcmp(path, "/redirect")) {
        send_head(fd, 302, "Found", "text/plain", 0, "Location: /final\r\n");
    } else if (!strcmp(path, "/eof")) {
        const char *r = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\neof body\n";
        send_all(fd, r, strlen(r));
    } else {
        plain(fd, 404, "Not Found", "not found\n");
    }
}

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    int port = argc > 1 ? atoi(argv[1]) : 18080;
    int s = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "cube-test-server: http://127.0.0.1:%d\n", port);

    for (;;) {
        int c = (int)accept(s, NULL, NULL);
        if (c < 0) continue;
        char req[8192]; size_t len = 0;
        while (len + 1 < sizeof req) {
            int r = (int)recv(c, req + len, (int)(sizeof req - len - 1), 0);
            if (r <= 0) break;
            len += (size_t)r;
            req[len] = 0;
            if (strstr(req, "\r\n\r\n")) break;
        }
        char method[16] = "GET", path[2048] = "/";
        if (len) sscanf(req, "%15s %2047s", method, path);
        char *q = strchr(path, '?');
        if (q) *q = 0;
        respond(c, method, path);
        close(c);
    }
}
