/** proxy.c — HTTP CONNECT and SOCKS5/5h client handshakes. */

#include "proxy.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define proxy_close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define proxy_close close
#endif

static int ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++, cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

int proxy_parse(proxy_config_t *p, const char *url) {
    if (!p || !url) return -1;
    memset(p, 0, sizeof(*p));
    const char *rest = url;
    if (!strncmp(url, "http://", 7))      { p->type = PROXY_HTTP;    rest = url + 7; }
    else if (!strncmp(url, "https://", 8)){ p->type = PROXY_HTTP;    rest = url + 8; }
    else if (!strncmp(url, "socks5h://", 10)) { p->type = PROXY_SOCKS5H; rest = url + 10; }
    else if (!strncmp(url, "socks5://", 9))   { p->type = PROXY_SOCKS5;  rest = url + 9; }
    else if (!strncmp(url, "socks://", 8))    { p->type = PROXY_SOCKS5;  rest = url + 8; }

    const char *at = strrchr(rest, '@');
    const char *hostpart = rest;
    if (at) {
        const char *colon = memchr(rest, ':', (size_t)(at - rest));
        if (colon) {
            size_t ul = (size_t)(colon - rest);
            if (ul >= sizeof p->user) ul = sizeof p->user - 1;
            memcpy(p->user, rest, ul); p->user[ul] = 0;
            size_t pl = (size_t)(at - colon - 1);
            if (pl >= sizeof p->pass) pl = sizeof p->pass - 1;
            memcpy(p->pass, colon + 1, pl); p->pass[pl] = 0;
        }
        hostpart = at + 1;
    }
    char hostbuf[300];
    snprintf(hostbuf, sizeof hostbuf, "%s", hostpart);
    char *slash = strchr(hostbuf, '/');
    if (slash) *slash = 0;
    char *hp = hostbuf;
    char *portstr = NULL;
    if (*hp == '[') {
        char *end = strchr(hp, ']');
        if (end) { *end = 0; hp++; portstr = end[1] == ':' ? end + 2 : NULL; }
    } else {
        char *c = strrchr(hp, ':');
        if (c) { *c = 0; portstr = c + 1; }
    }
    snprintf(p->host, sizeof p->host, "%s", hp);
    if (p->type == PROXY_NONE) p->type = PROXY_HTTP;
    long pv = portstr && *portstr ? strtol(portstr, NULL, 10) :
              (p->type == PROXY_HTTP ? 8080 : 1080);
    if (pv <= 0 || pv > 65535) return -1;
    p->port = (unsigned short)pv;
    return p->host[0] ? 0 : -1;
}

void proxy_set_no_proxy(proxy_config_t *p, const char *list) {
    if (!p) return;
    p->no_proxy[0] = 0;
    if (list) snprintf(p->no_proxy, sizeof p->no_proxy, "%s", list);
}

static int host_matches(const char *host, const char *pat) {
    while (*pat == '.') pat++;
    size_t hl = strlen(host), pl = strlen(pat);
    if (!pl) return 0;
    if (hl == pl && ci_eq(host, pat)) return 1;
    if (hl > pl && host[hl - pl - 1] == '.' && ci_eq(host + hl - pl, pat)) return 1;
    return 0;
}

int proxy_bypass(const proxy_config_t *p, const char *host) {
    if (!p || p->type == PROXY_NONE) return 1;
    if (!host) return 0;
    if (ci_eq(host, "localhost") || !strcmp(host, "127.0.0.1") || !strcmp(host, "::1"))
        return 1;
    char buf[sizeof p->no_proxy];
    snprintf(buf, sizeof buf, "%s", p->no_proxy);
    char *save = NULL;
    for (char *t = strtok_r(buf, ", ;", &save); t; t = strtok_r(NULL, ", ;", &save)) {
        if (!strcmp(t, "*")) return 1;
        if (host_matches(host, t)) return 1;
    }
    return 0;
}

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64(const char *in, char *out, size_t cap) {
    size_t o = 0, n = strlen(in);
    for (size_t i = 0; i < n && o + 4 < cap; i += 3) {
        unsigned v = (unsigned char)in[i] << 16;
        if (i + 1 < n) v |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)in[i + 2];
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = i + 1 < n ? b64tab[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? b64tab[v & 63] : '=';
    }
    out[o] = 0;
}

static int send_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) {
        int w = (int)send(fd, p, (int)n, 0);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t n) {
    char *p = (char *)buf;
    while (n) {
        int r = (int)recv(fd, p, (int)n, 0);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int http_tunnel(const proxy_config_t *p, int fd,
                       const char *host, unsigned short port,
                       char *err, size_t cap) {
    char req[1024];
    int n;
    if (p->user[0]) {
        char cred[300], enc[512];
        snprintf(cred, sizeof cred, "%s:%s", p->user, p->pass);
        b64(cred, enc, sizeof enc);
        n = snprintf(req, sizeof req,
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n"
            "Proxy-Authorization: Basic %s\r\n\r\n",
            host, (unsigned)port, host, (unsigned)port, enc);
    } else {
        n = snprintf(req, sizeof req,
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
            host, (unsigned)port, host, (unsigned)port);
    }
    if (n <= 0 || (size_t)n >= sizeof req || send_all(fd, req, (size_t)n) != 0) {
        snprintf(err, cap, "proxy: failed to send CONNECT");
        return -1;
    }
    char resp[1024]; size_t len = 0;
    while (len + 1 < sizeof resp) {
        char c;
        if (recv(fd, &c, 1, 0) != 1) break;
        resp[len++] = c;
        if (len >= 4 && !memcmp(resp + len - 4, "\r\n\r\n", 4)) break;
    }
    resp[len] = 0;
    int code = 0;
    sscanf(resp, "HTTP/%*d.%*d %d", &code);
    if (code != 200) {
        snprintf(err, cap, "proxy CONNECT rejected (HTTP %d)", code);
        return -1;
    }
    return 0;
}

static int socks_tunnel(const proxy_config_t *p, int fd,
                        const char *host, unsigned short port,
                        char *err, size_t cap) {
    unsigned char g[3] = { 5, 1, (unsigned char)(p->user[0] ? 2 : 0) };
    if (send_all(fd, g, 3) != 0) { snprintf(err, cap, "socks: greeting failed"); return -1; }
    unsigned char r[2];
    if (recv_all(fd, r, 2) != 0 || r[0] != 5) { snprintf(err, cap, "socks: bad greeting"); return -1; }
    if (r[1] == 2) {
        size_t ul = strlen(p->user), pl = strlen(p->pass);
        if (ul > 255) ul = 255; if (pl > 255) pl = 255;
        unsigned char a[513]; size_t o = 0;
        a[o++] = 1; a[o++] = (unsigned char)ul; memcpy(a + o, p->user, ul); o += ul;
        a[o++] = (unsigned char)pl; memcpy(a + o, p->pass, pl); o += pl;
        if (send_all(fd, a, o) != 0 || recv_all(fd, r, 2) != 0 || r[1] != 0) {
            snprintf(err, cap, "socks: auth failed");
            return -1;
        }
    } else if (r[1] != 0) {
        snprintf(err, cap, "socks: no acceptable auth method");
        return -1;
    }

    unsigned char req[300]; size_t o = 0;
    req[o++] = 5; req[o++] = 1; req[o++] = 0;
    int fam = strchr(host, ':') ? 6 : 0;
    struct in_addr v4; struct in6_addr v6;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        req[o++] = 1; memcpy(req + o, &v4, 4); o += 4;
    } else if (fam == 6 && inet_pton(AF_INET6, host, &v6) == 1) {
        req[o++] = 4; memcpy(req + o, &v6, 16); o += 16;
    } else {
        size_t hl = strlen(host);
        if (hl > 255) hl = 255;
        req[o++] = 3; req[o++] = (unsigned char)hl; memcpy(req + o, host, hl); o += hl;
    }
    req[o++] = (unsigned char)(port >> 8);
    req[o++] = (unsigned char)(port & 0xff);
    if (send_all(fd, req, o) != 0) { snprintf(err, cap, "socks: connect send failed"); return -1; }
    unsigned char hdr[4];
    if (recv_all(fd, hdr, 4) != 0) { snprintf(err, cap, "socks: connect recv failed"); return -1; }
    if (hdr[1] != 0) { snprintf(err, cap, "socks: connect refused (code %u)", hdr[1]); return -1; }
    size_t skip = 0;
    if (hdr[3] == 1) skip = 4;
    else if (hdr[3] == 4) skip = 16;
    else if (hdr[3] == 3) { unsigned char l; if (recv_all(fd, &l, 1) != 0) return -1; skip = l; }
    unsigned char tmp[258];
    if (skip && recv_all(fd, tmp, skip) != 0) return -1;
    if (recv_all(fd, tmp, 2) != 0) return -1;
    return 0;
}

int proxy_tunnel(const proxy_config_t *p, int fd,
                 const char *host, unsigned short port,
                 unsigned int timeout_ms, char *err, size_t cap) {
    (void)timeout_ms;
    if (!p || !err || cap == 0) return -1;
    err[0] = 0;
    if (p->type == PROXY_HTTP) return http_tunnel(p, fd, host, port, err, cap);
    if (p->type == PROXY_SOCKS5 || p->type == PROXY_SOCKS5H)
        return socks_tunnel(p, fd, host, port, err, cap);
    snprintf(err, cap, "proxy: unsupported type");
    return -1;
}
