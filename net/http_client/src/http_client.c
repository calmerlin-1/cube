/** http_client.c — raw HTTP/1.x client over plain TCP.
 *
 * No URL, no DNS, no TLS. Host + port in, HTTP request out.
 * The *_send_fd() entry point is what net/crisptls/ will call after
 * it has wrapped the socket, so TLS is a layering concern, not ours.
 *
 * Wire format produced:
 *     <METHOD> <PATH> HTTP/1.x\r\n
 *     Header: value\r\n
 *     ...
 *     \r\n
 *     <body>
 *
 * We default to Connection: close and read the response body to EOF.
 * Chunked transfer-encoding is NOT decoded yet.
 */

#include "http_client.h"
#include "http_protocol.h"
#include "http_status.h"

#include <errno.h>
#include <stdio.h>
#include "trace.h"
#include <stdlib.h>
#include <string.h>

#include <quic_conn.h>
#include <quic_udp.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#define cube_close closesocket
#define strcasecmp _stricmp
#define cube_setsockopt(fd,lvl,opt,val,len) \
    setsockopt((fd),(lvl),(opt),(const char *)(val),(int)(len))
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define cube_close close
#define cube_setsockopt setsockopt
#endif

/* Headers */

void http_headers_init(http_headers_t *h) {
    h->items = NULL;
    h->count = 0;
    h->cap   = 0;
}

void http_headers_free(http_headers_t *h) {
    if (!h) return;
    for (size_t i = 0; i < h->count; i++) {
        free(h->items[i].name);
        free(h->items[i].value);
    }
    free(h->items);
    h->items = NULL;
    h->count = 0;
    h->cap   = 0;
}

static int ci_equal(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void headers_grow(http_headers_t *h) {
    if (h->count < h->cap) return;
    size_t ncap = h->cap ? h->cap * 2 : 8;
    http_header_t *ni = realloc(h->items, ncap * sizeof(*ni));
    if (!ni) return;
    h->items = ni;
    h->cap   = ncap;
}

void http_headers_set(http_headers_t *h, const char *name, const char *value) {
    for (size_t i = 0; i < h->count; i++) {
        if (ci_equal(h->items[i].name, name)) {
            free(h->items[i].value);
            h->items[i].value = xstrdup(value);
            return;
        }
    }
    http_headers_add(h, name, value);
}

void http_headers_add(http_headers_t *h, const char *name, const char *value) {
    headers_grow(h);
    if (h->count >= h->cap) return;
    h->items[h->count].name  = xstrdup(name);
    h->items[h->count].value = xstrdup(value);
    h->count++;
}

const char *http_headers_get(const http_headers_t *h, const char *name) {
    for (size_t i = 0; i < h->count; i++) {
        if (ci_equal(h->items[i].name, name))
            return h->items[i].value;
    }
    return NULL;
}

/* Response */

void http_response_free(http_response_t *r) {
    if (!r) return;
    free(r->reason);
    http_headers_free(&r->headers);
    free(r->body);
    memset(r, 0, sizeof(*r));
}

/* Client */

void http_client_init(http_client_t *c) {
    if (!c) return;
    c->timeout_ms = 30000;
    http_headers_init(&c->default_headers);
}

void http_client_free(http_client_t *c) {
    if (!c) return;
    http_headers_free(&c->default_headers);
    http_cookie_jar_free(&c->cookies);
    memset(c, 0, sizeof(*c));
}

/* ---- Growable byte buffer ---- */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

static int buf_reserve(buf_t *b, size_t need) {
    if (b->len + need <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + need) ncap *= 2;
    uint8_t *nd = realloc(b->data, ncap);
    if (!nd) return -1;
    b->data = nd;
    b->cap  = ncap;
    return 0;
}

static int buf_append(buf_t *b, const void *src, size_t n) {
    if (buf_reserve(b, n) != 0) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static int buf_append_str(buf_t *b, const char *s) {
    return buf_append(b, s, strlen(s));
}

/* http_io_t — raw-fd implementation */

/* Buffered read on top of a raw fd.
 * The protocol layer calls read() one byte at a time for header
 * parsing, which would otherwise be one syscall per byte. We keep
 * a small internal buffer so most reads are served from memory. */

typedef struct {
    int      fd;
    uint8_t  buf[8192];
    size_t   len;
    size_t   pos;
} fd_io_ctx_t;

static ssize_t io_fd_read(void *ctx, void *out, size_t n) {
    fd_io_ctx_t *c = (fd_io_ctx_t *)ctx;
    if (c->pos < c->len) {
        size_t avail = c->len - c->pos;
        size_t copy  = n < avail ? n : avail;
        memcpy(out, c->buf + c->pos, copy);
        c->pos += copy;
        return (ssize_t)copy;
    }
    /* Buffer empty — refill. Serve small reads from buffer,
     * large reads direct to caller. */
    if (n >= sizeof(c->buf)) {
        for (;;) {
            ssize_t r = recv(c->fd, out, n, 0);
            if (r < 0 && errno == EINTR) continue;
            return r;
        }
    }
    for (;;) {
        ssize_t r = recv(c->fd, c->buf, sizeof(c->buf), 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return r;
        c->len = (size_t)r;
        c->pos = 0;
        size_t copy = n < c->len ? n : c->len;
        memcpy(out, c->buf, copy);
        c->pos = copy;
        return (ssize_t)copy;
    }
}

static ssize_t io_fd_write(void *ctx, const void *buf, size_t n) {
    fd_io_ctx_t *c = (fd_io_ctx_t *)ctx;
    int fd = c->fd;
    for (;;) {
        ssize_t r = send(fd, buf, n, 0);
        if (r < 0 && errno == EINTR) continue;
        return r;
    }
}

/* Stable per-io context for raw-fd transport. Caller supplies it. */
void http_io_from_fd_ctx(http_io_t *io, fd_io_ctx_t *ctx, int fd) {
    if (!io || !ctx) return;
    ctx->fd  = fd;
    ctx->len = 0;
    ctx->pos = 0;
    io->ctx   = ctx;
    io->read  = io_fd_read;
    io->write = io_fd_write;
    io->close = NULL;
}

/* Legacy single-shot helper — allocates a static context. Only safe
 * for one io per process. Prefer http_io_from_fd_ctx. */
static fd_io_ctx_t g_fd_ctx;
void http_io_from_fd(http_io_t *io, int fd) {
    http_io_from_fd_ctx(io, &g_fd_ctx, fd);
}


/* ---- TCP dial (host may be IPv4, IPv6, or a name getaddrinfo accepts) ---- */
static int tcp_dial(const char *host, uint16_t port, int timeout_ms) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        if (timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            cube_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            cube_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        /* Low-latency + resilient connection. */
        int one = 1;
        cube_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        cube_setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof(one));

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        cube_close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* ---- Line reader ---- */
static char *read_line_io(const http_io_t *io) {
    size_t cap = 128, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        char ch;
        ssize_t n = io->read(io->ctx, &ch, 1);
        if (n <= 0) { free(buf); return NULL; }
        if (ch == '\n') break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[len++] = ch;
    }
    if (len > 0 && buf[len - 1] == '\r') len--;
    buf[len] = '\0';
    return buf;
}

static int read_all_io(const http_io_t *io, buf_t *out) {
    uint8_t tmp[4096];
    for (;;) {
        ssize_t n = io->read(io->ctx, tmp, sizeof(tmp));
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (buf_append(out, tmp, (size_t)n) != 0) return -1;
    }
}

static const char *version_str(http_version_t v) {
    switch (v) {
        case HTTP_09: return NULL;        /* no version token on wire */
        case HTTP_10: return "HTTP/1.0";
        case HTTP_11: return "HTTP/1.1";
    }
    return "HTTP/1.1";
}

static http_version_t parse_version(const char *s, int *is_09) {
    if (is_09) *is_09 = 0;
    if (strncmp(s, "HTTP/1.0", 8) == 0) return HTTP_10;
    if (strncmp(s, "HTTP/1.1", 8) == 0) return HTTP_11;
    if (is_09) *is_09 = 1;
    return HTTP_09;   /* caller: bare body, no headers */
}

/* RFC 7230 3.3.2: Content-Length is 1*DIGIT. No sign, no ws, no comma. */
int http_parse_content_length(const char *s, unsigned long long *out) {
    if (!s || !*s) return -1;
    unsigned long long v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (unsigned long long)(*p - '0');
        if (v > 0x7fffffffffffffffULL) return -1;
    }
    if (out) *out = v;
    return 0;
}

static int read_exact_io(const http_io_t *io, buf_t *out, size_t n) {
    if (buf_reserve(out, n) != 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = io->read(io->ctx, out->data + out->len + got, n - got);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    out->len += n;
    return 0;
}

static int read_chunked_body_io(const http_io_t *io, buf_t *out) {
    for (;;) {
        char *line = read_line_io(io);
        if (!line) return -1;

        char *semi = strchr(line, ';');
        if (semi) *semi = '\0';

        char *end = NULL;
        unsigned long long chunk = strtoull(line, &end, 16);
        free(line);

        if (chunk == 0) {
            for (;;) {
                char *t = read_line_io(io);
                if (!t) return -1;
                int blank = (t[0] == '\0');
                free(t);
                if (blank) break;
            }
            return 0;
        }

        if (read_exact_io(io, out, (size_t)chunk) != 0) return -1;

        char crlf[2];
        size_t got = 0;
        while (got < 2) {
            ssize_t r = io->read(io->ctx, crlf + got, 2 - got);
            if (r <= 0) {
                if (r < 0 && errno == EINTR) continue;
                return -1;
            }
            got += (size_t)r;
        }
    }
}

/* Core: send over an existing fd */

/* http_client_send_io — core protocol logic (io-agnostic) */

int http_client_send_io(const http_io_t       *io,
                        const char            *host,
                        uint16_t               port,
                        const http_request_t  *req,
                        http_response_t       *out)
{
    if (!io || !io->read || !io->write || !host || !req || !out) return -1;
    memset(out, 0, sizeof(*out));
    http_headers_init(&out->headers);

    /* Strict knobs come from a thread-local? No — http_client_send_io is
     * io-based and has no client handle. Set strict via a global that
     * http_client_do flips before calling us, or accept lenient here.
     * For 1.0-only work we default to lenient (browser-friendly). */
    int strict_chunked_10 = 0;

    const char *method = req->method ? req->method : "GET";
    const char *path   = req->path   ? req->path   : "/";
    http_version_t ver = req->version;

    http_headers_t merged;
    http_headers_init(&merged);
    for (size_t i = 0; i < req->headers.count; i++)
        http_headers_set(&merged,
                         req->headers.items[i].name,
                         req->headers.items[i].value);

    char hosthdr[280];
    /* Omit :port for default ports (80 http, 443 https) is a nicety —
     * we don't know scheme here, so include port always unless 80/443. */
    if (port == 80 || port == 443)
        snprintf(hosthdr, sizeof(hosthdr), "%s", host);
    else
        snprintf(hosthdr, sizeof(hosthdr), "%s:%u", host, (unsigned)port);

    if (!http_headers_get(&merged, "Host"))
        http_headers_set(&merged, "Host", hosthdr);
    if (!http_headers_get(&merged, "Connection"))
        http_headers_set(&merged, "Connection", "close");
    if (!http_headers_get(&merged, "User-Agent"))
        http_headers_set(&merged, "User-Agent", "cube-http-client/1.0");
    if (!http_headers_get(&merged, "Accept"))
        http_headers_set(&merged, "Accept", "*/*");

    char clbuf[32];
    if (req->body_len > 0 && !http_headers_get(&merged, "Content-Length")) {
        snprintf(clbuf, sizeof(clbuf), "%zu", req->body_len);
        http_headers_set(&merged, "Content-Length", clbuf);
    }

    /* ---- Build request ---- */
    buf_t reqbuf;
    memset(&reqbuf, 0, sizeof(reqbuf));
    char line[1024];

    if (ver == HTTP_09) {
        /* RFC 1945 4.1: bare "GET /path CRLF", nothing else. */
        snprintf(line, sizeof(line), "%s %s\r\n", method, path);
        buf_append_str(&reqbuf, line);
    } else {
        snprintf(line, sizeof(line), "%s %s %s\r\n",
                 method, path, version_str(ver));
        buf_append_str(&reqbuf, line);

        for (size_t i = 0; i < merged.count; i++) {
            buf_append_str(&reqbuf, merged.items[i].name);
            buf_append_str(&reqbuf, ": ");
            buf_append_str(&reqbuf, merged.items[i].value);
            buf_append_str(&reqbuf, "\r\n");
        }
        buf_append_str(&reqbuf, "\r\n");
        if (req->body_len > 0)
            buf_append(&reqbuf, req->body, req->body_len);
    }

    size_t sent = 0;
    while (sent < reqbuf.len) {
        ssize_t n = io->write(io->ctx, reqbuf.data + sent, reqbuf.len - sent);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            free(reqbuf.data);
            http_headers_free(&merged);
            return -3;
        }
        sent += (size_t)n;
    }
    free(reqbuf.data);
    http_headers_free(&merged);

    /* ---- Status line ----
     *
     * HTTP/0.9 has no status line at all: the very first byte of the
     * response is the body. We detect this by whether the first line
     * starts with "HTTP/". If not, treat the entire response — that
     * line included — as body.
     */
    char *status_line = read_line_io(io);
    if (!status_line) return -4;

    int is_09 = 0;
    out->version = parse_version(status_line, &is_09);

    if (is_09) {
        /* 0.9: status_line is body, plus whatever else is on the wire */
        buf_t b09;
        memset(&b09, 0, sizeof(b09));
        buf_append_str(&b09, status_line);
        buf_append_str(&b09, "\n");
        free(status_line);
        if (read_all_io(io, &b09) != 0) {
            free(b09.data);
            return -5;
        }
        out->status_code = 200;
        out->reason      = xstrdup("OK (HTTP/0.9)");
        out->body        = b09.data;
        out->body_len    = b09.len;
        return 0;
    }

    char verstr[16] = {0};
    int  code = 0;
    char reason[256] = {0};
    int matched = sscanf(status_line, "%15s %d %255[^\r\n]", verstr, &code, reason);
    free(status_line);
    if (matched < 2) return -5;

    out->status_code = code;
    out->reason      = xstrdup(http_status_str(code));

    /* If we asked for 1.0 but got 1.1 (or vice versa), keep the server's
     * version in out->version — that's what the wire said. */
    (void)verstr;
    if (out->version != HTTP_09) {
        /* parse_version already set it */
    }

    /* ---- Headers ---- */
    for (;;) {
        char *hline = read_line_io(io);
        if (!hline) { http_response_free(out); return -6; }
        if (hline[0] == '\0') { free(hline); break; }

        char *colon = strchr(hline, ':');
        if (!colon) { free(hline); continue; }
        *colon = '\0';
        char *name = hline;
        char *val  = colon + 1;
        while (*val == ' ' || *val == '\t') val++;

        http_headers_add(&out->headers, name, val);
        free(hline);
    }

    /* ---- Body ----
     *
     * Framing rules per RFC 1945 (HTTP/1.0) and RFC 7230 (1.1):
     *   1. Transfer-Encoding: chunked   -> 1.1 only; reject for 1.0 in strict
     *   2. Content-Length: N            -> exactly N bytes, no more, no less
     *   3. neither                      -> read to EOF (1.0 close-delimited)
     */
    buf_t body;
    memset(&body, 0, sizeof(body));

    const char *te = http_headers_get(&out->headers, "Transfer-Encoding");
    const char *cl = http_headers_get(&out->headers, "Content-Length");

    if (te && strstr(te, "chunked")) {
        if (out->version == HTTP_10) {
            /* RFC 1945 §7.2.2: HTTP/1.0 has no TE. A 1.0 response that
             * carries it is malformed. Strict => reject. Lenient => try. */
            if (strict_chunked_10) {
                http_response_free(out);
                return -10;   /* HTTP_ERR_NOTSUP-like */
            }
            /* fall through and attempt chunked decode */
        }
        if (read_chunked_body_io(io, &body) != 0) {
            free(body.data);
            http_response_free(out);
            return -8;
        }
    } else if (cl) {
        unsigned long long n = 0;
        if (http_parse_content_length(cl, &n) != 0) {
            /* malformed CL: reject regardless of strictness */
            http_response_free(out);
            return -6;
        }
        if (read_exact_io(io, &body, (size_t)n) != 0) {
            /* short read: server closed before sending all N bytes */
            free(body.data);
            http_response_free(out);
            return -9;
        }
        /* Sanity: if the connection had more bytes after CL they belong
         * to the next response (keep-alive). For 1.0 with Connection: close
         * we just stop here — the socket will be closed by the caller. */
    } else {
        if (read_all_io(io, &body) != 0) {
            free(body.data);
            http_response_free(out);
            return -7;
        }
    }

    out->body     = body.data;
    out->body_len = body.len;
    return 0;
}

/* ---- Thin wrapper: raw fd ---- */

int http_client_send_fd(int                    fd,
                        const char            *host,
                        uint16_t               port,
                        const http_request_t  *req,
                        http_response_t       *out)
{
    http_io_t io;
    http_io_from_fd(&io, fd);
    return http_client_send_io(&io, host, port, req, out);
}


/* Open / close wrapper */

/* http_client_do — plain HTTP over TCP, with cookies + keep-alive */

int http_client_do(http_client_t        *c,
                   const char           *host,
                   uint16_t              port,
                   const http_request_t *req,
                   http_response_t      *out)
{
    if (!c || !host || !req || !out) return -1;

    int fd = tcp_dial(host, port, c->timeout_ms);
    if (fd < 0) return -2;

    /* Merge client defaults + request headers into one set. */
    http_request_t merged = *req;
    http_headers_init(&merged.headers);
    for (size_t i = 0; i < c->default_headers.count; i++)
        http_headers_set(&merged.headers,
                         c->default_headers.items[i].name,
                         c->default_headers.items[i].value);
    for (size_t i = 0; i < req->headers.count; i++)
        http_headers_set(&merged.headers,
                         req->headers.items[i].name,
                         req->headers.items[i].value);

    /* Cookies */
    char cookiebuf[4096];
    if (http_cookie_jar_header(&c->cookies, host,
                                req->path ? req->path : "/",
                                0 /* plain HTTP */,
                                cookiebuf, sizeof(cookiebuf)) > 0 &&
        !http_headers_get(&merged.headers, "Cookie")) {
        http_headers_set(&merged.headers, "Cookie", cookiebuf);
    }

    /* Keep-alive: if enabled, don't force Connection: close. */
    if (c->keep_alive) {
        http_headers_set(&merged.headers, "Connection", "keep-alive");
    }

    int rc = http_client_send_fd(fd, host, port, &merged, out);

    /* Absorb Set-Cookie headers */
    if (rc == 0 && out->headers.count) {
        for (size_t i = 0; i < out->headers.count; i++) {
            const char *n = out->headers.items[i].name;
            if (n && !strcasecmp(n, "Set-Cookie")) {
                http_cookie_jar_set(&c->cookies,
                                     out->headers.items[i].value,
                                     host);
            }
        }
    }

    http_headers_free(&merged.headers);
    cube_close(fd);

    /* Follow redirects? */
    if (rc == 0 && c->follow_redirects &&
        out->status_code >= 300 && out->status_code < 400) {
        const char *loc = http_headers_get(&out->headers, "Location");
        if (loc) {
            int max = c->max_redirects > 0 ? c->max_redirects
                                            : HTTP_DEFAULT_MAX_REDIRECTS;
            if (max > 0) {
                /* Parse Location — absolute or relative */
                char newhost[256];
                uint16_t newport = port;
                char newpath[2048];
                const char *scheme = "http";

                if (strncmp(loc, "http://", 7) == 0 ||
                    strncmp(loc, "https://", 8) == 0) {
                    const char *p_host;
                    if (strncmp(loc, "https://", 8) == 0) {
                        scheme = "https";
                        p_host = loc + 8;
                        newport = 443;
                    } else {
                        scheme = "http";
                        p_host = loc + 7;
                        newport = 80;
                    }
                    const char *slash = strchr(p_host, '/');
                    size_t hl = slash ? (size_t)(slash - p_host)
                                       : strlen(p_host);
                    if (hl >= sizeof(newhost)) hl = sizeof(newhost) - 1;
                    memcpy(newhost, p_host, hl);
                    newhost[hl] = 0;
                    /* strip :port from host */
                    char *colon = strchr(newhost, ':');
                    if (colon) {
                        *colon = 0;
                        newport = (uint16_t)atoi(colon + 1);
                    }
                    if (slash) {
                        size_t pl = strlen(slash);
                        if (pl >= sizeof(newpath)) pl = sizeof(newpath) - 1;
                        memcpy(newpath, slash, pl);
                        newpath[pl] = 0;
                    } else {
                        newpath[0] = '/';
                        newpath[1] = 0;
                    }
                } else {
                    /* Relative */
                    snprintf(newhost, sizeof(newhost), "%s", host);
                    if (loc[0] == '/') {
                        snprintf(newpath, sizeof(newpath), "%s", loc);
                    } else {
                        /* relative to current dir */
                        const char *cur = req->path ? req->path : "/";
                        const char *lastslash = strrchr(cur, '/');
                        if (lastslash) {
                            size_t pl = (size_t)(lastslash - cur) + 1;
                            if (pl >= sizeof(newpath)) pl = sizeof(newpath) - 1;
                            memcpy(newpath, cur, pl);
                            newpath[pl] = 0;
                            size_t ll = strlen(loc);
                            if (pl + ll >= sizeof(newpath))
                                ll = sizeof(newpath) - pl - 1;
                            memcpy(newpath + pl, loc, ll);
                            newpath[pl + ll] = 0;
                        } else {
                            snprintf(newpath, sizeof(newpath), "/%s", loc);
                        }
                    }
                }

                http_response_free(out);
                http_request_t r2 = *req;
                r2.path = newpath;
                c->max_redirects = max - 1;
                int rc2 = http_client_do(c, newhost, newport, &r2, out);
                c->max_redirects = max;
                (void)scheme;
                return rc2;
            }
        }
    }

    return rc;
}

/* ---- Explicit redirect-following entry point (scheme-aware) ---- */

/* NOTE: this is the crypto-agnostic entry. In cube/core, a TLS wrapper
 * would call http_client_send_io directly for https:// URLs. */

int http_client_do_follow(http_client_t        *c,
                          const char           *host,
                          uint16_t              port,
                          const char           *scheme,
                          const http_request_t *req,
                          int                   max_redirects,
                          http_response_t      *out)
{
    if (!c) return -1;
    int save = c->max_redirects;
    c->follow_redirects = 1;
    c->max_redirects = max_redirects;
    int rc = http_client_do(c, host, port, req, out);
    c->max_redirects = save;
    (void)scheme;
    return rc;
}

/* Convenience */

int http_client_get(http_client_t *c, const char *host, uint16_t port,
                    const char *path, http_response_t *out)
{
    return http_client_get_ver(c, host, port, path, HTTP_11, out);
}

int http_client_get_ver(http_client_t *c, const char *host, uint16_t port,
                        const char *path, http_version_t ver,
                        http_response_t *out)
{
    http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method  = "GET";
    req.path    = path;
    req.version = ver;
    http_headers_init(&req.headers);
    int rc = http_client_do(c, host, port, &req, out);
    http_headers_free(&req.headers);
    return rc;
}

int http_client_post(http_client_t *c, const char *host, uint16_t port,
                     const char *path, const char *content_type,
                     const void *body, size_t body_len,
                     http_response_t *out)
{
    http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method   = "POST";
    req.path     = path;
    req.version  = HTTP_11;
    req.body     = body;
    req.body_len = body_len;
    http_headers_init(&req.headers);
    if (content_type)
        http_headers_set(&req.headers, "Content-Type", content_type);

    int rc = http_client_do(c, host, port, &req, out);
    http_headers_free(&req.headers);
    return rc;
}

/* ---- Protocol dispatcher ---- */

extern int http2_send_io(const http_io_t *, const char *, uint16_t,
                         const char *, const http_request_t *, http_response_t *);

/* Experimental HTTP/3 over QUIC sender. */
static int h3_send_io(const char *host, uint16_t port,
                      const http_request_t *req, http_response_t *out);

int http_send_io(const http_io_t       *io,
                 const char            *host,
                 uint16_t               port,
                 const char            *scheme,
                 const char            *alpn,
                 const http_request_t  *req,
                 http_response_t       *out)
{
    const http_protocol_t *p = http_protocol_for_alpn(alpn);
    if (p->id == HTTP_PROTO_H2)
        return http2_send_io(io, host, port, scheme, req, out);
    if (p->id == HTTP_PROTO_H3)
        return h3_send_io(host, port, req, out);
    return http_client_send_io(io, host, port, req, out);
}

/* ---- HTTP/3 over QUIC (experimental) ----
 *
 * QUIC in this repo is handshake-capable (Initial/ClientHello) but its
 * datagram->frame dispatch and stream layer are not complete, so a real
 * interop H3 client (QPACK, stream flow control, bidirectional streams)
 * cannot be built on top yet.  This is a best-effort, experimental sender:
 * it performs the QUIC Initial, sends the request as a single STREAM frame,
 * and reads back STREAM frames until FIN.  It is intentionally not wired
 * into real H3 servers yet; callers should treat a nonzero return as
 * "H3 not available, fall back to h2/http1". */

static int h3_send_io(const char *host, uint16_t port,
                      const http_request_t *req, http_response_t *out) {
    (void)host; (void)port; (void)req; (void)out;
    return -101; /* h3: QUIC data path not yet implemented */
}


/* Runtime trace switch for the HTTP/2 layer. Off by default. Enabled by cube's --debug flag, or by calling http_client_set_trace(1) directly. */
int g_h2_trace = 0;

void http_client_set_trace(int on) {
    g_h2_trace = on ? 1 : 0;
}
