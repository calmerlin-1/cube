#ifndef CUBE_NET_HTTP_CLIENT_H
#define CUBE_NET_HTTP_CLIENT_H

/** http_client.h — raw HTTP/1.x protocol engine.
 *
 * Scope: HTTP wire format only.
 *   - Request building
 *   - Response parsing (status line, headers, body framing)
 *   - Chunked / Content-Length / EOF body modes
 *   - Cookie jar (RFC 6265-lite)
 *   - Redirect following
 *
 * Out of scope:
 *   - URL parsing          (see flywheel/url)
 *   - DNS resolution       (see net/dns)
 *   - TCP/UDP connection   (caller)
 *   - TLS / QUIC           (see net/crisptls)
 *
 * The protocol logic is transport-agnostic. Callers supply an
 * http_io_t (read/write function pointers) so the same code speaks
 * HTTP over plain TCP, TLS, a pipe, or a test harness.
 *
 * `http_client_do` is a convenience wrapper that opens its own TCP
 * socket via libc getaddrinfo/connect. It is meant for plain HTTP
 * and simple cases. Orchestrators (cube/core) should use
 * `http_client_send_io` and drive the transport themselves.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ---- HTTP version ---- */
typedef enum {
    HTTP_09 = 0,   /* bare GET, no headers, response is raw body */
    HTTP_10 = 1,
    HTTP_11 = 2,
    HTTP_2  = 3,   /* HTTP/2 (RFC 9113) */
} http_version_t;

/* ---- Transport abstraction ----
 *
 * All I/O goes through this. A raw TCP fd is wrapped in http_io_from_fd().
 * A crisptls_conn_t is wrapped in http_io_from_crisptls() (in the caller's
 * code — this header stays crypto-agnostic).
 */
typedef struct http_io {
    void   *ctx;
    ssize_t (*read) (void *ctx, void *buf, size_t n);
    ssize_t (*write)(void *ctx, const void *buf, size_t n);
    int     (*close)(void *ctx);   /* optional */
} http_io_t;

/* Build an http_io_t over a raw POSIX fd. Does not take ownership. */
void http_io_from_fd(http_io_t *io, int fd);

/* ---- Header list ---- */
typedef struct {
    char *name;
    char *value;
} http_header_t;

typedef struct {
    http_header_t *items;
    size_t         count;
    size_t         cap;
} http_headers_t;

void        http_headers_init(http_headers_t *h);
void        http_headers_free(http_headers_t *h);
void        http_headers_set(http_headers_t *h, const char *name, const char *value);
void        http_headers_add(http_headers_t *h, const char *name, const char *value);
const char *http_headers_get(const http_headers_t *h, const char *name);

/* ---- Request / Response ---- */
typedef struct {
    const char     *method;     /* "GET", "POST", ... default: GET */
    const char     *path;       /* "/", "/foo?bar=1" default: "/" */
    http_version_t  version;    /* default: HTTP_11 */
    http_headers_t  headers;
    const void     *body;
    size_t          body_len;
} http_request_t;

typedef struct {
    http_version_t  version;
    int             status_code;
    char           *reason;     /* owned */
    http_headers_t  headers;
    uint8_t        *body;       /* owned */
    size_t          body_len;
} http_response_t;

void http_response_free(http_response_t *r);

/* ---- Client ---- */
typedef struct {
    char  *name;
    char  *value;
    char  *domain;
    char  *path;
    long   expires;      /* 0 = session */
    int    secure;
    int    httponly;
} http_cookie_t;

typedef struct {
    http_cookie_t *items;
    size_t         count;
    size_t         cap;
} http_cookie_jar_t;

typedef struct {
    int               timeout_ms;      /* 0 = blocking forever */
    int               keep_alive;      /* 1 = don't force Connection: close */
    int               follow_redirects;/* 1 = auto-follow 3xx */
    int               max_redirects;   /* default 10 */
    unsigned          flags;           /* HTTP_F_* */
    http_headers_t    default_headers;
    http_cookie_jar_t cookies;         /* optional; only used if keep_alive or explicit */
} http_client_t;

void http_client_init(http_client_t *c);
void http_client_free(http_client_t *c);

/* ---- Send a request over a caller-owned fd (no connect/close). ---- */
int http_client_send_fd(int                    fd,
                        const char            *host,
                        uint16_t               port,
                        const http_request_t  *req,
                        http_response_t       *out);

/* ---- Full open/close request against host:port. ---- */
int http_client_do(http_client_t        *c,
                   const char           *host,
                   uint16_t              port,
                   const http_request_t *req,
                   http_response_t      *out);

/* ---- Convenience ---- */
int http_client_get(http_client_t *c, const char *host, uint16_t port,
                    const char *path, http_response_t *out);

int http_client_post(http_client_t *c, const char *host, uint16_t port,
                     const char *path, const char *content_type,
                     const void *body, size_t body_len,
                     http_response_t *out);

/* ---- I/O variant (crisptls, tests, pipes) ----
 *
 * Send a request over an arbitrary http_io_t. Caller owns the io's
 * lifetime; we neither connect nor close.
 */
int http_client_send_io(const http_io_t       *io,
                        const char            *host,
                        uint16_t               port,
                        const http_request_t  *req,
                        http_response_t       *out);

/* ---- Redirects ----
 *
 * Follow 3xx responses up to max_redirects. Handles relative Location.
 * Cookies are carried through if a jar is supplied (may be NULL).
 */
int http_client_do_follow(http_client_t      *c,
                          const char         *host,
                          uint16_t            port,
                          const char         *scheme,     /* "http" or "https" */
                          const http_request_t *req,
                          int                 max_redirects,
                          http_response_t    *out);

/* ---- Cookie jar ---- */


void http_cookie_jar_init(http_cookie_jar_t *j);
void http_cookie_jar_free(http_cookie_jar_t *j);

/* Parse a Set-Cookie header value. default_domain is the request's host. */
void http_cookie_jar_set(http_cookie_jar_t *j, const char *set_cookie,
                         const char *default_domain);

/* Build a Cookie: header value for host/path/secure. Returns bytes written. */
size_t http_cookie_jar_header(const http_cookie_jar_t *j,
                              const char *host, const char *path, int secure,
                              char *out, size_t cap);

/* Store/load (Netscape format). Returns 0 on success. */
int http_cookie_jar_save(const http_cookie_jar_t *j, const char *path);
int http_cookie_jar_load(http_cookie_jar_t *j, const char *path);

/* ---- Keep-alive: on http_client_t ---- */
#define HTTP_DEFAULT_MAX_REDIRECTS 10

/* ---- Strict-mode flags (client->flags) ----
 *
 * Default (0) is forgiving — matches what a browser does with broken
 * servers. Set HTTP_F_STRICT to reject protocol violations with a
 * distinct error code instead of guessing.
 */
#define HTTP_F_STRICT         (1u << 0)  /* reject protocol violations */
#define HTTP_F_REJECT_CHUNKED_10 (1u << 1) /* RFC 1945: no TE in HTTP/1.0 */

/* Version-explicit convenience (http_client_get forces HTTP_11). */
int http_client_get_ver(http_client_t *c, const char *host, uint16_t port,
                        const char *path, http_version_t ver,
                        http_response_t *out);

/* Content-Length validation helper (exposed for tests). */
int http_parse_content_length(const char *s, unsigned long long *out);

/* ---- Protocol dispatcher ----
 *
 * Sends the request using HTTP/2 if `alpn` is "h2", otherwise HTTP/1.x.
 * Caller passes whatever ALPN the TLS layer negotiated. */
int http_send_io(const http_io_t       *io,
                 const char            *host,
                 uint16_t               port,
                 const char            *scheme,
                 const char            *alpn,
                 const http_request_t  *req,
                 http_response_t       *out);

/* Runtime trace switch. When enabled, HTTP/2 frame operations print
 * to stderr. Default off. */
void http_client_set_trace(int on);

#endif /* CUBE_NET_HTTP_CLIENT_H */
