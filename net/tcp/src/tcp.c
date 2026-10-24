/** tcp.c — TCP connect. See include/tcp.h. */
#define _GNU_SOURCE
#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdarg.h>

/* ─── helpers ─────────────────────────────────────────────────────── */

static void set_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int parse_ip(const char *ip, int *family_out,
                    struct sockaddr_storage *ss_out, socklen_t *slen_out)
{
    if (!ip || !family_out || !ss_out) return -1;

    struct in_addr  a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, ip, &a4) == 1) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss_out;
        memset(s, 0, sizeof(*s));
        s->sin_family = AF_INET;
        s->sin_addr   = a4;
        *family_out = AF_INET;
        *slen_out = sizeof(*s);
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &a6) == 1) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss_out;
        memset(s, 0, sizeof(*s));
        s->sin6_family = AF_INET6;
        s->sin6_addr   = a6;
        *family_out = AF_INET6;
        *slen_out = sizeof(*s);
        return 0;
    }
    return -1;
}

static int set_port(struct sockaddr_storage *ss, uint16_t port) {
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
    } else if (ss->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
    } else return -1;
    return 0;
}

/* Wait for fd readability/writability with ms timeout. 0 = block forever. */
static int wait_fd(int fd, short events, uint32_t timeout_ms) {
    struct pollfd p = { fd, events, 0 };
    int t = (timeout_ms == 0) ? -1 : (int)timeout_ms;
    for (;;) {
        int r = poll(&p, 1, t);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) { errno = ETIMEDOUT; return -1; }
        return 0;
    }
}

/* ─── public API ──────────────────────────────────────────────────── */

int tcp_ip_family(const char *ip) {
    struct in_addr  a4;
    struct in6_addr a6;
    if (!ip || !*ip) return -1;
    if (inet_pton(AF_INET,  ip, &a4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, ip, &a6) == 1) return AF_INET6;
    return -1;
}

int tcp_looks_like_hostname(const char *s) {
    if (!s || !*s) return 0;
    if (tcp_ip_family(s) != -1) return 0;   /* it IS an IP */
    /* Heuristic: at least one dot, no colon, letters present */
    int has_dot = 0, has_colon = 0, has_alpha = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '.') has_dot = 1;
        if (*p == ':') has_colon = 1;
        if (isalpha((unsigned char)*p)) has_alpha = 1;
    }
    return (has_dot && !has_colon && has_alpha) ? 1 : 0;
}

int tcp_connect(const char *ip, int family, uint16_t port,
                uint32_t timeout_ms, char *err, size_t err_cap)
{
    if (!ip || !*ip) { set_err(err, err_cap, "empty ip"); errno = EINVAL; return -1; }
    if (port == 0)   { set_err(err, err_cap, "port 0");   errno = EINVAL; return -1; }
    if (tcp_looks_like_hostname(ip)) {
        set_err(err, err_cap, "hostname given to tcp_connect; resolve first (%s)", ip);
        errno = EINVAL; return -1;
    }

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    int parsed_fam = 0;
    if (parse_ip(ip, &parsed_fam, &ss, &slen) != 0) {
        set_err(err, err_cap, "not a valid IP: %s", ip);
        errno = EINVAL; return -1;
    }
    if (family != AF_UNSPEC && family != parsed_fam) {
        set_err(err, err_cap, "family mismatch: asked %s, ip is %s",
                family == AF_INET ? "AF_INET" : "AF_INET6",
                parsed_fam == AF_INET ? "AF_INET" : "AF_INET6");
        errno = EINVAL; return -1;
    }
    set_port(&ss, port);

    int fd = socket(parsed_fam, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { set_err(err, err_cap, "socket: %s", strerror(errno)); return -1; }

    /* Sensible defaults. Callers may override via tcp_set_* afterwards,
     * but these get used during connect. */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof one);

    /* Set non-blocking during connect so we can enforce a timeout via poll. */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        set_err(err, err_cap, "fcntl: %s", strerror(errno));
        close(fd); return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&ss, slen);
    if (rc < 0 && errno != EINPROGRESS) {
        set_err(err, err_cap, "connect: %s", strerror(errno));
        close(fd); return -1;
    }

    if (rc < 0) {
        /* Wait for writability (connect completed) or timeout. */
        if (wait_fd(fd, POLLOUT, timeout_ms) != 0) {
            set_err(err, err_cap, "connect timeout (%ums)", (unsigned)timeout_ms);
            close(fd); return -1;
        }
        int soerr = 0; socklen_t solen = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) < 0 || soerr != 0) {
            errno = soerr ? soerr : errno;
            set_err(err, err_cap, "connect: %s", strerror(errno));
            close(fd); return -1;
        }
    }

    /* Restore blocking mode. Caller can set non-blocking again if wanted. */
    if (fcntl(fd, F_SETFL, fl) < 0) {
        set_err(err, err_cap, "fcntl restore: %s", strerror(errno));
        close(fd); return -1;
    }

    return fd;
}

/* ─── tuning ──────────────────────────────────────────────────────── */

int tcp_set_nodelay(int fd, int on) {
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
}
int tcp_set_keepalive(int fd, int on) {
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
}
int tcp_set_nonblocking(int fd, int on) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (on) fl |=  O_NONBLOCK;
    else    fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl);
}
int tcp_set_rcvbuf(int fd, int bytes) {
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
}
int tcp_set_sndbuf(int fd, int bytes) {
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
}
int tcp_set_reuseaddr(int fd, int on) {
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
}

/* ─── I/O ─────────────────────────────────────────────────────────── */

ssize_t tcp_read(int fd, void *buf, size_t n, uint32_t timeout_ms) {
    if (fd < 0 || (!buf && n)) { errno = EINVAL; return -1; }
    for (;;) {
        if (wait_fd(fd, POLLIN, timeout_ms) != 0) return -1;
        ssize_t r = read(fd, buf, n);
        if (r < 0 && errno == EINTR) continue;
        return r;
    }
}

ssize_t tcp_write(int fd, const void *buf, size_t n, uint32_t timeout_ms) {
    if (fd < 0 || (!buf && n)) { errno = EINVAL; return -1; }
    for (;;) {
        if (wait_fd(fd, POLLOUT, timeout_ms) != 0) return -1;
        ssize_t r = write(fd, buf, n);
        if (r < 0 && errno == EINTR) continue;
        return r;
    }
}

int tcp_read_exact(int fd, void *buf, size_t n, uint32_t timeout_ms) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = tcp_read(fd, (char *)buf + done, n - done, timeout_ms);
        if (r < 0) return -1;
        if (r == 0) { errno = ECONNRESET; return -1; }
        done += (size_t)r;
    }
    return 0;
}

int tcp_write_all(int fd, const void *buf, size_t n, uint32_t timeout_ms) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = tcp_write(fd, (const char *)buf + done, n - done, timeout_ms);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

/* ─── close ───────────────────────────────────────────────────────── */

int tcp_shutdown_write(int fd) {
    if (fd < 0) return -1;
    return shutdown(fd, SHUT_WR);
}

void tcp_close(int fd) {
    if (fd >= 0) close(fd);
}

/* ─── peer / local ────────────────────────────────────────────────── */

int tcp_peer(int fd, char *ip, size_t cap, uint16_t *port) {
    struct sockaddr_storage ss; socklen_t slen = sizeof ss;
    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) return -1;
    const void *src = NULL;
    if (ss.ss_family == AF_INET) {
        src = &((struct sockaddr_in *)&ss)->sin_addr;
        if (port) *port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        src = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        if (port) *port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    } else return -1;
    if (!inet_ntop(ss.ss_family, src, ip, (socklen_t)cap)) return -1;
    return 0;
}

int tcp_local(int fd, char *ip, size_t cap, uint16_t *port) {
    struct sockaddr_storage ss; socklen_t slen = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &slen) != 0) return -1;
    const void *src = NULL;
    if (ss.ss_family == AF_INET) {
        src = &((struct sockaddr_in *)&ss)->sin_addr;
        if (port) *port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        src = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        if (port) *port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    } else return -1;
    if (!inet_ntop(ss.ss_family, src, ip, (socklen_t)cap)) return -1;
    return 0;
}

/* ─── range helpers ───────────────────────────────────────────────── */

/* IPv4 range: "A.B.C.D-A.B.C.E". Only 32-bit arithmetic; safe for /16
 * scans and smaller. For IPv6, ranges are rejected. */
long tcp_parse_range(const char *spec, char *start_ip, size_t cap) {
    if (!spec || !start_ip || cap < 16) return -1;
    const char *dash = strchr(spec, '-');
    if (!dash) return -1;

    char lo[64]; size_t ll = (size_t)(dash - spec);
    if (ll == 0 || ll >= sizeof lo) return -1;
    memcpy(lo, spec, ll); lo[ll] = 0;

    char hi[64]; snprintf(hi, sizeof hi, "%s", dash + 1);

    struct in_addr a, b;
    if (inet_pton(AF_INET, lo, &a) != 1) return -1;
    if (inet_pton(AF_INET, hi, &b) != 1) return -1;

    uint32_t lo_h = ntohl(a.s_addr);
    uint32_t hi_h = ntohl(b.s_addr);
    if (hi_h < lo_h) return -1;

    snprintf(start_ip, cap, "%s", lo);
    return (long)(hi_h - lo_h + 1);
}

int tcp_range_nth(const char *start_ip, long n, char *out, size_t cap) {
    if (!start_ip || !out || n < 0) return -1;
    struct in_addr a;
    if (inet_pton(AF_INET, start_ip, &a) != 1) return -1;
    uint32_t base = ntohl(a.s_addr);
    uint32_t cur  = base + (uint32_t)n;
    struct in_addr c; c.s_addr = htonl(cur);
    return inet_ntop(AF_INET, &c, out, (socklen_t)cap) ? 0 : -1;
}
