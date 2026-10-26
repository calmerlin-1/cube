/** tcp.c — TCP connect. See include/tcp.h.
 *
 * Portable across POSIX (Linux, macOS, BSD, Android) and Windows.
 * The #ifdef _WIN32 block below aliases Windows Sockets to the POSIX
 * API used throughout the file. No caller-visible difference: every
 * public function behaves identically on both platforms.
 */

#ifdef _WIN32
    #define _WIN32_WINNT 0x0600
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    #include <stdint.h>
    #include <stdarg.h>
    #include <string.h>
    #include <errno.h>

    /* Linkage */
    #pragma comment(lib, "ws2_32.lib")

    /* Types */
    typedef SSIZE_T ssize_t;
    typedef int     socklen_t;
    typedef int     nfds_t;

    /* Socket lifecycle */
    #define cube_close(fd)          closesocket(fd)
    #define cube_read(fd, b, n)     recv((fd), (char *)(b), (int)(n), 0)
    #define cube_write(fd, b, n)    send((fd), (const char *)(b), (int)(n), 0)

    /* Poll */
    #define cube_pollfd             WSAPOLLFD
    #define cube_poll               WSAPoll
    #define POLLIN                  POLLRDNORM
    #define POLLOUT                 POLLWRNORM

    /* errno mapping */
    #define cube_errno              WSAGetLastError()
    #define cube_socket_err_is_eintr(e)     ((e) == WSAEINTR)
    #define cube_socket_err_is_eagain(e)    ((e) == WSAEWOULDBLOCK)
    #define cube_socket_err_str(e)          \
        ({ static char _b[128]; snprintf(_b, sizeof _b, "WSA %d", (int)(e)); _b; })
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/socket.h>
    #include <stdint.h>
    #include <stdarg.h>
    #include <string.h>
    #include <errno.h>

    #define cube_close(fd)          close(fd)
    #define cube_read(fd, b, n)     read((fd), (b), (n))
    #define cube_write(fd, b, n)    write((fd), (b), (n))

    #define cube_pollfd             struct pollfd
    #define cube_poll               poll

    #define cube_errno              errno
    #define cube_socket_err_is_eintr(e)     ((e) == EINTR)
    #define cube_socket_err_is_eagain(e)    ((e) == EAGAIN || (e) == EWOULDBLOCK)
    #define cube_socket_err_str(e)          strerror(e)
#endif
/* portable errno helpers */
#ifdef _WIN32
static int  cube_set_nonblock(int fd, int on) { u_long m = on?1:0; return ioctlsocket(fd, FIONBIO, &m); }
static int  cube_errno_is_inprogress(int e)   { return e == WSAEWOULDBLOCK; }
static void cube_set_errno_inval(void)        { WSASetLastError(WSAEINVAL); }
static void cube_set_errno(int e)             { WSASetLastError(e ? e : WSAEINVAL); }
#else
static int  cube_set_nonblock(int fd, int on) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (on) fl |=  O_NONBLOCK;
    else    fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl);
}
static int  cube_errno_is_inprogress(int e)   { return e == EINPROGRESS; }
static void cube_set_errno_inval(void)        { errno = EINVAL; }
static void cube_set_errno(int e)             { errno = e ? e : EINVAL; }
#endif


#include "tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* helpers */

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
    cube_pollfd p = { fd, events, 0 };
    int t = (timeout_ms == 0) ? -1
          : (timeout_ms > (uint32_t)INT_MAX) ? INT_MAX
          : (int)timeout_ms;
    for (;;) {
        int r = cube_poll(&p, 1, t);
        if (r < 0 && cube_socket_err_is_eintr(cube_errno)) continue;
        if (r < 0) return -1;
        if (r == 0) { /* timeout */; return -1; }
        return 0;
    }
}

/* public API */

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
    /* Heuristic: RFC 1035 hostname chars only — letters, digits, dot, hyphen,
     * underscore. At least one dot, at least one letter. No leading/trailing dot. */
    int has_dot = 0, has_alpha = 0;
    size_t len = 0;
    for (const char *p = s; *p; p++, len++) {
        unsigned char c = (unsigned char)*p;
        if (c == '.') has_dot = 1;
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) has_alpha = 1;
        else if (!((c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    if (len == 0 || s[0] == '.' || s[len-1] == '.') return 0;
    return (has_dot && has_alpha) ? 1 : 0;
}

int tcp_connect(const char *ip, int family, uint16_t port,
                uint32_t timeout_ms, char *err, size_t err_cap)
{
    if (!ip || !*ip) { set_err(err, err_cap, "empty ip"); cube_set_errno_inval(); return -1; }
    if (port == 0)   { set_err(err, err_cap, "port 0");   cube_set_errno_inval(); return -1; }
    if (tcp_looks_like_hostname(ip)) {
        set_err(err, err_cap, "hostname given to tcp_connect; resolve first (%s)", ip);
        cube_set_errno_inval(); return -1;
    }

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    int parsed_fam = 0;
    if (parse_ip(ip, &parsed_fam, &ss, &slen) != 0) {
        set_err(err, err_cap, "not a valid IP: %s", ip);
        cube_set_errno_inval(); return -1;
    }
    if (family != AF_UNSPEC && family != parsed_fam) {
        set_err(err, err_cap, "family mismatch: asked %s, ip is %s",
                family == AF_INET ? "AF_INET" : "AF_INET6",
                parsed_fam == AF_INET ? "AF_INET" : "AF_INET6");
        cube_set_errno_inval(); return -1;
    }
    set_port(&ss, port);

    int fd = socket(parsed_fam, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { set_err(err, err_cap, "socket: %s", cube_socket_err_str(cube_errno)); return -1; }

    /* Sensible defaults. Callers may override via tcp_set_* afterwards,
     * but these get used during connect. */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof one);

    /* Set non-blocking during connect so we can enforce a timeout via poll. */
    int fl = cube_set_nonblock(fd, 1);
    if (fl < 0) {
        set_err(err, err_cap, "fcntl: %s", cube_socket_err_str(cube_errno));
        cube_close(fd); return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&ss, slen);
    if (rc < 0 && !cube_errno_is_inprogress(cube_errno)) {
        set_err(err, err_cap, "connect: %s", cube_socket_err_str(cube_errno));
        cube_close(fd); return -1;
    }

    if (rc < 0) {
        /* Wait for writability (connect completed) or timeout. */
        if (wait_fd(fd, POLLOUT, timeout_ms) != 0) {
            set_err(err, err_cap, "connect timeout (%ums)", (unsigned)timeout_ms);
            cube_close(fd); return -1;
        }
        int soerr = 0; socklen_t solen = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) < 0 || soerr != 0) {
            cube_set_errno(soerr);
            set_err(err, err_cap, "connect: %s", cube_socket_err_str(cube_errno));
            cube_close(fd); return -1;
        }
    }

    /* Restore blocking mode. Caller can set non-blocking again if wanted. */
    if (cube_set_nonblock(fd, fl) < 0) {
        set_err(err, err_cap, "fcntl restore: %s", cube_socket_err_str(cube_errno));
        cube_close(fd); return -1;
    }

    return fd;
}

/* tuning */

int tcp_set_nodelay(int fd, int on) {
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
}
int tcp_set_keepalive(int fd, int on) {
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
}
int tcp_set_nonblocking(int fd, int on) {
    return cube_set_nonblock(fd, on ? 1 : 0);
}
int tcp_set_rcvbuf(int fd, int bytes) {
    if (bytes < 0) { cube_set_errno_inval(); return -1; }
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
}
int tcp_set_sndbuf(int fd, int bytes) {
    if (bytes < 0) { cube_set_errno_inval(); return -1; }
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
}
int tcp_set_reuseaddr(int fd, int on) {
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
}

/* I/O */

ssize_t tcp_read(int fd, void *buf, size_t n, uint32_t timeout_ms) {
    if (fd < 0 || (!buf && n)) { cube_set_errno_inval(); return -1; }
    for (;;) {
        if (wait_fd(fd, POLLIN, timeout_ms) != 0) return -1;
        ssize_t r = cube_read(fd, buf, n);
        if (r < 0 && (cube_socket_err_is_eintr(cube_errno) || cube_socket_err_is_eagain(cube_errno))) continue;
        return r;
    }
}

ssize_t tcp_write(int fd, const void *buf, size_t n, uint32_t timeout_ms) {
    if (fd < 0 || (!buf && n)) { cube_set_errno_inval(); return -1; }
    for (;;) {
        if (wait_fd(fd, POLLOUT, timeout_ms) != 0) return -1;
        ssize_t r = cube_write(fd, buf, n);
        if (r < 0 && (cube_socket_err_is_eintr(cube_errno) || cube_socket_err_is_eagain(cube_errno))) continue;
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

/* close */

int tcp_shutdown_write(int fd) {
    if (fd < 0) return -1;
    return shutdown(fd, SHUT_WR);
}

void tcp_close(int fd) {
    if (fd >= 0) cube_close(fd);
}

/* peer / local */

int tcp_peer(int fd, char *ip, size_t cap, uint16_t *port) {
    if (!ip || cap < 46) { cube_set_errno_inval(); return -1; }
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

/* range helpers */

/* IPv4 range: "A.B.C.D-A.B.C.E". Only 32-bit arithmetic; safe for /16
 * scans and smaller. For IPv6, ranges are rejected. */
long tcp_parse_range(const char *spec, char *start_ip, size_t cap) {
    if (!spec || !start_ip || cap < 16) return -1;
    const char *dash = strchr(spec, '-');
    struct in_addr a, b;

    if (!dash) {
        /* Single IP — return 1 (per header: ">= 1") */
        if (inet_pton(AF_INET, spec, &a) != 1) return -1;
        snprintf(start_ip, cap, "%s", spec);
        return 1;
    }

    char lo[64]; size_t ll = (size_t)(dash - spec);
    if (ll == 0 || ll >= sizeof lo) return -1;
    memcpy(lo, spec, ll); lo[ll] = 0;

    char hi[64]; snprintf(hi, sizeof hi, "%s", dash + 1);

    if (inet_pton(AF_INET, lo, &a) != 1) return -1;
    if (inet_pton(AF_INET, hi, &b) != 1) return -1;

    uint32_t lo_h = ntohl(a.s_addr);
    uint32_t hi_h = ntohl(b.s_addr);
    if (hi_h < lo_h) return -1;

    /* Full range 0.0.0.0-255.255.255.255 = 2^32 addresses, doesn't fit in long on 32-bit */
    uint64_t count = (uint64_t)hi_h - lo_h + 1;
    if (count > (uint64_t)LONG_MAX) return -1;

    snprintf(start_ip, cap, "%s", lo);
    return (long)count;
}

int tcp_range_nth(const char *start_ip, long n, char *out, size_t cap) {
    if (!start_ip || !out || n < 0) return -1;
    struct in_addr a;
    if (inet_pton(AF_INET, start_ip, &a) != 1) return -1;
    uint32_t base = ntohl(a.s_addr);
    if ((uint64_t)base + (uint64_t)n > 0xFFFFFFFFull) { errno = ERANGE; return -1; }
    uint32_t cur = base + (uint32_t)n;
    struct in_addr c; c.s_addr = htonl(cur);
    return inet_ntop(AF_INET, &c, out, (socklen_t)cap) ? 0 : -1;
}
