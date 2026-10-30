/** browser.c — minimal CDP (Chromium) and WebDriver BiDi (Firefox) client.
 *
 * Lifecycle: launch a headless browser with a loopback debugging port,
 * discover the WebSocket endpoint over HTTP, then drive it with JSON-RPC.
 * No third-party libraries; the WebSocket framing is implemented here.
 */

#include "browser.h"

#ifdef _WIN32

#include <stdio.h>
int browser_available(const char *engine) { (void)engine; return 0; }
int browser_fetch(const char *url, const char *engine, char **html, size_t *html_len,
                  char *err, size_t cap) {
    (void)url; (void)engine; (void)html; (void)html_len;
    if (err && cap) snprintf(err, cap, "browser automation is not supported on Windows");
    return -1;
}

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
    int fd;
} ws_t;

static void set_err(char *err, size_t cap, const char *msg) {
    if (err && cap) snprintf(err, cap, "%s", msg);
}

static void sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

static int connect_local(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int wait_port(int port, int tries) {
    for (int i = 0; i < tries; i++) {
        int fd = connect_local(port);
        if (fd >= 0) { close(fd); return 0; }
        sleep_ms(100);
    }
    return -1;
}

static int find_free_port(int base) {
    for (int p = base; p < base + 64; p++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((unsigned short)p);
        int ok = bind(fd, (struct sockaddr *)&a, sizeof a) == 0;
        close(fd);
        if (ok) return p;
    }
    return -1;
}

static int send_all(int fd, const void *p, size_t n) {
    const char *c = (const char *)p;
    while (n) {
        ssize_t w = send(fd, c, n, 0);
        if (w <= 0) return -1;
        c += w; n -= (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, void *p, size_t n) {
    char *c = (char *)p;
    while (n) {
        ssize_t r = recv(fd, c, n, 0);
        if (r <= 0) return -1;
        c += r; n -= (size_t)r;
    }
    return 0;
}

/* --- HTTP GET against the local debug endpoint --- */
static int http_get(int port, const char *path, char **out, size_t *out_len) {
    int fd = connect_local(port);
    if (fd < 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char req[512];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                     "Connection: close\r\n\r\n", path, port);
    if (send_all(fd, req, (size_t)n) != 0) { close(fd); return -1; }
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) { close(fd); return -1; }
    for (;;) {
        if (len == cap) {
            char *nb = (char *)realloc(buf, cap * 2 + 1);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb; cap *= 2;
        }
        ssize_t r = recv(fd, buf + len, cap - len, 0);
        if (r <= 0) break;
        len += (size_t)r;
    }
    close(fd);
    buf[len] = 0;
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) { free(buf); return -1; }
    body += 4;
    size_t blen = len - (size_t)(body - buf);
    memmove(buf, body, blen);
    buf[blen] = 0;
    *out = buf; *out_len = blen;
    return 0;
}

/* --- base64 (for the WebSocket key) --- */
static void b64(const unsigned char *in, size_t n, char *out) {
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = 0;
}

static int ws_connect(ws_t *ws, int port, const char *path, const char *subproto,
                      char *err, size_t cap) {
    ws->fd = connect_local(port);
    if (ws->fd < 0) { set_err(err, cap, "browser: debug port unreachable"); return -1; }
    struct timeval tv0 = { 10, 0 };
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof tv0);
    unsigned char key[16];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0 || read(rfd, key, sizeof key) != (ssize_t)sizeof key) {
        for (size_t i = 0; i < sizeof key; i++) key[i] = (unsigned char)(rand() & 0xff);
    }
    if (rfd >= 0) close(rfd);
    char kb64[32]; b64(key, sizeof key, kb64);

    char req[1024];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
        "Origin: http://127.0.0.1:%d\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n%s%s\r\n", path, port, port, kb64,
        subproto ? "Sec-WebSocket-Protocol: " : "",
        subproto ? subproto : "");
    if (send_all(ws->fd, req, (size_t)n) != 0) {
        set_err(err, cap, "browser: websocket handshake send failed");
        close(ws->fd); return -1;
    }
    char resp[4096]; size_t len = 0;
    while (len + 1 < sizeof resp) {
        if (recv_all(ws->fd, resp + len, 1) != 0) break;
        len++;
        resp[len] = 0;
        if (len >= 4 && !memcmp(resp + len - 4, "\r\n\r\n", 4)) break;
    }
    if (!strstr(resp, " 101 ")) {
        if (getenv("CUBE_BROWSER_DEBUG"))
            fprintf(stderr, "[ws] %s\n", resp);
        set_err(err, cap, "browser: websocket upgrade rejected");
        close(ws->fd); return -1;
    }
    struct timeval tv = { 10, 0 };
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return 0;
}

static int ws_send_frame(ws_t *ws, int opcode, const void *data, size_t n) {
    unsigned char h[14]; size_t hl = 0;
    h[hl++] = (unsigned char)(0x80 | opcode);
    if (n < 126) h[hl++] = (unsigned char)(0x80 | n);
    else if (n <= 0xffff) {
        h[hl++] = 0x80 | 126;
        h[hl++] = (unsigned char)(n >> 8);
        h[hl++] = (unsigned char)n;
    } else {
        h[hl++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) h[hl++] = (unsigned char)((uint64_t)n >> (i * 8));
    }
    unsigned char mask[4] = { 0x12, 0x34, 0x56, 0x78 };
    memcpy(h + hl, mask, 4); hl += 4;
    unsigned char *p = (unsigned char *)malloc(n ? n : 1);
    if (!p) return -1;
    for (size_t i = 0; i < n; i++) p[i] = ((const unsigned char *)data)[i] ^ mask[i & 3];
    int rc = send_all(ws->fd, h, hl) == 0 && send_all(ws->fd, p, n) == 0 ? 0 : -1;
    free(p);
    return rc;
}

static int ws_send_text(ws_t *ws, const char *s) {
    return ws_send_frame(ws, 0x1, s, strlen(s));
}

static int ws_recv_text(ws_t *ws, char **out) {
    size_t total = 0, cap = 65536;
    char *acc = (char *)malloc(cap);
    if (!acc) return -1;
    for (;;) {
        unsigned char h[2];
        if (recv_all(ws->fd, h, 2) != 0) { free(acc); return -1; }
        int fin = h[0] & 0x80, opcode = h[0] & 0x0f;
        uint64_t n = h[1] & 0x7f;
        if (n == 126) {
            unsigned char e[2];
            if (recv_all(ws->fd, e, 2) != 0) { free(acc); return -1; }
            n = ((uint64_t)e[0] << 8) | e[1];
        } else if (n == 127) {
            unsigned char e[8];
            if (recv_all(ws->fd, e, 8) != 0) { free(acc); return -1; }
            n = 0;
            for (int i = 0; i < 8; i++) n = (n << 8) | e[i];
        }
        int masked = h[1] & 0x80;
        unsigned char mask[4] = { 0 };
        if (masked && recv_all(ws->fd, mask, 4) != 0) { free(acc); return -1; }
        if (n > 256u * 1024u * 1024u) { free(acc); return -1; }
        if (total + n + 1 > cap) {
            while (total + n + 1 > cap) cap *= 2;
            char *nb = (char *)realloc(acc, cap);
            if (!nb) { free(acc); return -1; }
            acc = nb;
        }
        if (n && recv_all(ws->fd, acc + total, (size_t)n) != 0) { free(acc); return -1; }
        if (masked) for (size_t i = 0; i < n; i++) acc[total + i] ^= mask[i & 3];
        total += (size_t)n;
        if (opcode == 0x9) { ws_send_frame(ws, 0xA, acc, total); total = 0; continue; }
        if (opcode == 0x8) { free(acc); return -1; }
        if (fin) break;
    }
    acc[total] = 0;
    *out = acc;
    return 0;
}

static int rpc(ws_t *ws, const char *json, int id, char **reply) {
    if (ws_send_text(ws, json) != 0) return -1;
    char idbuf[32];
    snprintf(idbuf, sizeof idbuf, "\"id\":%d", id);
    for (int tries = 0; tries < 500; tries++) {
        char *msg = NULL;
        if (ws_recv_text(ws, &msg) != 0) return -1;
        if (strstr(msg, idbuf)) { *reply = msg; return 0; }
        free(msg);
    }
    return -1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void put_utf8(char **o, unsigned cp) {
    if (cp < 0x80) *(*o)++ = (char)cp;
    else if (cp < 0x800) {
        *(*o)++ = (char)(0xC0 | (cp >> 6));
        *(*o)++ = (char)(0x80 | (cp & 0x3F));
    } else {
        *(*o)++ = (char)(0xE0 | (cp >> 12));
        *(*o)++ = (char)(0x80 | ((cp >> 6) & 0x3F));
        *(*o)++ = (char)(0x80 | (cp & 0x3F));
    }
}

/* Extract the first "key":"string" value and JSON-unescape it. */
static int json_string(const char *json, const char *key, char **out) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '"') return -1;
    p++;
    char *buf = (char *)malloc(strlen(p) + 1);
    if (!buf) return -1;
    size_t n = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\' && *p) {
            char e = *p++;
            switch (e) {
            case 'n': buf[n++] = '\n'; break;
            case 'r': buf[n++] = '\r'; break;
            case 't': buf[n++] = '\t'; break;
            case 'b': buf[n++] = '\b'; break;
            case 'f': buf[n++] = '\f'; break;
            case '"': buf[n++] = '"'; break;
            case '\\': buf[n++] = '\\'; break;
            case '/': buf[n++] = '/'; break;
            case 'u': {
                unsigned cp = 0; int ok = 1;
                for (int i = 0; i < 4; i++) {
                    int v = hexval(*p++);
                    if (v < 0) { ok = 0; break; }
                    cp = (cp << 4) | (unsigned)v;
                }
                if (ok) { char *q = buf + n; put_utf8(&q, cp); n = (size_t)(q - buf); }
                break;
            }
            default: buf[n++] = e; break;
            }
        } else buf[n++] = (char)c;
    }
    buf[n] = 0;
    *out = buf;
    return 0;
}

/* --- process management --- */
static pid_t spawn_browser(const char *engine, int port, char *profile, size_t pcap) {
    snprintf(profile, pcap, "/tmp/cube-browser-%d-%d", (int)getpid(), port);
    mkdir(profile, 0700);   /* Firefox requires an existing profile dir */
    pid_t pid = fork();
    if (pid != 0) return pid;
    int debug = getenv("CUBE_BROWSER_DEBUG") != NULL;
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0 && !debug) {
        dup2(devnull, 1);
        dup2(devnull, 2);
    }
    if (devnull > 2) close(devnull);
    setsid();
    char rdport[32], udd[300];
    snprintf(rdport, sizeof rdport, "--remote-debugging-port=%d", port);
    snprintf(udd, sizeof udd, "--user-data-dir=%s", profile);
    if (!strcmp(engine, "firefox")) {
        setenv("MOZ_HEADLESS", "1", 1);
        execlp("firefox", "firefox", "--headless", "--no-remote", rdport,
               "--profile", profile, "about:blank", (char *)NULL);
    } else {
        execlp("chromium", "chromium", "--headless=new", "--no-sandbox",
               "--disable-gpu", "--disable-dev-shm-usage", rdport, udd,
               "about:blank", (char *)NULL);
        execlp("chromium-browser", "chromium-browser", "--headless=new", "--no-sandbox",
               "--disable-gpu", "--disable-dev-shm-usage", rdport, udd,
               "about:blank", (char *)NULL);
        execlp("google-chrome", "google-chrome", "--headless=new", "--no-sandbox",
               "--disable-gpu", "--disable-dev-shm-usage", rdport, udd,
               "about:blank", (char *)NULL);
    }
    _exit(127);
}

static void stop_browser(pid_t pid, const char *profile) {
    if (pid > 0) {
        kill(-pid, SIGTERM);   /* setsid(): pid is the process-group leader */
        kill(pid, SIGTERM);
        int reaped = 0;
        for (int i = 0; i < 40; i++) {
            if (waitpid(pid, NULL, WNOHANG) == pid) { reaped = 1; break; }
            sleep_ms(50);
        }
        if (!reaped) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    if (profile && profile[0]) {
        char cmd[512];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", profile);
        if (system(cmd) != 0) { /* best effort */ }
    }
}

static int on_path(const char *name) {
    const char *path = getenv("PATH");
    if (!path) return 0;
    char buf[4096];
    while (*path) {
        const char *end = strchr(path, ':');
        size_t n = end ? (size_t)(end - path) : strlen(path);
        if (n + strlen(name) + 2 < sizeof buf) {
            memcpy(buf, path, n);
            buf[n] = '/';
            strcpy(buf + n + 1, name);
            if (access(buf, X_OK) == 0) return 1;
        }
        if (!end) break;
        path = end + 1;
    }
    return 0;
}

int browser_available(const char *engine) {
    if (engine && !strcmp(engine, "firefox")) return on_path("firefox");
    return on_path("chromium") || on_path("chromium-browser") || on_path("google-chrome");
}

static int wait_doc_complete(ws_t *ws, int *id, int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited += 100) {
        char cmd[256];
        snprintf(cmd, sizeof cmd,
            "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":"
            "{\"expression\":\"document.readyState\",\"returnByValue\":true}}", ++*id);
        char *reply = NULL;
        if (rpc(ws, cmd, *id, &reply) == 0) {
            int ready = strstr(reply, "\"value\":\"complete\"") != NULL;
            free(reply);
            if (ready) return 0;
        }
        sleep_ms(100);
    }
    return -1;
}

static int chromium_fetch(const char *url, int port, char *err, size_t cap,
                          char **html, size_t *html_len) {
    char *list = NULL; size_t list_len = 0;
    if (http_get(port, "/json/list", &list, &list_len) != 0) {
        set_err(err, cap, "browser: cannot read /json/list");
        return -1;
    }
    char *wsurl = NULL;
    if (json_string(list, "webSocketDebuggerUrl", &wsurl) != 0) {
        free(list); set_err(err, cap, "browser: no debuggable page");
        return -1;
    }
    free(list);
    char *path = strstr(wsurl, "/devtools/");
    ws_t ws;
    if (!path || ws_connect(&ws, port, path, NULL, err, cap) != 0) { free(wsurl); return -1; }
    free(wsurl);

    int id = 0;
    char cmd[8192];
    char *reply = NULL;

    snprintf(cmd, sizeof cmd, "{\"id\":%d,\"method\":\"Page.enable\"}", ++id);
    if (rpc(&ws, cmd, id, &reply) != 0) {
        close(ws.fd); set_err(err, cap, "browser: Page.enable failed"); return -1;
    }
    free(reply);

    char *u = (char *)malloc(strlen(url) * 2 + 1);
    if (!u) { close(ws.fd); return -1; }
    size_t o = 0;
    for (const char *p = url; *p; p++) {
        if (*p == '"' || *p == '\\') u[o++] = '\\';
        u[o++] = *p;
    }
    u[o] = 0;
    snprintf(cmd, sizeof cmd,
        "{\"id\":%d,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"}}", ++id, u);
    free(u);
    if (rpc(&ws, cmd, id, &reply) != 0) {
        close(ws.fd); set_err(err, cap, "browser: navigate failed"); return -1;
    }
    free(reply);

    if (wait_doc_complete(&ws, &id, 8000) != 0) {
        close(ws.fd); set_err(err, cap, "browser: page load timed out"); return -1;
    }
    snprintf(cmd, sizeof cmd,
        "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":"
        "{\"expression\":\"document.documentElement.outerHTML\","
        "\"returnByValue\":true}}", ++id);
    if (rpc(&ws, cmd, id, &reply) != 0) {
        close(ws.fd); set_err(err, cap, "browser: evaluate failed"); return -1;
    }
    int rc = json_string(reply, "value", html);
    free(reply);
    close(ws.fd);
    if (rc != 0) { set_err(err, cap, "browser: no HTML in reply"); return -1; }
    *html_len = strlen(*html);
    return 0;
}

static int bidi_fetch(const char *url, int port, char *err, size_t cap,
                      char **html, size_t *html_len) {
    /* Firefox exposes WebDriver BiDi directly at ws://host:port/. */
    ws_t ws;
    if (ws_connect(&ws, port, "/", "webdriver-bidi", err, cap) != 0) return -1;

    char *reply = NULL, *ctx = NULL;
    const char *setup[] = {
        "{\"id\":1,\"method\":\"session.new\",\"params\":{\"capabilities\":{}}}",
        "{\"id\":2,\"method\":\"browsingContext.create\",\"params\":{\"type\":\"tab\"}}"
    };
    for (int i = 0; i < 2; i++) {
        int id = i + 1;
        if (rpc(&ws, setup[i], id, &reply) != 0) {
            close(ws.fd); set_err(err, cap, "browser: BiDi session setup failed");
            return -1;
        }
        if (i == 1 && json_string(reply, "context", &ctx) != 0) {
            free(reply); close(ws.fd); set_err(err, cap, "browser: no browsing context");
            return -1;
        }
        free(reply);
    }

    char esc[8192]; size_t o = 0;
    for (const char *p = url; *p && o + 2 < sizeof esc; p++) {
        if (*p == '"' || *p == '\\') esc[o++] = '\\';
        esc[o++] = *p;
    }
    esc[o] = 0;

    char cmd[16384];
    snprintf(cmd, sizeof cmd,
        "{\"id\":3,\"method\":\"browsingContext.navigate\",\"params\":"
        "{\"context\":\"%s\",\"url\":\"%s\",\"wait\":\"complete\"}}", ctx, esc);
    if (rpc(&ws, cmd, 3, &reply) != 0) {
        free(ctx); close(ws.fd); set_err(err, cap, "browser: BiDi navigate failed");
        return -1;
    }
    free(reply);

    snprintf(cmd, sizeof cmd,
        "{\"id\":4,\"method\":\"script.evaluate\",\"params\":"
        "{\"expression\":\"document.documentElement.outerHTML\","
        "\"target\":{\"context\":\"%s\"},\"awaitPromise\":false,"
        "\"resultOwnership\":\"none\"}}", ctx);
    free(ctx);
    if (rpc(&ws, cmd, 4, &reply) != 0) {
        close(ws.fd); set_err(err, cap, "browser: BiDi evaluate failed"); return -1;
    }
    int rc = json_string(reply, "value", html);
    free(reply);
    close(ws.fd);
    if (rc != 0) { set_err(err, cap, "browser: no HTML in BiDi reply"); return -1; }
    *html_len = strlen(*html);
    return 0;
}

int browser_fetch(const char *url, const char *engine,
                  char **html, size_t *html_len,
                  char *err, size_t cap) {
    if (!url || !html || !html_len) { set_err(err, cap, "browser: bad args"); return -1; }
    *html = NULL; *html_len = 0;
    if (!engine || !*engine) engine = "chromium";
    if (!browser_available(engine)) {
        char m[160];
        snprintf(m, sizeof m, "browser: %s not found on PATH", engine);
        set_err(err, cap, m);
        return -1;
    }
    int firefox = !strcmp(engine, "firefox");
    int port = find_free_port((firefox ? 9400 : 9300) + (int)(getpid() % 80));
    if (port < 0) { set_err(err, cap, "browser: no free debug port"); return -1; }
    char profile[256];
    pid_t pid = spawn_browser(engine, port, profile, sizeof profile);
    if (pid <= 0) { set_err(err, cap, "browser: launch failed"); return -1; }
    if (wait_port(port, 200) != 0) {
        char m[192];
        snprintf(m, sizeof m, "browser: debug port %d did not open (child %s)", port,
                 kill(pid, 0) == 0 ? "alive" : "exited");
        stop_browser(pid, profile);
        set_err(err, cap, m);
        return -1;
    }
    int rc = firefox ? bidi_fetch(url, port, err, cap, html, html_len)
                     : chromium_fetch(url, port, err, cap, html, html_len);
    stop_browser(pid, profile);
    return rc;
}

#endif /* _WIN32 */
