/** strutil.c — allocation and small string helpers. */

#include "sear.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

void *sear_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "sear: out of memory\n"); exit(1); }
    return p;
}

void *sear_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "sear: out of memory\n"); exit(1); }
    return q;
}

char *sear_xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = sear_xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *sear_xstrndup(const char *s, size_t n) {
    char *p = sear_xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

int sear_endswith(const char *s, const char *suffix) {
    size_t ls = strlen(s), lx = strlen(suffix);
    if (lx > ls) return 0;
    return memcmp(s + (ls - lx), suffix, lx) == 0;
}

int sear_startswith(const char *s, const char *pfx) {
    while (*pfx) { if (*s != *pfx) return 0; s++; pfx++; }
    return 1;
}

char *sear_read_all_fd(int fd, size_t *out_len) {
    size_t cap = 4096, len = 0;
    char *buf = sear_xmalloc(cap);
    for (;;) {
        if (len == cap) {
            cap *= 2;
            buf = sear_xrealloc(buf, cap);
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return NULL;
        }
        len += (size_t)n;
    }
    if (len == cap) {
        cap += 1;
        buf = sear_xrealloc(buf, cap);
    }
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}
