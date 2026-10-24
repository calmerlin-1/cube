/** shim.c — LD_PRELOAD interceptor.  Resolves symbols in a constructor
 *  so dlsym's internal allocations cannot recurse into our hooks. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>

static int logfd = -1;
static __thread int in_hook = 0;

static void *(*r_malloc)(size_t) = NULL;
static void  (*r_free)(void *) = NULL;
static void *(*r_calloc)(size_t, size_t) = NULL;
static void *(*r_realloc)(void *, size_t) = NULL;
static void *(*r_memcpy)(void *, const void *, size_t) = NULL;
static void *(*r_memmove)(void *, const void *, size_t) = NULL;
static void *(*r_memset)(void *, int, size_t) = NULL;
static char *(*r_strcpy)(char *, const char *) = NULL;
static char *(*r_strcat)(char *, const char *) = NULL;
static int    (*r_open)(const char *, int, ...) = NULL;
static ssize_t (*r_read)(int, void *, size_t) = NULL;
static ssize_t (*r_write)(int, const void *, size_t) = NULL;
static int    (*r_close)(int) = NULL;

__attribute__((constructor))
static void shim_init(void) {
    in_hook = 1;
    r_malloc  = dlsym(RTLD_NEXT, "malloc");
    r_free    = dlsym(RTLD_NEXT, "free");
    r_calloc  = dlsym(RTLD_NEXT, "calloc");
    r_realloc = dlsym(RTLD_NEXT, "realloc");
    r_memcpy  = dlsym(RTLD_NEXT, "memcpy");
    r_memmove = dlsym(RTLD_NEXT, "memmove");
    r_memset  = dlsym(RTLD_NEXT, "memset");
    r_strcpy  = dlsym(RTLD_NEXT, "strcpy");
    r_strcat  = dlsym(RTLD_NEXT, "strcat");
    r_open    = dlsym(RTLD_NEXT, "open");
    r_read    = dlsym(RTLD_NEXT, "read");
    r_write   = dlsym(RTLD_NEXT, "write");
    r_close   = dlsym(RTLD_NEXT, "close");

    const char *p = getenv("DBUG_TRACE_FILE");
    if (p) logfd = (int)syscall(SYS_openat, AT_FDCWD, p,
                                 O_WRONLY|O_CREAT|O_TRUNC, 0644);
    in_hook = 0;
}

static void logline(const char *fmt, ...) {
    if (logfd < 0) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) syscall(SYS_write, logfd, buf, (size_t)n);
}

/* ---- malloc family ---- */
void *malloc(size_t n) {
    if (in_hook || !r_malloc) return NULL;
    in_hook = 1;
    void *p = r_malloc(n);
    logline("malloc %zu %p\n", n, p);
    in_hook = 0;
    return p;
}
void free(void *p) {
    if (in_hook || !r_free) return;
    in_hook = 1;
    logline("free %p\n", p);
    r_free(p);
    in_hook = 0;
}
void *calloc(size_t a, size_t b) {
    if (in_hook || !r_calloc) return NULL;
    in_hook = 1;
    void *p = r_calloc(a, b);
    logline("calloc %zu %zu %p\n", a, b, p);
    in_hook = 0;
    return p;
}
void *realloc(void *p, size_t n) {
    if (in_hook || !r_realloc) return NULL;
    in_hook = 1;
    void *q = r_realloc(p, n);
    logline("realloc %p %zu %p\n", p, n, q);
    in_hook = 0;
    return q;
}

/* ---- mem/string ---- */
void *memcpy(void *d, const void *s, size_t n) {
    if (in_hook || !r_memcpy) return d;
    in_hook = 1;
    void *r = r_memcpy(d, s, n);
    logline("memcpy %p %p %zu\n", d, s, n);
    in_hook = 0;
    return r;
}
void *memmove(void *d, const void *s, size_t n) {
    if (in_hook || !r_memmove) return d;
    in_hook = 1;
    void *r = r_memmove(d, s, n);
    logline("memmove %p %p %zu\n", d, s, n);
    in_hook = 0;
    return r;
}
void *memset(void *d, int c, size_t n) {
    if (in_hook || !r_memset) return d;
    in_hook = 1;
    void *r = r_memset(d, c, n);
    logline("memset %p %d %zu\n", d, c, n);
    in_hook = 0;
    return r;
}
char *strcpy(char *d, const char *s) {
    if (in_hook || !r_strcpy) return d;
    in_hook = 1;
    char *r = r_strcpy(d, s);
    logline("strcpy %p %s\n", d, s);
    in_hook = 0;
    return r;
}
char *strcat(char *d, const char *s) {
    if (in_hook || !r_strcat) return d;
    in_hook = 1;
    char *r = r_strcat(d, s);
    logline("strcat %p %s\n", d, s);
    in_hook = 0;
    return r;
}

/* ---- io ---- */
int open(const char *path, int flags, ...) {
    if (in_hook || !r_open) return -1;
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    in_hook = 1;
    int fd = r_open(path, flags, mode);
    logline("open %s %d %d\n", path, flags, fd);
    in_hook = 0;
    return fd;
}
ssize_t read(int fd, void *buf, size_t n) {
    if (in_hook || !r_read) return r_read ? r_read(fd, buf, n) : -1;
    in_hook = 1;
    ssize_t r = r_read(fd, buf, n);
    if (fd != logfd) logline("read %d %zu %zd\n", fd, n, r);
    in_hook = 0;
    return r;
}
ssize_t write(int fd, const void *buf, size_t n) {
    if (in_hook || !r_write) return r_write ? r_write(fd, buf, n) : -1;
    in_hook = 1;
    ssize_t r = r_write(fd, buf, n);
    if (fd != logfd) logline("write %d %zu\n", fd, n);
    in_hook = 0;
    return r;
}
int close(int fd) {
    if (in_hook || !r_close) return r_close ? r_close(fd) : -1;
    in_hook = 1;
    int r = r_close(fd);
    logline("close %d\n", fd);
    in_hook = 0;
    return r;
}
