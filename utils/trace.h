#ifndef CUBE_TRACE_H
#define CUBE_TRACE_H

#ifdef TRACE_CALLS
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>

static uint64_t g_trace_start_ns = 0;
static int      g_trace_depth    = 0;

static inline uint64_t trace_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static inline void trace_indent_(void) {
    for (int i = 0; i < g_trace_depth; i++) fputs("  ", stderr);
}

typedef struct { const char *name; } trace_guard_t;

static void trace_exit_cleanup(trace_guard_t *g) {
    uint64_t now = trace_now_ns();
    if (g_trace_depth > 0) g_trace_depth--;
    trace_indent_();
    fprintf(stderr, "[%9.3fms] <- %s\n",
            (now - g_trace_start_ns) / 1e6, g->name);
}

static void trace_enter_print_(const char *fn, const char *desc,
                                const char *fmt, ...) {
    if (g_trace_start_ns == 0) g_trace_start_ns = trace_now_ns();
    uint64_t now = trace_now_ns();
    trace_indent_();
    fprintf(stderr, "[%9.3fms] -> %s(", (now - g_trace_start_ns) / 1e6, fn);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ")  # %s\n", desc);
    g_trace_depth++;
}

#define TRACE_ENTER(desc, ...) \
    __attribute__((cleanup(trace_exit_cleanup))) \
    trace_guard_t _trace_guard_ = { .name = __func__ }; \
    trace_enter_print_(__func__, desc, "" __VA_ARGS__)

#define TRACE_STEP(fmt, ...) do { \
    uint64_t _n = trace_now_ns(); \
    trace_indent_(); \
    fprintf(stderr, "[%9.3fms]    %s: " fmt "\n", \
            (_n - g_trace_start_ns) / 1e6, __func__, ##__VA_ARGS__); \
} while (0)
#else
#define TRACE_ENTER(...) do {} while (0)
#define TRACE_STEP(...)  do {} while (0)
#endif
#endif
