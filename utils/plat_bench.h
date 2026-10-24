/**
 * plat_bench.h — portable benchmarking primitives for throughput testers.
 *
 * Header-only. Any tester links it by #include alone. Nothing platform-
 * specific leaks into the caller.
 *
 * Provides:
 *   plat_bench_now_ns()       monotonic clock
 *   plat_bench_pin_cpu(n)     best-effort affinity pin, 0 on success
 *   plat_bench_freq()         reads scaling_cur_freq across cores, MHz
 *   plat_bench_cpu_count()    online core count
 *   plat_bench_arch()         architecture name string
 *
 * On platforms without cpufreq (Windows, macOS without sysctl, some VMs),
 * freq functions return 0 and callers should print "unknown".
 */

#ifndef CUBE_UTILS_PLAT_BENCH_H
#define CUBE_UTILS_PLAT_BENCH_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
  #define PLAT_BENCH_LINUX 1
  #include <time.h>
  #include <unistd.h>
#elif defined(__APPLE__)
  #define PLAT_BENCH_DARWIN 1
  #include <time.h>
  #include <sys/sysctl.h>
#elif defined(_WIN32)
  #define PLAT_BENCH_WINDOWS 1
  #include <windows.h>
#endif

/* ---- clock ---- */

static inline uint64_t plat_bench_now_ns(void) {
#if defined(PLAT_BENCH_WINDOWS)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (uint64_t)((double)c.QuadPart / (double)f.QuadPart * 1e9);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

/* ---- affinity (best effort) ----
 * Caller must define _GNU_SOURCE before including this header
 * to get sched_setaffinity on glibc. Bionic (Android) always has it. */

static inline int plat_bench_pin_cpu(int cpu) {
#if defined(PLAT_BENCH_LINUX)
    #if defined(__ANDROID__) || defined(_GNU_SOURCE)
      extern int sched_setaffinity(int, size_t, const void *);
      /* We forward-declare rather than #include <sched.h> so callers
       * don't need _GNU_SOURCE dance. Actual prototype matches glibc. */
      unsigned long mask = 1UL << cpu;
      /* cpu_set_t is a bitmask; on 64-bit Linux it's 128 bytes but the
       * kernel only reads sizeof(unsigned long) worth for the syscall. */
      struct { unsigned long bits[16]; } set = {{0}};
      set.bits[cpu / (8 * sizeof(unsigned long))] = 1UL << (cpu % (8 * sizeof(unsigned long)));
      (void)mask;
      return sched_setaffinity(0, sizeof(set), &set);
    #else
      (void)cpu; return -1;
    #endif
#else
    (void)cpu;
    return -1;
#endif
}

/* ---- cpu frequency (best effort) ---- */

static inline long plat_bench_read_khz(const char *path) {
#if defined(PLAT_BENCH_LINUX)
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) v = -1;
    fclose(f);
    return v;
#else
    (void)path;
    return -1;
#endif
}

typedef struct {
    int    cores;
    long   max_khz;
    long   min_khz;
    double mean_khz;
} plat_bench_freq_t;

static inline void plat_bench_freq(plat_bench_freq_t *out) {
    memset(out, 0, sizeof(*out));
    out->max_khz = -1;
    out->min_khz = -1;
#if defined(PLAT_BENCH_LINUX)
    long sum = 0;
    int n = 0;
    for (int cpu = 0; cpu < 64; cpu++) {
        char path[256];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
        long khz = plat_bench_read_khz(path);
        if (khz <= 0) continue;
        if (out->max_khz < 0 || khz > out->max_khz) out->max_khz = khz;
        if (out->min_khz < 0 || khz < out->min_khz) out->min_khz = khz;
        sum += khz;
        n++;
    }
    out->cores = n;
    out->mean_khz = n ? (double)sum / n : 0;
#elif defined(PLAT_BENCH_DARWIN)
    uint64_t freq = 0;
    size_t sz = sizeof(freq);
    if (sysctlbyname("hw.cpufrequency", &freq, &sz, NULL, 0) == 0 && freq > 0) {
        out->max_khz = (long)(freq / 1000);
        out->min_khz = out->max_khz;
        out->mean_khz = (double)out->max_khz;
    }
    out->cores = 1;
#endif
}

static inline int plat_bench_cpu_count(void) {
#if defined(PLAT_BENCH_LINUX)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#else
    return 1;
#endif
}

static inline const char *plat_bench_arch(void) {
#if defined(__aarch64__)   return "aarch64";
#elif defined(__x86_64__)  return "x86_64";
#elif defined(__i386__)    return "i386";
#elif defined(__arm__)     return "arm";
#elif defined(__riscv)     return "riscv64";
#elif defined(__wasm__)    return "wasm";
#else                      return "unknown";
#endif
}

#endif /* CUBE_UTILS_PLAT_BENCH_H */
