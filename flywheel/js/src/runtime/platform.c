/** platform.c — portable primitives. Android, Linux, macOS, Windows. */

#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
  #include <windows.h>
  #include <psapi.h>
#endif

#if defined(__linux__) || defined(__ANDROID__)
  #include <sys/auxv.h>
  #include <unistd.h>
#endif

#if defined(__APPLE__)
  #include <sys/sysctl.h>
  #include <mach/mach.h>
  #include <unistd.h>
#endif

#if defined(_WIN32)
  #include <windows.h>
  #include <direct.h>
  #define mkdir(p, m) _mkdir(p)
  #define stat _stat
#endif

const char *plat_name(void) {
#if defined(__ANDROID__)
    return "android";
#elif defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "macos";
#elif defined(_WIN32)
    return "windows";
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return "bsd";
#else
    return "unknown";
#endif
}

const char *plat_arch(void) {
#if defined(__aarch64__)
    return "aarch64";
#elif defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__arm__) || defined(_M_ARM)
    return "armv7";
#elif defined(__i386__) || defined(_M_IX86)
    return "i386";
#else
    return "unknown";
#endif
}

uint64_t plat_now_ns(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER c;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000000ull) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

uint64_t plat_realtime_ns(void) {
#if defined(_WIN32)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ull) * 100ull;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

#if defined(__x86_64__) || defined(__i386__)
  #if defined(_MSC_VER)
    #include <intrin.h>
    static void _cpuid(unsigned leaf, unsigned sub,
                       unsigned *a, unsigned *b, unsigned *c, unsigned *d) {
        int r[4]; __cpuidex(r, (int)leaf, (int)sub);
        *a = r[0]; *b = r[1]; *c = r[2]; *d = r[3];
    }
  #elif defined(__GNUC__) || defined(__clang__)
    static void _cpuid(unsigned leaf, unsigned sub,
                       unsigned *a, unsigned *b, unsigned *c, unsigned *d) {
        __asm__ volatile("cpuid"
            : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
            : "a"(leaf), "c"(sub));
    }
  #endif
#endif

void plat_cpu_detect(plat_cpu_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

#if defined(__aarch64__)
  #if defined(__linux__) || defined(__ANDROID__)
    unsigned long hw = getauxval(AT_HWCAP);
    out->has_aes   = (hw & (1u << 3)) != 0;
    out->has_pmull = (hw & (1u << 4)) != 0;
    out->has_sha1  = (hw & (1u << 5)) != 0;
    out->has_sha2  = (hw & (1u << 6)) != 0;
    out->has_crc32 = (hw & (1u << 7)) != 0;
    out->has_neon  = 1;
  #elif defined(__APPLE__)
    out->has_aes = 1; out->has_pmull = 1;
    out->has_sha1 = 1; out->has_sha2 = 1;
    out->has_crc32 = 1; out->has_neon = 1;
  #endif
#elif defined(__x86_64__) || defined(__i386__)
  #if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    unsigned a, b, c, d;
    _cpuid(1, 0, &a, &b, &c, &d);
    out->has_aes   = (c & (1u << 25)) != 0;
    out->has_pmull = (c & (1u <<  1)) != 0;
    out->has_sse42 = (c & (1u << 20)) != 0;
    _cpuid(7, 0, &a, &b, &c, &d);
    out->has_sha1 = (b & (1u << 29)) != 0;
    out->has_sha2 = (b & (1u << 29)) != 0;
    out->has_avx2 = (b & (1u <<  5)) != 0;
    out->has_avx512 = (b & (1u << 16)) != 0;
  #endif
#endif
}

int plat_mkdir_p(const char *path) {
    if (!path || !*path) return -1;
    char tmp[1024];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == PLAT_PATH_SEP) {
            *p = '\0';
#if defined(_WIN32)
            _mkdir(tmp);
#else
            mkdir(tmp, 0755);
#endif
            *p = PLAT_PATH_SEP;
        }
    }
#if defined(_WIN32)
    _mkdir(tmp);
#else
    mkdir(tmp, 0755);
#endif
    return 0;
}

int plat_file_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 ? 1 : 0;
}

long plat_rss_bytes(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long size, resident;
    if (fscanf(f, "%ld %ld", &size, &resident) != 2) { fclose(f); return -1; }
    fclose(f);
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    return resident * ps;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &count) != KERN_SUCCESS) return -1;
    return (long)info.resident_size;
#elif defined(_WIN32)
    PROCESS_MEMORY_COUNTERS pmc;
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) return -1;
    return (long)pmc.WorkingSetSize;
#else
    return -1;
#endif
}

const char *plat_home_dir(void) {
    const char *h = getenv("HOME");
    if (h && *h) return h;
#if defined(_WIN32)
    h = getenv("USERPROFILE");
    if (h && *h) return h;
#endif
    return ".";
}

const char *plat_tmp_dir(void) {
    const char *t = getenv("TMPDIR");
    if (t && *t) return t;
#if defined(_WIN32)
    t = getenv("TEMP");
    if (t && *t) return t;
    return "C:\\Temp";
#else
    return "/tmp";
#endif
}

int plat_path_join(char *dst, size_t cap, const char *a, const char *b) {
    if (!dst || cap == 0 || !a || !b) return -1;
    size_t al = strlen(a), bl = strlen(b);
    if (al + 1 + bl + 1 > cap) return -1;
    memcpy(dst, a, al);
    dst[al] = PLAT_PATH_SEP;
    memcpy(dst + al + 1, b, bl);
    dst[al + 1 + bl] = '\0';
    return 0;
}
