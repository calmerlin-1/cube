/** platform.h — portable primitives. Same interface everywhere.
 * Android, Linux, macOS, Windows, BSD, embedded. */

#ifndef CRISPTLS_PLATFORM_H
#define CRISPTLS_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/** Monotonic nanoseconds. Never goes backward. */
uint64_t plat_now_ns(void);

/** Wall-clock nanoseconds since Unix epoch. */
uint64_t plat_realtime_ns(void);

/** CPU feature detection. */
typedef struct {
    int has_aes;
    int has_pmull;
    int has_sha1;
    int has_sha2;
    int has_crc32;
    int has_avx2;
    int has_avx512;
    int has_sse42;
    int has_neon;
} plat_cpu_t;

void plat_cpu_detect(plat_cpu_t *out);

/** Recursive mkdir -p. Returns 0 on success. */
int plat_mkdir_p(const char *path);

/** Does a path exist? Returns 1/0. */
int plat_file_exists(const char *path);

/** Resident set size in bytes, or -1 if unsupported. */
long plat_rss_bytes(void);

/** Home directory. Never NULL. Falls back to "." */
const char *plat_home_dir(void);

/** Temp directory. Never NULL. */
const char *plat_tmp_dir(void);

/** Path separator. '/' everywhere except Windows. */
#if defined(_WIN32)
  #define PLAT_PATH_SEP '\\'
#else
  #define PLAT_PATH_SEP '/'
#endif

/** Join two path components into dst. Returns 0 on success. */
int plat_path_join(char *dst, size_t cap, const char *a, const char *b);

/** Platform name: "linux", "android", "macos", "windows", "bsd", "unknown". */
const char *plat_name(void);

/** Architecture name: "aarch64", "x86_64", "armv7", "i386", "unknown". */
const char *plat_arch(void);

#endif
