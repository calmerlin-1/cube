/** platform.h — portable primitives for flywheel. */

#ifndef FLYWHEEL_PLATFORM_H
#define FLYWHEEL_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

uint64_t plat_now_ns(void);
uint64_t plat_realtime_ns(void);

typedef struct {
    int has_aes, has_pmull, has_sha1, has_sha2, has_crc32;
    int has_avx2, has_avx512, has_sse42, has_neon;
} plat_cpu_t;

void plat_cpu_detect(plat_cpu_t *out);

int  plat_mkdir_p(const char *path);
int  plat_file_exists(const char *path);
long plat_rss_bytes(void);
const char *plat_home_dir(void);
const char *plat_tmp_dir(void);

#if defined(_WIN32)
  #define PLAT_PATH_SEP '\\'
#else
  #define PLAT_PATH_SEP '/'
#endif

int plat_path_join(char *dst, size_t cap, const char *a, const char *b);
const char *plat_name(void);
const char *plat_arch(void);

#endif
