/** os_hooks.c — one implementation per OS.
 * Each branch below uses #if per platform. No assumptions. */

#include "os_hooks.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- per-OS includes and command wrappers ---- */
#if defined(_WIN32)
  #include <windows.h>
  #include <direct.h>
  #include <process.h>
  #define FW_POPEN   _popen
  #define FW_PCLOSE  _pclose
  #define FW_GETPID  _getpid
#elif defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__) || \
      defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  #define FW_POPEN   popen
  #define FW_PCLOSE  pclose
  #define FW_GETPID  getpid
#else
  /* Unknown POSIX-like target. Try generic. */
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  #define FW_POPEN   popen
  #define FW_PCLOSE  pclose
  #define FW_GETPID  getpid
#endif

const char *os_name(void)      { return plat_name(); }
const char *os_arch(void)      { return plat_arch(); }
const char *os_home_dir(void)  { return plat_home_dir(); }
const char *os_temp_dir(void)  { return plat_tmp_dir(); }
long        os_rss_bytes(void){ return plat_rss_bytes(); }
unsigned long long os_now_ns(void)     { return (unsigned long long)plat_now_ns(); }
unsigned long long os_realtime_ns(void){ return (unsigned long long)plat_realtime_ns(); }

char os_path_sep(void) {
#if defined(_WIN32)
    return '\\';
#else
    return '/';
#endif
}

const char *os_describe(void) {
    static char buf[64];
    snprintf(buf, sizeof(buf), "%s %s", plat_name(), plat_arch());
    return buf;
}

const char *os_shell(void) {
#if defined(_WIN32)
    return "cmd.exe";
#else
    return "/bin/sh";
#endif
}

int os_run(const char *cmd) {
    if (!cmd) return -1;
#if defined(_WIN32)
    char buf[4096];
    snprintf(buf, sizeof(buf), "cmd.exe /C %s", cmd);
    return system(buf);
#else
    int rc = system(cmd);
    if (rc < 0) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
#endif
}

int os_capture(const char *cmd, char *out, size_t cap) {
    if (!cmd || !out || cap == 0) return -1;
    FILE *f = FW_POPEN(cmd, "r");
    if (!f) return -1;
    size_t w = 0;
    while (w < cap - 1) {
        int c = fgetc(f);
        if (c == EOF) break;
        out[w++] = (char)c;
    }
    out[w] = '\0';
    int rc = FW_PCLOSE(f);
    return rc == 0 ? (int)w : -1;
}

int os_cpu_count(void) {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

void os_sleep_ms(unsigned ms) {
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

const char *os_env(const char *name) {
    return name ? getenv(name) : NULL;
}

int os_open_url(const char *url) {
    if (!url) return -1;
    char cmd[1024];
#if defined(_WIN32)
    snprintf(cmd, sizeof(cmd), "start \"\" \"%s\"", url);
#elif defined(__APPLE__)
    snprintf(cmd, sizeof(cmd), "open '%s'", url);
#else
    snprintf(cmd, sizeof(cmd), "xdg-open '%s' >/dev/null 2>&1 &", url);
#endif
    return os_run(cmd);
}

int os_list_shells(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    out[0] = '\0';
    size_t w = 0;
#if defined(_WIN32)
    const char *cands[] = { "cmd.exe", "powershell.exe", "pwsh.exe", NULL };
#else
    const char *cands[] = { "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
                            "/bin/ksh", "/bin/fish", "/system/bin/sh", NULL };
#endif
    for (size_t i = 0; cands[i]; i++) {
        if (plat_file_exists(cands[i])) {
            int n = snprintf(out + w, cap - w, "%s\n", cands[i]);
            if (n < 0) break;
            w += (size_t)n;
        }
    }
    return (int)w;
}

void os_print_banner(void) {
    printf("========== OS hooks banner ==========\n");
    printf("  os:          %s\n", os_name());
    printf("  arch:        %s\n", os_arch());
    printf("  describe:    %s\n", os_describe());
    printf("  path sep:    '%c'\n", os_path_sep());
    printf("  shell:       %s\n", os_shell());
    printf("  cpus:        %d\n", os_cpu_count());
    printf("  home:        %s\n", os_home_dir());
    printf("  temp:        %s\n", os_temp_dir());
    printf("  rss:         %ld bytes\n", os_rss_bytes());
    printf("  now_ns:      %llu\n", os_now_ns());
    printf("  realtime_ns: %llu\n", os_realtime_ns());

    char shells[512];
    if (os_list_shells(shells, sizeof(shells)) > 0) {
        printf("  shells present:\n");
        printf("    %s", shells);
    } else {
        printf("  shells present: none detected\n");
    }

    const char *path = os_env("PATH");
    printf("  PATH:        %s\n", path ? path : "(unset)");
    printf("  writable dirs:\n");
    printf("    /tmp:        %s\n", os_writable_dir("/tmp") ? "yes" : "no");
    printf("    /var/tmp:    %s\n", os_writable_dir("/var/tmp") ? "yes" : "no");
    printf("    $HOME:       %s\n", os_writable_dir(os_home_dir()) ? "yes" : "no");

    const char *best = os_best_tmp_dir();
    printf("  best tmp:    %s\n", best ? best : "(none found)");

    char tempfile[1024];
    if (os_make_temp(tempfile, sizeof(tempfile), ".txt") == 0)
        printf("  temp path:   %s\n", tempfile);
    else
        printf("  temp path:   (unavailable)\n");
    printf("=====================================\n");
}

/* filesystem writability */

/** Probe by trying to create a file. Never crashes. */
int os_writable_dir(const char *path) {
    if (!path || !*path) return 0;
    char probe[1024];
    int n = snprintf(probe, sizeof(probe), "%s%c.flywheel_probe_%u",
                     path, os_path_sep(), (unsigned)FW_GETPID());
    if (n < 0 || (size_t)n >= sizeof(probe)) return 0;
    FILE *f = fopen(probe, "w");
    if (!f) return 0;
    fputc('x', f);
    fclose(f);
    remove(probe);
    return 1;
}

/** Cache: NULL until probed once. */
static const char *g_best_tmp = NULL;
static char        g_best_tmp_buf[1024];

const char *os_best_tmp_dir(void) {
    if (g_best_tmp) return g_best_tmp;

    const char *candidates[8];
    int nc = 0;

    const char *e;
    if ((e = getenv("TMPDIR")) && *e) candidates[nc++] = e;
    if ((e = getenv("TEMP"))   && *e) candidates[nc++] = e;
    if ((e = getenv("TMP"))    && *e) candidates[nc++] = e;
    candidates[nc++] = "/tmp";
    candidates[nc++] = "/var/tmp";
#if defined(_WIN32)
    candidates[nc++] = "C:\\Windows\\Temp";
#endif

    char home_cache[1024];
    const char *home = plat_home_dir();
    if (home && *home) {
        snprintf(home_cache, sizeof(home_cache), "%s%c.cache%cflywheel",
                 home, os_path_sep(), os_path_sep());
        plat_mkdir_p(home_cache);
        candidates[nc++] = home_cache;
    }

    for (int i = 0; i < nc; i++) {
        if (candidates[i] && os_writable_dir(candidates[i])) {
            snprintf(g_best_tmp_buf, sizeof(g_best_tmp_buf), "%s", candidates[i]);
            g_best_tmp = g_best_tmp_buf;
            return g_best_tmp;
        }
    }
    return NULL;
}

int os_make_temp(char *out, size_t cap, const char *suffix) {
    if (!out || cap == 0) return -1;
    const char *dir = os_best_tmp_dir();
    if (!dir) return -1;
    if (!suffix) suffix = ".tmp";
    int n = snprintf(out, cap, "%s%cflywheel_%u_%llu%s",
                     dir, os_path_sep(),
                     (unsigned)FW_GETPID(),
                     (unsigned long long)plat_now_ns(),
                     suffix);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}
