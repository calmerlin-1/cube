/** os_hooks.h — OS-dependent commands and hooks.
 * Use this to verify a C stub works on any platform.
 * Everything routes through here, not raw system calls. */

#ifndef FLYWHEEL_OS_HOOKS_H
#define FLYWHEEL_OS_HOOKS_H

#include <stddef.h>

/** Which OS? "android" | "linux" | "macos" | "windows" | "bsd" | "unknown". */
const char *os_name(void);

/** Which CPU arch? "aarch64" | "x86_64" | "armv7" | "i386" | "unknown". */
const char *os_arch(void);

/** Combined: "android aarch64", "linux x86_64", etc. */
const char *os_describe(void);

/** Path separator. '\\' on Windows, '/' everywhere else. */
char os_path_sep(void);

/** System shell path. "/bin/sh" on Unix, "cmd.exe" on Windows. */
const char *os_shell(void);

/** Run a shell command, wait, return exit code. -1 on error. */
int os_run(const char *cmd);

/** Run a shell command, capture stdout into `out`. Returns bytes written, or -1. */
int os_capture(const char *cmd, char *out, size_t cap);

/** Number of logical CPUs. Returns 1 if unknown. */
int os_cpu_count(void);

/** Sleep for N milliseconds. */
void os_sleep_ms(unsigned ms);

/** Read environment variable. NULL if unset. */
const char *os_env(const char *name);

/** Temp directory path. Not owned. */
const char *os_temp_dir(void);

/** Home directory. Not owned. */
const char *os_home_dir(void);
int os_writable_dir(const char *path);
const char *os_best_tmp_dir(void);
int os_make_temp(char *out, size_t cap, const char *suffix);

/** Open a URL/file in the system default app. 0 on success, -1 on error. */
int os_open_url(const char *url);

/** Peak/current RSS in bytes. -1 if unsupported. */
long os_rss_bytes(void);

/** Current monotonic time in nanoseconds. */
unsigned long long os_now_ns(void);

/** Wall-clock time in nanoseconds since epoch. */
unsigned long long os_realtime_ns(void);

/* ---- Per-OS verification hooks ----
 * These return strings that let you prove from C which OS you're on. */

/** List available shells on this platform, one per line. */
int os_list_shells(char *out, size_t cap);

/** Print a diagnostic banner describing this platform. */
void os_print_banner(void);

#endif
