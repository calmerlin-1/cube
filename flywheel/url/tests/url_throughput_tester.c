/**
 * url_throughput_tester.c — URL parser throughput, fuzz, and stress.
 *
 * Sources URLs from files in tests/corpus/, not hardcoded arrays.
 * Modes: parse (default), mutate, fuzz, stress.
 *
 * Timing methodology:
 *   - iterations between two clock_gettime reads (clock cost amortized)
 *   - baseline empty-loop subtracted
 *   - volatile sink so calls aren't elided
 *   - 3 back-to-back repeats, report min/mean/max (throttle visibility)
 *   - read scaling_cur_freq from all cores before and after each category
 *
 * Crash/timeout:
 *   - SIGSEGV/SIGBUS/SIGABRT/SIGALRM handler prints input, phase, iteration
 *
 * usage:
 *   url_throughput_tester [-n N] [-r R] [-t MS] [-q] [-s SEED]
 *                         <file> [<file> ...]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <ctype.h>

#include "url_parser.h"
#include "color.h"

/* ---- cpu frequency ---- */

typedef struct {
    int    cores;
    long   cur_khz_max;
    long   cur_khz_min;
    double cur_khz_mean;
} cpu_freq_t;

static long read_int_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static void read_cpu_freq(cpu_freq_t *out) {
    memset(out, 0, sizeof(*out));
    out->cur_khz_max = -1;
    out->cur_khz_min = -1;
    long sum = 0;
    int n = 0;
    for (int cpu = 0; cpu < 64; cpu++) {
        char path[256];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
        long khz = read_int_file(path);
        if (khz <= 0) continue;
        if (out->cur_khz_max < 0 || khz > out->cur_khz_max) out->cur_khz_max = khz;
        if (out->cur_khz_min < 0 || khz < out->cur_khz_min) out->cur_khz_min = khz;
        sum += khz;
        n++;
    }
    out->cores = n;
    out->cur_khz_mean = n ? (double)sum / (double)n : 0;
}

/* ---- timing ---- */

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static volatile size_t g_sink = 0;

/* ---- crash / timeout ---- */

static volatile sig_atomic_t g_timeout_hit  = 0;
static const char           *g_cur_input    = NULL;
static const char           *g_cur_category = "?";
static const char           *g_cur_phase    = "?";
static size_t                g_cur_iter     = 0;
static size_t                g_cur_total    = 0;
static int                   g_cur_repeat   = 0;
static int                   g_cur_total_r  = 0;

static void print_input_dump(const char *s) {
    if (!s) { printf("(null)\n"); return; }
    printf("\"");
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p >= 0x20 && *p < 0x7f) putchar(*p);
        else printf("\\x%02x", *p);
    }
    printf("\"\n");
}

static void on_signal(int sig) {
    const char *name = sig == SIGSEGV ? "SIGSEGV"
                     : sig == SIGBUS  ? "SIGBUS"
                     : sig == SIGABRT ? "SIGABRT"
                     : sig == SIGALRM ? "SIGALRM (timeout)"
                     : "signal";
    fprintf(stderr, "\n%sCRASH%s  %s\n", col_red(), col_reset(), name);
    fprintf(stderr, "  category: %s\n", g_cur_category);
    fprintf(stderr, "  phase:    %s\n", g_cur_phase);
    fprintf(stderr, "  iter:     %zu / %zu   (repeat %d/%d)\n",
            g_cur_iter, g_cur_total, g_cur_repeat, g_cur_total_r);
    fprintf(stderr, "  input:    ");
    print_input_dump(g_cur_input);
    if (sig == SIGALRM) { g_timeout_hit = 1; return; }
    _exit(1);
}

/* ---- corpus ---- */

typedef struct {
    char  **lines;
    size_t *lens;
    size_t  n;
    size_t  cap;
    char   *buf;
    size_t  buf_len;
} corpus_t;

static void corpus_free(corpus_t *c) {
    if (!c) return;
    free(c->lines);
    free(c->lens);
    free(c->buf);
    memset(c, 0, sizeof(*c));
}

static int corpus_load(corpus_t *c, const char *path) {
    memset(c, 0, sizeof(*c));
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    c->buf = malloc((size_t)sz + 1);
    if (!c->buf) { fclose(f); return -1; }
    size_t got = fread(c->buf, 1, (size_t)sz, f);
    fclose(f);
    c->buf[got] = 0;
    c->buf_len = got;

    size_t cap = 64;
    c->lines = malloc(cap * sizeof(char *));
    c->lens  = malloc(cap * sizeof(size_t));
    if (!c->lines || !c->lens) return -1;
    c->cap = cap;

    char *p = c->buf;
    char *end = c->buf + got;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (len > 0 && p[len - 1] == '\r') len--;
        if (len > 0 && p[0] != '#') {
            if (c->n >= c->cap) {
                c->cap *= 2;
                char **nl2 = realloc(c->lines, c->cap * sizeof(char *));
                size_t *ln2 = realloc(c->lens, c->cap * sizeof(size_t));
                if (!nl2 || !ln2) return -1;
                c->lines = nl2;
                c->lens  = ln2;
            }
            if (nl) *nl = 0;
            if (len > 0 && p[len - 1] == '\r') p[len - 1] = 0;
            c->lens[c->n] = strlen(p);
            c->lines[c->n++] = p;
        }
        p = nl ? nl + 1 : end;
    }
    return 0;
}

/* ---- mutation engine ---- */

static uint64_t g_rng = 0xC0FFEEu;

static inline uint32_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)g_rng;
}

static size_t mutate(const char *src, size_t src_len, char *dst, size_t cap) {
    if (src_len == 0 || cap < 2) {
        dst[0] = (char)(rnd() & 0xff);
        return 1;
    }
    if (src_len >= cap) src_len = cap - 1;
    memcpy(dst, src, src_len);
    int op = rnd() % 6;
    size_t len = src_len;

    switch (op) {
    case 0:
        if (len > 0) { size_t pos = rnd() % len; dst[pos] = (char)(rnd() & 0xff); }
        break;
    case 1:
        if (len + 1 < cap) {
            size_t pos = rnd() % (len + 1);
            memmove(dst + pos + 1, dst + pos, len - pos);
            dst[pos] = (char)(rnd() & 0xff);
            len++;
        }
        break;
    case 2:
        if (len > 1) {
            size_t pos = rnd() % len;
            memmove(dst + pos, dst + pos + 1, len - pos - 1);
            len--;
        }
        break;
    case 3:
        if (len > 1) {
            size_t a = rnd() % len, b = rnd() % len;
            char t = dst[a]; dst[a] = dst[b]; dst[b] = t;
        }
        break;
    case 4:
        if (len > 1) len = 1 + (rnd() % len);
        break;
    case 5:
        if (len > 2 && len * 2 < cap) {
            size_t a = rnd() % len;
            size_t seg = 1 + (rnd() % (len - a));
            if (a + seg + seg <= cap) {
                memmove(dst + a + seg + seg, dst + a + seg, len - (a + seg));
                memcpy(dst + a + seg, dst + a, seg);
                len += seg;
            }
        }
        break;
    }
    dst[len] = 0;
    return len;
}

/* ---- modes ---- */

typedef enum { MODE_PARSE, MODE_MUTATE, MODE_FUZZ, MODE_STRESS } run_mode_t;

static uint64_t run_once(const corpus_t *c, run_mode_t mode, size_t iters,
                         char *scratch, size_t scratch_cap)
{
    uint64_t t0 = now_ns();
    if (mode == MODE_FUZZ) {
        for (size_t i = 0; i < iters; i++) {
            size_t n = 1 + (rnd() % 256);
            if (n >= scratch_cap) n = scratch_cap - 1;
            for (size_t k = 0; k < n; k++) scratch[k] = (char)(rnd() & 0xff);
            scratch[n] = 0;
            g_cur_input = scratch;
            g_cur_iter = i;
            g_cur_total = iters;
            url_view v;
            url_err e = url_parse(scratch, n, &v);
            g_sink += (e == URL_OK) ? v.path_len : 1;
        }
    } else if (mode == MODE_MUTATE) {
        for (size_t i = 0; i < iters; i++) {
            const char *src = c->lines[i % c->n];
            size_t mlen = mutate(src, strlen(src), scratch, scratch_cap);
            g_cur_input = scratch;
            g_cur_iter = i;
            g_cur_total = iters;
            url_view v;
            url_err e = url_parse(scratch, mlen, &v);
            g_sink += (e == URL_OK) ? v.path_len : 1;
        }
    } else if (mode == MODE_STRESS) {
        for (size_t i = 0; i < iters; i++) {
            const char *src = c->lines[i % c->n];
            size_t slen = strlen(src);
            if (slen >= scratch_cap) slen = scratch_cap - 1;
            memcpy(scratch, src, slen); scratch[slen] = 0;
            int gens = 1 + (int)(rnd() % 8);
            for (int g = 0; g < gens; g++) {
                char tmp[4096];
                size_t mlen = mutate(scratch, strlen(scratch), tmp, sizeof(tmp));
                memcpy(scratch, tmp, mlen); scratch[mlen] = 0;
            }
            g_cur_input = scratch;
            g_cur_iter = i;
            g_cur_total = iters;
            url_view v;
            url_err e = url_parse(scratch, strlen(scratch), &v);
            g_sink += (e == URL_OK) ? v.path_len : 1;
        }
    } else {
        for (size_t i = 0; i < iters; i++) {
            size_t idx = i % c->n;
            const char *u = c->lines[idx];
            size_t n = c->lens[idx];
            g_cur_input = u;
            g_cur_iter = i;
            g_cur_total = iters;
            url_view v;
            url_err e = url_parse(u, n, &v);
            g_sink += (e == URL_OK) ? v.path_len : 1;
        }
    }
    return now_ns() - t0;
}

static uint64_t run_baseline(const corpus_t *c, run_mode_t mode, size_t iters,
                             char *scratch, size_t scratch_cap)
{
    (void)scratch; (void)scratch_cap;
    uint64_t t0 = now_ns();
    if (mode == MODE_FUZZ) {
        for (size_t i = 0; i < iters; i++) g_sink += (rnd() & 0xff);
    } else {
        for (size_t i = 0; i < iters; i++) {
            const char *u = c->lines[i % c->n];
            g_sink += (size_t)(unsigned char)u[0];
        }
    }
    return now_ns() - t0;
}

static size_t auto_tune(const corpus_t *c, run_mode_t mode, uint64_t target_ms,
                        char *scratch, size_t scratch_cap)
{
    size_t n = 1000;
    for (;;) {
        uint64_t el = run_once(c, mode, n, scratch, scratch_cap);
        if (el >= target_ms * 1000000ull || n >= 10000000ull) return n;
        if (el > 0) n = n * (target_ms * 1000000ull) / el + 1;
        else n *= 10;
        if (n > 10000000ull) n = 10000000ull;
    }
}

/* ---- report ---- */

static uint64_t u64_min(const uint64_t *a, int n) { uint64_t m = a[0]; for (int i=1;i<n;i++) if (a[i]<m) m=a[i]; return m; }
static uint64_t u64_max(const uint64_t *a, int n) { uint64_t m = a[0]; for (int i=1;i<n;i++) if (a[i]>m) m=a[i]; return m; }
static uint64_t u64_mean(const uint64_t *a, int n) { uint64_t s=0; for (int i=0;i<n;i++) s+=a[i]; return s/(uint64_t)n; }

static const char *short_name(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

int main(int argc, char **argv) {
    size_t iters = 0;
    int    repeats = 3;
    int    timeout_ms = 5000;
    int    quiet = 0;
    run_mode_t mode = MODE_PARSE;
    const char *files[64];
    int nfiles = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-n") && i+1 < argc) iters = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-r") && i+1 < argc) repeats = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i+1 < argc) timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-q")) quiet = 1;
        else if (!strcmp(argv[i], "-s") && i+1 < argc) g_rng = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--mutate")) mode = MODE_MUTATE;
        else if (!strcmp(argv[i], "--fuzz"))   mode = MODE_FUZZ;
        else if (!strcmp(argv[i], "--stress")) mode = MODE_STRESS;
        else if (nfiles < 64) files[nfiles++] = argv[i];
        else { fprintf(stderr, "too many files\n"); return 2; }
    }

    if (mode != MODE_FUZZ && nfiles == 0) {
        fprintf(stderr,
            "usage: %s [-n N] [-r R] [-t MS] [-q] [-s SEED]\n"
            "           <file> [<file> ...]\n",
            argv[0]);
        return 2;
    }

    signal(SIGSEGV, on_signal);
    signal(SIGBUS,  on_signal);
    signal(SIGABRT, on_signal);
    signal(SIGALRM, on_signal);

    col_enable();

    const char *mode_name =
        mode == MODE_PARSE  ? "parse"  :
        mode == MODE_MUTATE ? "mutate" :
        mode == MODE_FUZZ   ? "fuzz"   : "stress";

    /* pin to cpu7 (big core on big.LITTLE). best-effort. */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(7, &set);
    int pinned = (sched_setaffinity(0, sizeof(set), &set) == 0);

    /* header */
    cpu_freq_t f0;
    read_cpu_freq(&f0);
    printf("%surl throughput%s  %s%s%s  ", col_bold(), col_reset(),
           col_dim(), mode_name, col_reset());
    if (f0.cores)
        printf("%s%d cores · %.0f MHz%s", col_dim(), f0.cores,
               f0.cur_khz_mean / 1000.0, col_reset());
    else
        printf("%sno freq available%s", col_dim(), col_reset());
    printf("\n");
    printf("  %s%d repeats · %d ms timeout · %s · %s%s\n",
           col_dim(), repeats, timeout_ms,
           iters ? "fixed iters" : "auto ~300ms",
           pinned ? "pinned cpu7" : "free scheduler",
           col_reset());
    printf("\n");

    if (quiet) {
        printf("%s%-18s %8s %8s %7s%s\n",
               col_dim(), "corpus", "ns/op", "M/s", "MHz",
               col_reset());
        printf("%s%-18s %8s %8s %7s%s\n",
               col_dim(), "------", "-----", "---", "---",
               col_reset());
    }

    char scratch[8192];
    size_t scratch_cap = sizeof(scratch);

    int categories_run = 0;
    uint64_t total_urls = 0;
    uint64_t total_ns = 0;

    int iters_arr = nfiles > 0 ? nfiles : 1;
    for (int fi = 0; fi < iters_arr; fi++) {
        const char *fname = (nfiles > 0) ? files[fi] : "<fuzz>";
        corpus_t c;
        memset(&c, 0, sizeof(c));

        if (mode != MODE_FUZZ) {
            if (corpus_load(&c, fname) != 0) {
                printf("%s%s%s  %sFAILED to load%s\n",
                       col_red(), fname, col_reset(),
                       col_red(), col_reset());
                continue;
            }
            if (c.n == 0) {
                printf("%s%s%s  %sempty%s\n",
                       col_yellow(), fname, col_reset(),
                       col_dim(), col_reset());
                corpus_free(&c);
                continue;
            }
        }

        g_cur_category = fname;
        cpu_freq_t f_start;
        read_cpu_freq(&f_start);

        size_t use_iters = iters ? iters
                                 : auto_tune(&c, mode, 300, scratch, scratch_cap);

        uint64_t samples[32];
        int nsamples = 0;
        int timed_out = 0;

        for (int r = 0; r < repeats && r < 32; r++) {
            g_cur_repeat = r + 1;
            g_cur_total_r = repeats;
            g_cur_phase = mode_name;
            g_cur_total = use_iters;

            alarm((unsigned)((timeout_ms + 999) / 1000));
            g_timeout_hit = 0;
            uint64_t el = run_once(&c, mode, use_iters, scratch, scratch_cap);
            alarm(0);
            if (g_timeout_hit) { timed_out = 1; break; }

            uint64_t base_ns = run_baseline(&c, mode, use_iters, scratch, scratch_cap);
            uint64_t per_op = el / use_iters;
            uint64_t base_per_op = base_ns / use_iters;
            uint64_t adj = per_op > base_per_op ? per_op - base_per_op : per_op;
            samples[nsamples++] = adj;
        }

        cpu_freq_t f_end;
        read_cpu_freq(&f_end);

        if (timed_out) {
            printf("%s%s%s  TIMEOUT after %d ms\n",
                   col_red(), short_name(fname), col_reset(), timeout_ms);
            corpus_free(&c);
            continue;
        }
        if (nsamples == 0) { corpus_free(&c); continue; }

        uint64_t mn = u64_min(samples, nsamples);
        uint64_t md = u64_mean(samples, nsamples);
        uint64_t mx = u64_max(samples, nsamples);

        double mops_min = mn ? 1000.0 / (double)mn : 0.0;
        double mhz_start = f_start.cur_khz_mean / 1000.0;
        double mhz_end   = f_end.cur_khz_mean / 1000.0;

        const char *speed_col = mops_min > 2.0 ? col_green()
                              : mops_min > 0.5 ? col_yellow()
                              : col_red();

        if (quiet) {
            printf("%-18s %s%8llu%s %s%8.2f%s %7.0f\n",
                   short_name(fname),
                   col_dim(), (unsigned long long)mn, col_reset(),
                   speed_col, mops_min, col_reset(),
                   (mhz_start + mhz_end) / 2.0);
        } else {
            printf("%s%s%s  %s%zu urls · %zu iters × %d%s\n",
                   col_cyan(), short_name(fname), col_reset(),
                   col_dim(), mode == MODE_FUZZ ? (size_t)0 : c.n,
                   use_iters, nsamples, col_reset());
            printf("  %smin%s    %8llu ns/op   %s%7.2f M/s%s\n",
                   col_dim(), col_reset(), (unsigned long long)mn,
                   speed_col, mops_min, col_reset());
            printf("  %smean%s   %8llu ns/op\n",
                   col_dim(), col_reset(), (unsigned long long)md);
            printf("  %smax%s    %8llu ns/op\n",
                   col_dim(), col_reset(), (unsigned long long)mx);
            printf("  %sclock%s  %.0f → %.0f MHz\n",
                   col_dim(), col_reset(), mhz_start, mhz_end);
            printf("\n");
        }

        categories_run++;
        total_urls += use_iters * (uint64_t)nsamples;
        total_ns += mn * use_iters * (uint64_t)nsamples;

        corpus_free(&c);
    }

    if (categories_run > 0) {
        cpu_freq_t f1;
        read_cpu_freq(&f1);
        double overall = total_ns ? (double)total_urls / (double)total_ns * 1000.0 : 0.0;
        printf("%s──────────────────────────────────────────────%s\n",
               col_dim(), col_reset());
        printf("%saggregate%s  %s%.2f M URLs/s%s  %s· %d %s · %llu URLs · %.2f s · %.0f MHz%s\n",
               col_dim(), col_reset(),
               col_green(), overall, col_reset(),
               col_dim(), categories_run,
               categories_run == 1 ? "corpus" : "corpora",
               (unsigned long long)total_urls,
               (double)total_ns / 1e9,
               f1.cores ? f1.cur_khz_mean / 1000.0 : 0.0,
               col_reset());
    }
    (void)g_sink;
    return 0;
}
