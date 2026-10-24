/**
 * url_cache_tester.c — measure cache win on repeated URLs.
 *
 * Loads a corpus twice:
 *   1. url_parse        (uncached)
 *   2. url_cache_parse  (cached, warm after first pass)
 *
 * Prints ns/op, M/s, and hit/miss stats for both. The difference is the
 * cache win.
 *
 * usage: url_cache_tester [-n N] [-c SIZE] <file> [<file> ...]
 *
 *   -n N     iterations per run (default: auto-tune ~300ms)
 *   -c SIZE  cache size in entries (default: 256)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>

#include "url_parser.h"
#include "url_cache.h"
#include "color.h"

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static volatile size_t g_sink = 0;

typedef struct {
    char **lines;
    size_t *lens;
    size_t  n;
    char   *buf;
} corpus_t;

static int corpus_load(corpus_t *c, const char *path) {
    memset(c, 0, sizeof(*c));
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    c->buf = malloc((size_t)sz + 1);
    size_t got = fread(c->buf, 1, (size_t)sz, f);
    fclose(f);
    c->buf[got] = 0;

    size_t cap = 64;
    c->lines = malloc(cap * sizeof(char *));
    c->lens  = malloc(cap * sizeof(size_t));

    char *p = c->buf;
    char *end = c->buf + got;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (len > 0 && p[len-1] == '\r') len--;
        if (len > 0 && p[0] != '#') {
            if (c->n >= cap) {
                cap *= 2;
                c->lines = realloc(c->lines, cap * sizeof(char *));
                c->lens  = realloc(c->lens, cap * sizeof(size_t));
            }
            if (nl) *nl = 0;
            if (len > 0 && p[len-1] == '\r') p[len-1] = 0;
            c->lens[c->n] = strlen(p);
            c->lines[c->n++] = p;
        }
        p = nl ? nl + 1 : end;
    }
    return 0;
}

static void corpus_free(corpus_t *c) {
    free(c->lines);
    free(c->lens);
    free(c->buf);
}

static uint64_t run_uncached(const corpus_t *c, size_t iters) {
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < iters; i++) {
        size_t idx = i % c->n;
        url_view v;
        url_err e = url_parse(c->lines[idx], c->lens[idx], &v);
        g_sink += (e == URL_OK) ? v.path_len : 1;
    }
    return now_ns() - t0;
}

static uint64_t run_cached(const corpus_t *c, size_t iters,
                           url_cache_t *cache) {
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < iters; i++) {
        size_t idx = i % c->n;
        url_view v;
        url_err e = url_cache_parse(cache, c->lines[idx], c->lens[idx], &v);
        g_sink += (e == URL_OK) ? v.path_len : 1;
    }
    return now_ns() - t0;
}

int main(int argc, char **argv) {
    size_t iters = 0;
    size_t cache_size = 256;
    const char *files[16];
    int nfiles = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i+1 < argc) iters = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-c") && i+1 < argc) cache_size = strtoull(argv[++i], NULL, 10);
        else if (nfiles < 16) files[nfiles++] = argv[i];
        else { fprintf(stderr, "too many files\n"); return 2; }
    }

    if (nfiles == 0) {
        fprintf(stderr, "usage: %s [-n N] [-c SIZE] <file> [<file> ...]\n", argv[0]);
        return 2;
    }

    col_enable();

    /* pin to cpu7 */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(7, &set);
    sched_setaffinity(0, sizeof(set), &set);

    printf("%surl cache tester%s  %scache size %zu%s\n\n",
           col_bold(), col_reset(), col_dim(), cache_size, col_reset());

    for (int fi = 0; fi < nfiles; fi++) {
        corpus_t c;
        if (corpus_load(&c, files[fi]) != 0) {
            printf("%s%s%s  %scannot load%s\n",
                   col_red(), files[fi], col_reset(),
                   col_red(), col_reset());
            continue;
        }

        size_t use_iters = iters;
        if (!use_iters) {
            use_iters = 10000;
            for (;;) {
                uint64_t el = run_uncached(&c, use_iters);
                if (el >= 300 * 1000000ull) break;
                use_iters *= 2;
                if (use_iters > 10000000) break;
            }
        }

        /* uncached */
        uint64_t un = 0;
        for (int r = 0; r < 3; r++) {
            uint64_t t = run_uncached(&c, use_iters);
            if (r == 0 || t < un) un = t;
        }
        double un_ns = (double)un / use_iters;
        double un_mops = 1000.0 / un_ns;

        /* cached — fresh cache, but corpus repeats inside it, so it warms fast */
        url_cache_t *cache = url_cache_new(cache_size);
        uint64_t ca = 0;
        for (int r = 0; r < 3; r++) {
            url_cache_clear(cache);
            uint64_t t = run_cached(&c, use_iters, cache);
            if (r == 0 || t < ca) ca = t;
        }
        double ca_ns = (double)ca / use_iters;
        double ca_mops = 1000.0 / ca_ns;

        url_cache_stats_t st;
        url_cache_stats(cache, &st);

        /* unique URLs in corpus */
        size_t uniq = 0;
        for (size_t i = 0; i < c.n; i++) {
            int seen = 0;
            for (size_t j = 0; j < i; j++)
                if (c.lens[j] == c.lens[i] &&
                    memcmp(c.lines[j], c.lines[i], c.lens[i]) == 0) {
                    seen = 1; break;
                }
            if (!seen) uniq++;
        }

        const char *shortname = strrchr(files[fi], '/');
        shortname = shortname ? shortname + 1 : files[fi];

        printf("%s%s%s  %s%zu urls · %zu unique · %zu iters%s\n",
               col_cyan(), shortname, col_reset(),
               col_dim(), c.n, uniq, use_iters, col_reset());

        printf("  %suncached%s  %s%8.1f ns/op%s  %s%7.2f M/s%s\n",
               col_dim(), col_reset(),
               col_bold(), un_ns, col_reset(),
               col_yellow(), un_mops, col_reset());

        printf("  %scached%s    %s%8.1f ns/op%s  %s%7.2f M/s%s  %s%.1f× faster%s\n",
               col_dim(), col_reset(),
               col_bold(), ca_ns, col_reset(),
               col_green(), ca_mops, col_reset(),
               ca_ns > 0 ? col_green() : col_dim(),
               un_ns / ca_ns, col_reset());

        printf("  %shits %llu · misses %llu · evictions %llu · live %zu/%zu%s\n",
               col_dim(),
               (unsigned long long)st.hits,
               (unsigned long long)st.misses,
               (unsigned long long)st.evictions,
               st.entries, st.max_entries,
               col_reset());

        printf("\n");

        url_cache_free(cache);
        corpus_free(&c);
    }

    (void)g_sink;
    return 0;
}
