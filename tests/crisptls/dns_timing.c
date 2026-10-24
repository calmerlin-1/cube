/** dns_timing.c — measure resolver + cache behavior end-to-end. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dns.h"

static double ms_since(struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000.0
         + (t1.tv_nsec - t0->tv_nsec) / 1e6;
}

static void one(const char *host, int N) {
    printf("════ %s  (%d iterations) ════\n", host, N);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    dns_resolver_t *r = dns_resolver_new_default();
    printf("  resolver_new_default   %8.2f ms\n", ms_since(&t0));
    if (!r) { printf("  FAIL: no resolver\n\n"); return; }

    double total = 0, min = 1e9, max = 0;
    for (int i = 0; i < N; i++) {
        dns_answer_t ans; memset(&ans, 0, sizeof ans);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = dns_resolve_dual(r, host, &ans);
        double dt = ms_since(&t0);
        printf("  resolve #%-2d            %8.2f ms  rc=%d  count=%zu\n",
               i + 1, dt, rc, ans.count);
        total += dt;
        if (dt < min) min = dt;
        if (dt > max) max = dt;
        dns_answer_free(&ans);
    }
    printf("  ─────────────────────────────────────────────\n");
    printf("  avg %8.2f ms   min %8.2f ms   max %8.2f ms\n",
           total / N, min, max);

    dns_stats_t st; memset(&st, 0, sizeof st);
    dns_stats(r, &st);
    printf("  stats: cached=%llu  udp=%llu  failed=%llu  evictions=%llu  entries=%zu\n",
           (unsigned long long)st.queries_cached,
           (unsigned long long)st.queries_udp,
           (unsigned long long)st.queries_failed,
           (unsigned long long)st.cache_evictions,
           st.cache_entries);
    dns_resolver_free(r);
    printf("\n");
}

int main(int argc, char **argv) {
    int N = argc > 1 ? atoi(argv[1]) : 5;
    if (N < 1) N = 5;
    one("example.com", N);
    one("google.com", N);
    one("cloudflare.com", N);
    one("github.com", N);
    return 0;
}
