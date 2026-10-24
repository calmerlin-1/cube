/* test_dns.c — full DNS test: offline logic, live queries, cache, fuzz, timing. */

#include "dns.h"
#include "dns_cache.h"
#include "dns_types.h"
#include "dns_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

static int passed = 0;
static int failed = 0;

static long page_size = 4096;

static long read_rss_bytes(void) {
    int fd = open("/proc/self/statm", O_RDONLY);
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    long size, resident;
    if (sscanf(buf, "%ld %ld", &size, &resident) != 2) return -1;
    return resident * page_size;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t rng_state = 0x123456789ABCDEFull;
static uint32_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 32);
}

static uint16_t rd16_off(const uint8_t *p, size_t o) {
    return (uint16_t)((p[o] << 8) | p[o + 1]);
}

static void check(int cond, const char *label) {
    if (cond) { passed++; printf("  PASS  %s\n", label); }
    else      { failed++; printf("  FAIL  %s\n", label); }
}

static void fuzz_parser(int N) {
    printf("=== FUZZ: parse_response with %d random packets ===\n", N);
    uint8_t pkt[512];
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; i++) {
        size_t len = 12 + (rng_next() % (sizeof(pkt) - 12));
        for (size_t j = 0; j < len; j++) pkt[j] = (uint8_t)rng_next();
        dns_answer_t out;
        (void)dns_wire_parse_response(pkt, len, 0x1234, NULL, 0, &out);
        dns_answer_free(&out);
    }
    uint64_t dt = now_ns() - t0;
    printf("  %d packets, %llu ns total, %llu ns/packet\n",
           N, (unsigned long long)dt, (unsigned long long)(dt / N));
    check(1, "no crash on random packets");
}

static void fuzz_query_build(int N) {
    printf("=== FUZZ: build_query with %d random names ===\n", N);
    uint8_t out[512];
    int errs = 0;
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; i++) {
        char name[128];
        size_t nlen = rng_next() % 120;
        for (size_t j = 0; j < nlen; j++) {
            uint8_t c = (uint8_t)(rng_next() & 0xFF);
            if (c < 0x20) c = (uint8_t)('a' + (c % 26));
            name[j] = (char)c;
        }
        name[nlen] = '\0';
        size_t qlen = dns_wire_build_query(0x1234, name, nlen, DNS_TYPE_A, DNS_CLASS_IN,
                                           0, 4096, out, sizeof(out));
        if (qlen == 0 && nlen > 0) errs++;
    }
    uint64_t dt = now_ns() - t0;
    printf("  %d names, %llu ns total, %llu ns/name, build errors=%d\n",
           N, (unsigned long long)dt, (unsigned long long)(dt / N), errs);
    check(1, "no crash on random names");
}

static void test_query_build(void) {
    printf("=== OFFLINE: query build roundtrip ===\n");
    uint8_t query[512];
    size_t qlen = dns_wire_build_query(0x1234, "example.com", 11,
                                       DNS_TYPE_A, DNS_CLASS_IN, 0, 4096,
                                       query, sizeof(query));
    check(qlen > 12, "build query for example.com");
    if (qlen > 12) {
        check(rd16_off(query, 0) == 0x1234, "query ID roundtrip");
        check(rd16_off(query, 4) == 1,      "qdcount=1");
    }
}

static void test_live_a(dns_resolver_t *r, const char *name, const char *label) {
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    long rss0 = read_rss_bytes();
    uint64_t t0 = now_ns();
    int rc = dns_resolve_a(r, name, &a);
    uint64_t dt = now_ns() - t0;
    long rss1 = read_rss_bytes();
    if (rc != DNS_OK) {
        failed++;
        printf("  FAIL  %-28s %s\n", label, dns_err_name(rc));
        return;
    }
    passed++;
    printf("  PASS  %-28s  %6llu us  rss %+5ld  records=%zu\n",
           label, (unsigned long long)(dt / 1000), rss1 - rss0, a.count);
    for (size_t i = 0; i < a.count && i < 8; i++) {
        char buf[256];
        dns_record_format(&a.records[i], buf, sizeof(buf));
        printf("          %s\n", buf);
    }
    dns_answer_free(&a);
}

static void test_live_aaaa(dns_resolver_t *r, const char *name, const char *label) {
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    uint64_t t0 = now_ns();
    int rc = dns_resolve_aaaa(r, name, &a);
    uint64_t dt = now_ns() - t0;
    if (rc != DNS_OK) { failed++; printf("  FAIL  %-28s %s\n", label, dns_err_name(rc)); return; }
    passed++;
    printf("  PASS  %-28s  %6llu us  records=%zu\n",
           label, (unsigned long long)(dt / 1000), a.count);
    for (size_t i = 0; i < a.count && i < 4; i++) {
        char buf[256];
        dns_record_format(&a.records[i], buf, sizeof(buf));
        printf("          %s\n", buf);
    }
    dns_answer_free(&a);
}

static void test_live_mx(dns_resolver_t *r, const char *name, const char *label) {
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    uint64_t t0 = now_ns();
    int rc = dns_resolve_mx(r, name, &a);
    uint64_t dt = now_ns() - t0;
    if (rc != DNS_OK) { failed++; printf("  FAIL  %-28s %s\n", label, dns_err_name(rc)); return; }
    passed++;
    printf("  PASS  %-28s  %6llu us  records=%zu\n",
           label, (unsigned long long)(dt / 1000), a.count);
    for (size_t i = 0; i < a.count && i < 4; i++) {
        char buf[256];
        dns_record_format(&a.records[i], buf, sizeof(buf));
        printf("          %s\n", buf);
    }
    dns_answer_free(&a);
}

static void test_live_txt(dns_resolver_t *r, const char *name, const char *label) {
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    uint64_t t0 = now_ns();
    int rc = dns_resolve_txt(r, name, &a);
    uint64_t dt = now_ns() - t0;
    if (rc != DNS_OK) { failed++; printf("  FAIL  %-28s %s\n", label, dns_err_name(rc)); return; }
    passed++;
    printf("  PASS  %-28s  %6llu us  records=%zu\n",
           label, (unsigned long long)(dt / 1000), a.count);
    for (size_t i = 0; i < a.count && i < 2; i++) {
        char buf[256];
        dns_record_format(&a.records[i], buf, sizeof(buf));
        printf("          %s\n", buf);
    }
    dns_answer_free(&a);
}

static void test_live_reverse(dns_resolver_t *r, const char *ip, const char *label) {
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    uint64_t t0 = now_ns();
    int rc = dns_resolve_reverse(r, ip, &a);
    uint64_t dt = now_ns() - t0;
    if (rc != DNS_OK) { failed++; printf("  FAIL  %-28s %s\n", label, dns_err_name(rc)); return; }
    passed++;
    printf("  PASS  %-28s  %6llu us  records=%zu\n",
           label, (unsigned long long)(dt / 1000), a.count);
    for (size_t i = 0; i < a.count && i < 2; i++) {
        char buf[256];
        dns_record_format(&a.records[i], buf, sizeof(buf));
        printf("          %s\n", buf);
    }
    dns_answer_free(&a);
}

static void test_cache_hit(dns_resolver_t *r) {
    printf("=== CACHE: hit speedup ===\n");
    dns_answer_t a1, a2;
    memset(&a1, 0, sizeof(a1));
    memset(&a2, 0, sizeof(a2));

    /* use a name not queried earlier, so the first is a true miss */
    const char *probe = "wikipedia.org";

    uint64_t t0 = now_ns();
    int rc1 = dns_resolve_a(r, probe, &a1);
    uint64_t dt1 = now_ns() - t0;

    uint64_t t1 = now_ns();
    int rc2 = dns_resolve_a(r, probe, &a2);
    uint64_t dt2 = now_ns() - t1;

    dns_answer_free(&a1);
    dns_answer_free(&a2);

    if (rc1 != DNS_OK || rc2 != DNS_OK) { failed++; printf("  FAIL  cache path\n"); return; }
    passed++;
    printf("  PASS  first query   %8llu ns\n", (unsigned long long)dt1);
    printf("  PASS  cached query  %8llu ns\n", (unsigned long long)dt2);
    if (dt2 > 0 && dt1 > 0) printf("  speedup: %.0fx\n", (double)dt1 / (double)dt2);
}

int main(int argc, char **argv) {
    int do_offline = 1, do_live = 1, do_fuzz = 1;
    int N = 2000;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--offline")) { do_live = 0; do_fuzz = 0; }
        else if (!strcmp(argv[i], "--live")) { do_offline = 0; do_fuzz = 0; }
        else if (!strcmp(argv[i], "--fuzz")) { do_offline = 0; do_live = 0; }
        else if (!strncmp(argv[i], "--n=", 4)) N = atoi(argv[i] + 4);
    }
    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0) page_size = ps;

    uint64_t t0 = now_ns();
    long rss0 = read_rss_bytes();

    printf("=== DNS test suite ===\n");
    printf("  page: %ld  rss: %ld  N: %d\n\n", page_size, rss0, N);

    if (do_offline) { test_query_build(); printf("\n"); }

    if (do_live) {
        printf("=== LIVE: real DNS queries ===\n");
        dns_resolver_t *r = dns_resolver_new_default();
        if (!r) { printf("  FAIL: could not create resolver\n"); return 1; }
        /* persist upstream scores across runs */
        mkdir("../cache", 0755);
        dns_resolver_set_persist(r, "../cache/upstream_scores.txt");
        dns_resolver_load_conf(r, "net/dns/data/resolvers.conf");

        test_live_a(r, "example.com", "example.com A");
        test_live_a(r, "cloudflare.com", "cloudflare.com A");
        test_live_a(r, "google.com", "google.com A");
        test_live_aaaa(r, "google.com", "google.com AAAA");
        test_live_mx(r, "gmail.com", "gmail.com MX");
        test_live_txt(r, "example.com", "example.com TXT");
        test_live_reverse(r, "8.8.8.8", "8.8.8.8 PTR");
        test_live_reverse(r, "1.1.1.1", "1.1.1.1 PTR");

        printf("\n");
        test_cache_hit(r);

        dns_stats_t st;
        dns_stats(r, &st);
        printf("\n=== resolver stats ===\n");
        printf("  queries_total:   %llu\n", (unsigned long long)st.queries_total);
        printf("  queries_cached:  %llu\n", (unsigned long long)st.queries_cached);
        printf("  queries_udp:     %llu\n", (unsigned long long)st.queries_udp);
        printf("  queries_failed:  %llu\n", (unsigned long long)st.queries_failed);
        printf("  cache_entries:   %zu\n", st.cache_entries);
        printf("  cache_bytes:     %zu\n", st.cache_bytes);

        dns_resolver_save_scores(r);
        printf("  persist file written: ../cache/upstream_scores.txt\n");
        dns_resolver_free(r);
        printf("\n");
    }

    if (do_fuzz) { fuzz_parser(N); fuzz_query_build(N); printf("\n"); }

    uint64_t dt = now_ns() - t0;
    long rss1 = read_rss_bytes();

    printf("=== SUMMARY ===\n");
    printf("  passed:      %d\n", passed);
    printf("  failed:      %d\n", failed);
    printf("  total time:  %.3f ms\n", (double)dt / 1e6);
    printf("  rss delta:   %+ld bytes\n", rss1 - rss0);
    return failed ? 1 : 0;
}
