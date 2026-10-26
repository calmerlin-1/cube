/** dns_upstream.c — upstream scoring, ranking, persistence. */

#include "dns_upstream.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/** Monotonic nanoseconds. */
uint64_t dns_now_ns(void);
uint64_t dns_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

dns_upstream_pool_t *dns_upstream_pool_new(void) {
    dns_upstream_pool_t *p = (dns_upstream_pool_t *)calloc(1, sizeof(*p));
    return p;
}

void dns_upstream_pool_free(dns_upstream_pool_t *p) {
    if (!p) return;
    free(p->items);
    free(p);
}

int dns_upstream_add(dns_upstream_pool_t *p, const char *addr, uint16_t port,
                     uint8_t proto, const char *doh_url) {
    if (!p || !addr) return -1;
    if (p->count == p->capacity) {
        size_t nc = p->capacity ? p->capacity * 2 : 16;
        dns_upstream_t *ni = (dns_upstream_t *)realloc(p->items, nc * sizeof(*ni));
        if (!ni) return -1;
        memset(ni + p->capacity, 0, (nc - p->capacity) * sizeof(*ni));
        p->items = ni;
        p->capacity = nc;
    }
    dns_upstream_t *u = &p->items[p->count];
    memset(u, 0, sizeof(*u));
    snprintf(u->addr, sizeof(u->addr), "%s", addr);
    u->port = port;
    u->proto = proto;
    if (doh_url) snprintf(u->doh_url, sizeof(u->doh_url), "%s", doh_url);

    /* Untried upstreams get UINT64_MAX/2 so they sort LAST, not first.
     * Measured upstreams (UDP that actually works) sort by real latency.
     * DoH/DoT therefore become fallbacks — used only when UDP fails. */
    u->score = UINT64_MAX / 2;
    u->latency_ema_ns = 0;
    u->latency_min_ns = UINT64_MAX;
    p->count++;
    return 0;
}

/** Recompute score from health fields. Lower is better. */
static void rescore(dns_upstream_t *u) {
    uint64_t base = u->latency_ema_ns;
    if (base == 0) base = 100ull * 1000000ull;
    /* failure inflation: 10× per recent failure, compounding logarithmically */
    uint64_t fail_mult = 1 + u->consecutive_failures * 10;
    /* success dividend: divide by 1 + successes/1000 (mild bonus) */
    uint64_t succ_div = 1 + u->queries_ok / 1000;
    u->score = (base * fail_mult) / succ_div;
}

void dns_upstream_record_ok(dns_upstream_pool_t *p, size_t idx, uint64_t latency_ns, uint8_t rcode) {
    if (!p || idx >= p->count) return;
    dns_upstream_t *u = &p->items[idx];
    u->queries_sent++;
    u->queries_ok++;
    u->last_rcode = rcode;
    u->latency_last_ns = latency_ns;
    /* EMA: 0.7 old + 0.3 new */
    if (u->latency_ema_ns == 0) u->latency_ema_ns = latency_ns;
    else u->latency_ema_ns = (7 * u->latency_ema_ns + 3 * latency_ns) / 10;
    if (latency_ns < u->latency_min_ns) u->latency_min_ns = latency_ns;
    if (latency_ns > u->latency_max_ns) u->latency_max_ns = latency_ns;
    u->last_success_ns = dns_now_ns();
    u->consecutive_failures = 0;
    u->down_until_ns = 0;
    rescore(u);
}

void dns_upstream_record_timeout(dns_upstream_pool_t *p, size_t idx) {
    if (!p || idx >= p->count) return;
    dns_upstream_t *u = &p->items[idx];
    u->queries_sent++;
    u->queries_timeout++;
    u->last_failure_ns = dns_now_ns();
    u->consecutive_failures++;
    if (u->consecutive_failures >= 5)
        u->down_until_ns = dns_now_ns() + 300ull * 1000000000ull;   /* 5 min */
    else if (u->consecutive_failures >= 3)
        u->down_until_ns = dns_now_ns() + 30ull * 1000000000ull;    /* 30 s */
    rescore(u);
}

void dns_upstream_record_failure(dns_upstream_pool_t *p, size_t idx, uint8_t rcode) {
    if (!p || idx >= p->count) return;
    dns_upstream_t *u = &p->items[idx];
    u->queries_sent++;
    u->queries_failed++;
    u->last_rcode = rcode;
    u->last_failure_ns = dns_now_ns();
    u->consecutive_failures++;
    rescore(u);
}

/** Sort indices by score ascending, skipping down-marked. */
static void insertion_sort_by_score(dns_upstream_pool_t *p, size_t *idx, size_t n) {
    for (size_t i = 1; i < n; i++) {
        size_t key = idx[i];
        uint64_t ks = p->items[key].score;
        size_t j = i;
        while (j > 0 && p->items[idx[j-1]].score > ks) {
            idx[j] = idx[j-1];
            j--;
        }
        idx[j] = key;
    }
}

size_t dns_upstream_top(dns_upstream_pool_t *p, size_t *out, size_t n) {
    if (!p || p->count == 0 || !out) return 0;

    uint64_t now = dns_now_ns();
    size_t healthy = 0;
    size_t idx_all[256];

    for (size_t i = 0; i < p->count && healthy < 256; i++) {
        dns_upstream_t *u = &p->items[i];
        if (u->down_until_ns && u->down_until_ns > now) continue;
        idx_all[healthy++] = i;
    }
    /* if all are down, use all anyway */
    if (healthy == 0) {
        for (size_t i = 0; i < p->count && i < 256; i++) idx_all[healthy++] = i;
    }

    insertion_sort_by_score(p, idx_all, healthy);

    size_t w = 0;
    for (size_t i = 0; i < healthy && w < n; i++) out[w++] = idx_all[i];
    return w;
}

int dns_upstream_find(dns_upstream_pool_t *p, const char *addr, uint16_t port, uint8_t proto) {
    if (!p || !addr) return -1;
    for (size_t i = 0; i < p->count; i++) {
        dns_upstream_t *u = &p->items[i];
        if (u->port == port && u->proto == proto && strcmp(u->addr, addr) == 0) return (int)i;
    }
    return -1;
}

void dns_upstream_reset_score(dns_upstream_pool_t *p, size_t idx) {
    if (!p || idx >= p->count) return;
    dns_upstream_t *u = &p->items[idx];
    u->score = 100ull * 1000000ull;
    u->latency_ema_ns = 100ull * 1000000ull;
    u->consecutive_failures = 0;
    u->down_until_ns = 0;
}

uint64_t dns_upstream_score(dns_upstream_pool_t *p, size_t idx) {
    if (!p || idx >= p->count) return UINT64_MAX;
    return p->items[idx].score;
}

int dns_upstream_save(dns_upstream_pool_t *p, const char *path) {
    if (!p || !path) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    for (size_t i = 0; i < p->count; i++) {
        dns_upstream_t *u = &p->items[i];
        fprintf(f, "%s %u %u %llu %llu %llu %u %llu\n",
                u->addr, u->port, u->proto,
                (unsigned long long)u->latency_ema_ns,
                (unsigned long long)u->queries_ok,
                (unsigned long long)u->queries_failed,
                (unsigned)u->consecutive_failures,
                (unsigned long long)u->score);
    }
    fclose(f);
    return 0;
}

int dns_upstream_load(dns_upstream_pool_t *p, const char *path) {
    if (!p || !path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char addr[128];
    unsigned port, proto, consec;
    unsigned long long ema, ok, fail, score;
    int loaded = 0;
    while (fscanf(f, "%127s %u %u %llu %llu %llu %u %llu\n",
                  addr, &port, &proto,
                  &ema, &ok, &fail, &consec, &score) == 8) {
        /* DNS-8: fscanf %u / %llu on "-1" yields UINT_MAX / ULLONG_MAX.
         * Reject nonsense; skip the line without mutating the pool. */
        if (port == 0 || port > 65535) continue;
        if (proto > 3) continue;
        if (consec > 1000000) continue;
        for (size_t i = 0; i < p->count; i++) {
            dns_upstream_t *u = &p->items[i];
            if (strcmp(u->addr, addr) == 0 && u->port == port && u->proto == proto) {
                u->latency_ema_ns = ema;
                u->queries_ok = ok;
                u->queries_failed = fail;
                u->consecutive_failures = consec;
                u->score = score;
                loaded++;
                break;
            }
        }
    }
    fclose(f);
    return loaded;
}
