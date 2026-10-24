/** dns_upstream.h — upstream server tracking and scoring. */

#ifndef FLYWHEEL_DNS_UPSTREAM_H
#define FLYWHEEL_DNS_UPSTREAM_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    UP_PROTO_UDP = 0,
    UP_PROTO_TCP,
    UP_PROTO_DOT,
    UP_PROTO_DOH,
} up_proto_t;

typedef struct {
    char      addr[128];       /* IP or hostname */
    uint16_t  port;
    uint8_t   proto;
    char      doh_url[256];    /* if proto == DoH */

    /* health */
    uint64_t  queries_sent;
    uint64_t  queries_ok;
    uint64_t  queries_timeout;
    uint64_t  queries_failed;
    uint64_t  latency_ema_ns;
    uint64_t  latency_last_ns;
    uint64_t  latency_min_ns;
    uint64_t  latency_max_ns;
    uint8_t   last_rcode;
    uint64_t  last_success_ns;
    uint64_t  last_failure_ns;
    uint32_t  consecutive_failures;

    /* derived */
    uint64_t  score;           /* lower is better */
    uint64_t  down_until_ns;   /* 0 = healthy */
    uint64_t  strikes;
} dns_upstream_t;

typedef struct {
    dns_upstream_t *items;
    size_t          count;
    size_t          capacity;
    size_t          next_rr;   /* round-robin cursor for ties */
} dns_upstream_pool_t;

dns_upstream_pool_t *dns_upstream_pool_new(void);
void dns_upstream_pool_free(dns_upstream_pool_t *p);

int dns_upstream_add(dns_upstream_pool_t *p, const char *addr, uint16_t port, uint8_t proto, const char *doh_url);

/** Record the outcome of one query against an upstream. */
void dns_upstream_record_ok(dns_upstream_pool_t *p, size_t idx, uint64_t latency_ns, uint8_t rcode);
void dns_upstream_record_timeout(dns_upstream_pool_t *p, size_t idx);
void dns_upstream_record_failure(dns_upstream_pool_t *p, size_t idx, uint8_t rcode);

/** Return the top-N healthy upstreams in score order.
 * Writes indices into `out`. Returns count written (may be < n). */
size_t dns_upstream_top(dns_upstream_pool_t *p, size_t *out, size_t n);

/** Save/load scores to a file for cross-run persistence. */
int dns_upstream_save(dns_upstream_pool_t *p, const char *path);
int dns_upstream_load(dns_upstream_pool_t *p, const char *path);

/** Find upstream by addr+port+proto. Returns index or -1. */
int dns_upstream_find(dns_upstream_pool_t *p, const char *addr, uint16_t port, uint8_t proto);

/** Reset one upstream's score to a fresh baseline. */
void dns_upstream_reset_score(dns_upstream_pool_t *p, size_t idx);

/** Return current score for an upstream. UINT64_MAX if not found. */
uint64_t dns_upstream_score(dns_upstream_pool_t *p, size_t idx);

/** Race N upstreams in parallel. Returns response bytes, 0 on timeout, -1 on error.
 * out_upstream_idx receives winning pool index. */
typedef struct {
    int      phases_run;     /* 1, 2, or 3 */
    uint32_t latecomers;     /* how many losers responded within grace */
} dns_race_stats_t;

int dns_race_query_staged(dns_upstream_pool_t *pool,
                          size_t *upstream_indices, size_t n,
                          const uint8_t *query, size_t qlen,
                          uint8_t *resp, size_t resp_cap,
                          uint32_t p1_ms, uint32_t p2_ms, uint32_t total_ms,
                          uint32_t grace_ms,
                          size_t *out_upstream_idx,
                          uint64_t *out_latency_ns,
                          dns_race_stats_t *out_stats);

int dns_race_query(dns_upstream_pool_t *pool,
                   size_t *upstream_indices, size_t n,
                   const uint8_t *query, size_t qlen,
                   uint8_t *resp, size_t resp_cap,
                   uint32_t window_ms, uint32_t total_ms,
                   size_t *out_upstream_idx,
                   uint64_t *out_latency_ns);

#endif
