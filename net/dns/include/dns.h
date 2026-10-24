/** dns.h — public resolver API. */

#ifndef CUBE_DNS_H
#define CUBE_DNS_H

#include "dns_types.h"

/** Error codes */
#define DNS_OK               0
#define DNS_ERR_ARGS        -1
#define DNS_ERR_NOMEM       -2
#define DNS_ERR_WIRE        -3   /* malformed packet */
#define DNS_ERR_TIMEOUT     -4
#define DNS_ERR_NETWORK     -5
#define DNS_ERR_RCODE       -6   /* server returned non-zero rcode */
#define DNS_ERR_NXDOMAIN    -7
#define DNS_ERR_TRUNCATED   -8
#define DNS_ERR_CACHE_MISS  -9
#define DNS_ERR_NO_UPSTREAM -10
#define DNS_ERR_TOO_LARGE   -11
#define DNS_ERR_COMPRESSION -12  /* bad compression pointer */
#define DNS_ERR_LOOP        -13  /* compression pointer loop */
#define DNS_ERR_NO_RECORDS  -14  /* DNS OK but zero A/AAAA returned */

/** Flags for dns_resolve */
#define DNS_F_NO_CACHE   (1u << 0)
#define DNS_F_NO_RETRY   (1u << 1)
#define DNS_F_TCP_ONLY   (1u << 2)
#define DNS_F_UDP_ONLY   (1u << 3)
#define DNS_F_DOH_ONLY   (1u << 4)
#define DNS_F_DOT_ONLY   (1u << 5)
#define DNS_F_DNSSEC     (1u << 6)   /* request DNSSEC records (DO bit) */
#define DNS_F_NO_RECURSE (1u << 7)   /* unset RD */

/** Transport preference */
typedef enum {
    DNS_TRANSPORT_AUTO = 0,   /* UDP, fallback TCP; DoH/DoT if configured */
    DNS_TRANSPORT_UDP,
    DNS_TRANSPORT_TCP,
    DNS_TRANSPORT_DOT,
    DNS_TRANSPORT_DOH,
} dns_transport_t;

/** Resolver config */
typedef struct {
    const char *upstream_primary;    /* "8.8.8.8" or "dns.google" */
    const char *upstream_fallback;   /* used if primary fails */
    const char *doh_url;             /* e.g. "https://cloudflare-dns.com/dns-query" */
    uint16_t    doh_port;            /* default 443 */
    const char *dot_host;            /* e.g. "1.1.1.1" */
    uint16_t    dot_port;            /* default 853 */
    uint32_t    timeout_ms;          /* per attempt */
    uint32_t    retry_count;         /* 0 = one attempt */
    size_t      cache_max;           /* max entries; 0 disables cache */
    size_t      cache_max_bytes;     /* soft cap on cache memory */
    int         edns_udp_size;       /* advertised, 0 = no EDNS0 */
    int         require_dnssec;      /* request DO bit */
    const char *persist_path;        /* score file; NULL disables persistence */
    const char *cache_path;          /* hostname cache file; NULL disables persistence */
    uint32_t    persist_every;       /* save every N queries; 0 = only on free */
} dns_config_t;

/** Resolver handle */
typedef struct dns_resolver dns_resolver_t;

/** Lifecycle */
dns_resolver_t *dns_resolver_new(const dns_config_t *cfg);
dns_resolver_t *dns_resolver_new_default(void);
void            dns_resolver_free(dns_resolver_t *r);

/** Load upstream servers from a conf file. Returns count loaded, -1 error. */
int  dns_resolver_load_conf(dns_resolver_t *r, const char *path);

/** Query */
int dns_resolve(dns_resolver_t *r,
                const char *name,
                uint16_t type,
                uint32_t flags,
                dns_answer_t *out);

/** Convenience: one type per call */
int dns_resolve_a    (dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_aaaa (dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_mx   (dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_txt  (dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_ns   (dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_cname(dns_resolver_t *r, const char *name, dns_answer_t *out);
int dns_resolve_ptr  (dns_resolver_t *r, const char *ip,   dns_answer_t *out);
int dns_resolve_srv  (dns_resolver_t *r, const char *name, dns_answer_t *out);

/** Resolve A and AAAA together, merging answers. */
int dns_resolve_dual(dns_resolver_t *r, const char *name, dns_answer_t *out);

/** Reverse lookup for an IPv4 or IPv6 address. */
int dns_resolve_reverse(dns_resolver_t *r, const char *ip, dns_answer_t *out);

/** Answer set */
void dns_answer_free(dns_answer_t *a);

/** First matching record (by type), or NULL. */
const dns_record_t *dns_answer_first(const dns_answer_t *a, uint16_t type);

/** Persistence */
/** Set the path where upstream scores persist across runs.
 * Pass NULL to disable. Creates the file on resolver free. */
void dns_resolver_set_persist(dns_resolver_t *r, const char *path);

/** Force an immediate save of upstream scores (in addition to periodic saves). */
int  dns_resolver_save_scores(dns_resolver_t *r);

/** Cache control */
void dns_resolver_cache_clear(dns_resolver_t *r);
void dns_resolver_cache_set_max(dns_resolver_t *r, size_t max_entries);
void dns_resolver_set_cache_path(dns_resolver_t *r, const char *path);

/** Diagnostics */
typedef struct {
    uint64_t queries_total;
    uint64_t queries_cached;
    uint64_t queries_udp;
    uint64_t queries_tcp;
    uint64_t queries_dot;
    uint64_t queries_doh;
    uint64_t queries_failed;
    uint64_t cache_evictions;
    size_t   cache_entries;
    size_t   cache_bytes;
} dns_stats_t;

void dns_stats(dns_resolver_t *r, dns_stats_t *out);

/** Number of upstreams configured in the resolver. */
size_t dns_upstream_count(dns_resolver_t *r);

/** Utility */
const char *dns_type_name(uint16_t type);
const char *dns_rcode_name(uint8_t rcode);
const char *dns_err_name(int err);

/** Text output: printable form of a record (for logs/debug) */
int dns_record_format(const dns_record_t *rec, char *out, size_t cap);

#endif
