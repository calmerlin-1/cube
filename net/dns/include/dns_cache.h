/** dns_cache.h — LRU cache with TTL honoring. */

#ifndef FLYWHEEL_DNS_CACHE_H
#define FLYWHEEL_DNS_CACHE_H

#include "dns_types.h"

typedef struct dns_cache dns_cache_t;

/** Create a cache with the given max entry count. */
dns_cache_t *dns_cache_new(size_t max_entries);

/** Free cache and all stored records. */
void dns_cache_free(dns_cache_t *c);

/** Empty the cache without destroying it. */
void dns_cache_clear(dns_cache_t *c);

/** Change max entries; evicts down to the new size if shrinking. */
void dns_cache_set_max(dns_cache_t *c, size_t max);

/** Lookup. Returns 0 on hit, negative on miss or expired. */
int dns_cache_get(dns_cache_t *c,
                  const char *name,
                  uint16_t type,
                  uint16_t cls,
                  dns_answer_t *out);

/** Insert or replace. TTL is derived from the minimum record TTL. */
void dns_cache_put(dns_cache_t *c,
                   const char *name,
                   uint16_t type,
                   uint16_t cls,
                   const dns_answer_t *answer,
                   uint32_t ttl_override);

/** Negative cache — NXDOMAIN / SERVFAIL with a short TTL. */
void dns_cache_put_negative(dns_cache_t *c,
                            const char *name,
                            uint16_t type,
                            uint16_t cls,
                            uint8_t rcode,
                            uint32_t ttl);

/** Insert a mapping directly (used for /etc/hosts-like overrides). */
int dns_cache_put_host(dns_cache_t *c,
                       const char *name,
                       const char *ip,
                       uint32_t ttl);

/** Stats. */
typedef struct {
    size_t   entries;
    size_t   bytes;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t expired;
} dns_cache_stats_t;

void dns_cache_stats(dns_cache_t *c, dns_cache_stats_t *out);

#endif

/* --- persistence --- */

/** Save all A and AAAA entries to `path` as text.
 *  Returns 0 on success, -1 on I/O error. */
int dns_cache_save(dns_cache_t *c, const char *path);

/** Load entries from `path`, skipping expired ones.
 *  Returns number of entries loaded, or -1 if the file cannot be opened. */
int dns_cache_load(dns_cache_t *c, const char *path);

