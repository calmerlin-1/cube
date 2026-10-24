/**
 * url_cache.h — URL parse cache.
 *
 * Purpose: when the same URL is parsed repeatedly, skip the parse and
 * return the previous result. For a crawler revisiting pages, a browser
 * loading back-references, or a server deduplicating requests, this
 * turns O(parse) into O(hash + lookup).
 *
 * Contract for cached views:
 *   Every pointer in the returned url_view points into the cache's own
 *   copy of the URL, not the caller's buffer. Those pointers are valid
 *   only until the entry is evicted or the cache is freed. Callers must
 *   not modify or free them. Copy the fields if you need them to outlive
 *   the cache entry.
 *
 * Concurrency: not thread-safe. One cache per thread.
 * Allocation: the cache allocates once at url_cache_new() and once per
 *   URL string on a miss. The fast path (hit) allocates nothing.
 */

#ifndef FLYWHEEL_URL_CACHE_H
#define FLYWHEEL_URL_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include "url_parser.h"

typedef struct url_cache url_cache_t;

/**
 * Create a cache with the given maximum number of entries.
 * Entries beyond the cap are evicted LRU.
 * Returns NULL on allocation failure.
 */
url_cache_t *url_cache_new(size_t max_entries);

void url_cache_free(url_cache_t *c);

/** Remove all entries but keep the cache usable. */
void url_cache_clear(url_cache_t *c);

/**
 * Parse with caching.
 * On hit: fills *out from the cached entry, returns URL_OK.
 * On miss: runs url_parse, stores the result, returns what url_parse
 *          returned. Parse errors are cached too (NXDOMAIN-style).
 */
url_err url_cache_parse(url_cache_t *c,
                        const char *s, size_t len,
                        url_view *out);

/** Runtime stats. */
typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    size_t   entries;
    size_t   max_entries;
} url_cache_stats_t;

void url_cache_stats(const url_cache_t *c, url_cache_stats_t *out);

#endif /* FLYWHEEL_URL_CACHE_H */
