/* flywheel/include/lexcache.h
 *
 * Token-stream cache. Same design as parse cache: FNV-1a hash of
 * source, ring buffer of N entries, one slot per unique source.
 *
 * Public API:
 *   lexer_all_cached(src)        -> tokens from cache or fresh lex
 *   lexer_all_nocache(src)       -> always lex fresh
 *   lexer_cache_clear()          -> drop all entries
 *   lexer_cache_set_capacity(n)  -> 1..64, returns actual
 *   lexer_cache_stats()          -> hits, misses, evictions
 */

#ifndef FLYWHEEL_LEXCACHE_H
#define FLYWHEEL_LEXCACHE_H

#include <stdint.h>
#include "lexer.h"

typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    int      entries;
    int      capacity;
} LexCacheStats;

/* Return a token array for the given source. On hit, returns the cached
 * array (do not free — cache owns it). On miss, lexes fresh, stores in
 * cache, and returns the same array. */
Token *lexer_all_cached(const char *source, int *out_count);

/* Same but bypasses the cache and always lexes fresh. Caller must free
 * the returned array. */
Token *lexer_all_nocache(const char *source, int *out_count);

void           lexer_cache_clear(void);
int            lexer_cache_set_capacity(int new_cap);
LexCacheStats  lexer_cache_stats(void);

#endif
