/* flywheel/include/cache.h
 *
 * Parse result cache. Keyed by source content hash.
 * Platform-agnostic: uses only stdint.h, stdlib.h, string.h.
 *
 * Public API (see src/cache.c for implementation):
 *   parser_parse_cached(src, filename)      -> cached or fresh parse
 *   parser_parse_module_cached(src, fname)  -> same for modules
 *   parser_cache_clear()                    -> drop all entries
 *   parser_cache_set_capacity(n)            -> 1..64, returns actual
 *   parser_cache_stats()                    -> hits, misses, size
 */

#ifndef FLYWHEEL_CACHE_H
#define FLYWHEEL_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include "parser.h"

typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    int      entries;
    int      capacity;
} ParseCacheStats;

ParseResult    parser_parse_cached(const char *source, const char *filename);
ParseResult    parser_parse_module_cached(const char *source, const char *filename);
void           parser_cache_clear(void);
void           parser_cache_forget(void);   /* clear entries, keep arenas */
int            parser_cache_set_capacity(int new_cap);
ParseCacheStats parser_cache_stats(void);

#endif
