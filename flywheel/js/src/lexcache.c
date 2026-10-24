/* flywheel/src/lexcache.c
 *
 * Token-stream cache. Platform-agnostic C99.
 *
 * Key:   FNV-1a hash of source text + length.
 * Value: malloc'd Token array (cache owns it).
 * Store: ring buffer of N entries, LRU round-robin.
 *
 * The cache never shares memory with a live lexer — it lexes into its
 * own Lexer instance, keeps the resulting Token array, and hands the
 * pointer back on hit. Callers must NOT free a cached array.
 */

#include "../include/lexcache.h"
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Hash                                                              */
/* ---------------------------------------------------------------- */
static uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* ---------------------------------------------------------------- */
/* Entry                                                             */
/* ---------------------------------------------------------------- */
typedef struct {
    uint64_t  hash;
    size_t    length;
    int       valid;
    Token    *tokens;
    int       count;
} LexEntry;

static LexEntry g_lex_entries[64];
static int      g_lex_cap = 8;
static int      g_lex_next = 0;
static uint64_t g_lex_hits = 0, g_lex_misses = 0, g_lex_evictions = 0;

/* ---------------------------------------------------------------- */
/* Public API                                                        */
/* ---------------------------------------------------------------- */
int lexer_cache_set_capacity(int new_cap) {
    if (new_cap < 1)  new_cap = 1;
    if (new_cap > 64) new_cap = 64;
    lexer_cache_clear();
    g_lex_cap = new_cap;
    g_lex_next = 0;
    return g_lex_cap;
}

LexCacheStats lexer_cache_stats(void) {
    LexCacheStats s;
    s.hits = g_lex_hits;
    s.misses = g_lex_misses;
    s.evictions = g_lex_evictions;
    s.entries = 0;
    for (int i = 0; i < g_lex_cap; i++) if (g_lex_entries[i].valid) s.entries++;
    s.capacity = g_lex_cap;
    return s;
}

void lexer_cache_clear(void) {
    for (int i = 0; i < g_lex_cap; i++) {
        LexEntry *e = &g_lex_entries[i];
        if (e->valid) {
            if (e->tokens) free(e->tokens);
            e->tokens = NULL;
            e->valid  = 0;
            e->count  = 0;
        }
    }
    g_lex_next = 0;
}

static LexEntry *lex_find(uint64_t h, size_t len) {
    for (int i = 0; i < g_lex_cap; i++) {
        LexEntry *e = &g_lex_entries[i];
        if (e->valid && e->hash == h && e->length == len) return e;
    }
    return NULL;
}

static LexEntry *lex_pick_slot(void) {
    LexEntry *e = &g_lex_entries[g_lex_next];
    g_lex_next = (g_lex_next + 1) % g_lex_cap;
    if (e->valid) {
        if (e->tokens) free(e->tokens);
        e->tokens = NULL;
        e->valid  = 0;
        e->count  = 0;
        g_lex_evictions++;
    }
    return e;
}

/* ---------------------------------------------------------------- */
/* Fresh lex into a malloc'd array                               */
/* ---------------------------------------------------------------- */
static Token *lex_fresh(const char *source, int *out_count) {
    Lexer lx;
    lexer_init(&lx, source);
    return lexer_all(&lx, out_count);
}

/* ---------------------------------------------------------------- */
/* Cached entry point                                            */
/* ---------------------------------------------------------------- */
Token *lexer_all_cached(const char *source, int *out_count) {
    if (!source) { *out_count = 0; return NULL; }
    size_t len = strlen(source);
    uint64_t h = fnv1a(source, len);

    LexEntry *hit = lex_find(h, len);
    if (hit) {
        g_lex_hits++;
        *out_count = hit->count;
        return hit->tokens;
    }

    g_lex_misses++;
    int n = 0;
    Token *fresh = lex_fresh(source, &n);

    LexEntry *slot = lex_pick_slot();
    slot->hash    = h;
    slot->length  = len;
    slot->valid   = 1;
    slot->tokens  = fresh;   /* cache owns it now */
    slot->count   = n;

    *out_count = n;
    return fresh;
}

Token *lexer_all_nocache(const char *source, int *out_count) {
    if (!source) { *out_count = 0; return NULL; }
    return lex_fresh(source, out_count);
}
