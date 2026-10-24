/* flywheel/src/cache.c
 *
 * Small, portable parse cache.
 *
 * Design:
 *  - Cache key = (length + 64-bit FNV-1a hash of full source).
 *  - Ring buffer of N entries (default 8, max 64). On overflow,
 *    the oldest slot is reused.
 *  - Each entry keeps its own arena so cached ASTs don't share
 *    memory with a live parse.
 *  - On hit: swap the working arena for the cached one, copy
 *    errors into the caller's ParseResult, swap back.
 *  - No OS calls, no threads, no locks. Works everywhere.
 *
 * The parser is not modified. This file calls parser_parse and
 * ast_free_arena() exactly as a normal caller would.
 */

#include "../include/cache.h"
#include "../include/ast.h"
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Hash                                                              */
/* ---------------------------------------------------------------- */
static uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;   /* FNV offset */
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;             /* FNV prime */
    }
    return h;
}

/* ---------------------------------------------------------------- */
/* Entry                                                             */
/* ---------------------------------------------------------------- */
typedef struct {
    uint64_t    hash;
    size_t      length;
    int         valid;
    int         fatal;
    void       *program;    /* the AST root — points into saved_arena_head */

    /* AST lives in arena.c's single global arena. To keep cached
     * ASTs separate from the live one, we save and restore the arena
     * head pointer around parse calls. Cache owns its entries'
     * arenas via a saved head pointer. */
    void       *saved_arena_head;

    /* Errors copied out of the parse so we can replay them on hit */
    ParseError *errors;
    int         nerrors;
    int         errcap;
} Entry;

static Entry  g_entries[64];
static int    g_cap = 8;
static int    g_next = 0;
static uint64_t g_hits = 0, g_misses = 0, g_evictions = 0;
static size_t   g_live = 0;

/* ---------------------------------------------------------------- */
/* Arena snapshot helpers                                            */
/* ---------------------------------------------------------------- */
extern void  *ast_arena_head(void);       /* returns current head pointer */
extern void   ast_arena_set_head(void *); /* installs a specific head */
extern void   ast_arena_release_head(void *); /* frees an arena chain */

/* If the parser doesn't expose these, this file provides fallbacks. */
#ifdef FW_CACHE_NEEDS_FALLBACK_ARENA
/* (unused in this build) */
#endif

/* ---------------------------------------------------------------- */
/* Public API                                                        */
/* ---------------------------------------------------------------- */
int parser_cache_set_capacity(int new_cap) {
    if (new_cap < 1)  new_cap = 1;
    if (new_cap > 64) new_cap = 64;
    /* Reset the cache when resizing — simple, correct. */
    parser_cache_clear();
    g_cap = new_cap;
    g_next = 0;
    return g_cap;
}

ParseCacheStats parser_cache_stats(void) {
    ParseCacheStats s;
    s.hits = g_hits;
    s.misses = g_misses;
    s.evictions = g_evictions;
    s.entries = 0;
    for (int i = 0; i < g_cap; i++) if (g_entries[i].valid) s.entries++;
    s.capacity = g_cap;
    return s;
}

void parser_cache_clear(void) {
    /* Fast path: nothing cached, nothing to walk. */
    if (g_live == 0) {
        ast_mark_cache_owned(0);
        return;
    }
    ast_mark_cache_owned(0);   /* we're about to free; not owned by cache */
    void *current = ast_arena_head();
    for (int i = 0; i < g_cap; i++) {
        Entry *e = &g_entries[i];
        if (e->valid) {
            if (e->saved_arena_head && e->saved_arena_head != current) {
                ast_arena_release_head(e->saved_arena_head);
            }
            if (e->errors) free(e->errors);
            e->errors = NULL;
            e->valid = 0;
            e->saved_arena_head = NULL;
        }
    }
    g_next = 0;
    g_live = 0;
}

static Entry *find_entry(uint64_t h, size_t len) {
    /* Fast path: try the natural slot for this hash. */
    if (g_cap > 0) {
        Entry *e = &g_entries[h % (uint64_t)g_cap];
        if (e->valid && e->hash == h && e->length == len) return e;
    }
    /* Fallback linear scan for the ring-buffer case. */
    for (int i = 0; i < g_cap; i++) {
        Entry *e = &g_entries[i];
        if (e->valid && e->hash == h && e->length == len) return e;
    }
    return NULL;
}

static Entry *pick_slot(void) {
    Entry *e = &g_entries[g_next];
    g_next = (g_next + 1) % g_cap;
    if (e->valid) {
        /* Do not free the arena if it is currently installed as the
         * working arena — some earlier caller may still be reading
         * from it. The arena will be freed on the next
         * parser_cache_clear() call. */
        if (e->saved_arena_head != ast_arena_head()) {
            ast_arena_release_head(e->saved_arena_head);
        }
        if (e->errors) free(e->errors);
        e->errors = NULL;
        e->valid = 0;
        e->saved_arena_head = NULL;
        g_evictions++;
        if (g_live > 0) g_live--;
    }
    return e;
}

static ParseResult build_hit_result(Entry *e) {
    ParseResult r;
    memset(&r, 0, sizeof(r));
    r.program  = (Node *)e->saved_arena_head;    /* used as opaque tag */
    r.nerrors  = e->nerrors;
    r.capacity = e->nerrors;
    r.fatal    = e->fatal;

    /* Copy errors so caller can free them independently */
    if (e->nerrors > 0) {
        r.errors = (ParseError *)malloc(sizeof(ParseError) * e->nerrors);
        if (r.errors) {
            memcpy(r.errors, e->errors, sizeof(ParseError) * e->nerrors);
        } else {
            r.nerrors = 0;
            r.capacity = 0;
        }
    } else {
        r.errors = NULL;
    }
    return r;
}

/* ---------------------------------------------------------------- */
/* Common cached parse path                                          */
/* ---------------------------------------------------------------- */
static ParseResult cached_parse(const char *source, const char *filename,
                                int as_module) {
    ParseResult result;
    memset(&result, 0, sizeof(result));

    if (!source) {
        result.nerrors = 1;
        result.fatal = 1;
        return result;
    }

    size_t len = strlen(source);
    uint64_t h = fnv1a(source, len);

    /* ---------------- HIT ---------------- */
    Entry *hit = find_entry(h, len);
    if (hit) {
        g_hits++;

        /* The cached AST lives in the entry's own arena.
         * We install that arena as the current one so the caller's
         * subsequent operations (ast_print, ast_free_arena if they
         * insist) see a consistent view.
         *
         * But we DON'T let them free it — that's handled by
         * parser_cache_clear(). Callers of the *_cached API must not
         * call ast_free_arena() on the returned AST. */
        /* Do NOT install the cached arena as the current head.
         * The AST root pointer (result.program) is all the caller
         * needs. Leaving the working arena in place means later
         * ast_free_arena() calls don't touch cache-owned chains. */
        if (!ast_is_cache_owned()) ast_mark_cache_owned(1);

        result.program  = (Node *)hit->program;   /* AST root */
        result.owns_arena = 0;                     /* cache owns the arena */
        result.fatal    = hit->fatal;
        result.nerrors  = hit->nerrors;
        result.capacity = hit->nerrors;
        if (hit->nerrors > 0 && hit->errors) {
            result.errors = (ParseError *)malloc(sizeof(ParseError) * hit->nerrors);
            if (result.errors) {
                memcpy(result.errors, hit->errors,
                       sizeof(ParseError) * hit->nerrors);
            } else {
                result.nerrors = 0;
                result.capacity = 0;
            }
        }
        return result;
    }

    /* ---------------- MISS ---------------- */
    g_misses++;

    /* Step 1: save the working arena head (belongs to the caller). */
    void *working_head = ast_arena_head();

    /* Step 2: install an EMPTY arena. The parser will fill it. */
    ast_arena_set_head(NULL);

    /* Step 3: parse. All allocations go into the fresh arena. */
    ParseResult fresh = as_module
        ? parser_parse_module_uncached(source, filename)
        : parser_parse_uncached(source, filename);

    /* Step 4: snapshot the fresh arena head — that's the cache's payload. */
    void *fresh_head = ast_arena_head();

    /* Step 5: restore the caller's working arena. */
    ast_arena_set_head(working_head);

    /* Step 6: store the entry. */
    Entry *slot = pick_slot();
    slot->hash   = h;
    slot->length = len;
    slot->valid  = 1;
    g_live++;
    slot->fatal  = fresh.fatal;
    slot->saved_arena_head = fresh_head;
    slot->program = fresh.program;

    if (fresh.nerrors > 0 && fresh.errors) {
        slot->errors = (ParseError *)malloc(sizeof(ParseError) * fresh.nerrors);
        if (slot->errors) {
            memcpy(slot->errors, fresh.errors,
                   sizeof(ParseError) * fresh.nerrors);
            slot->nerrors = fresh.nerrors;
            slot->errcap = fresh.nerrors;
        } else {
            slot->nerrors = 0;
            slot->errcap = 0;
        }
    } else {
        slot->errors = NULL;
        slot->nerrors = 0;
        slot->errcap = 0;
    }

    /* Step 7: build the caller's result. Errors are copied; program
     * is unused in our ParseResult usage (the AST is in the arena). */
    result.program  = fresh.program;   /* AST root */
    result.fatal    = fresh.fatal;
    result.owns_arena = 0;             /* cache now owns this arena */
    result.nerrors  = fresh.nerrors;
    result.capacity = fresh.nerrors;
    if (fresh.nerrors > 0) {
        result.errors = (ParseError *)malloc(sizeof(ParseError) * fresh.nerrors);
        if (result.errors) {
            memcpy(result.errors, fresh.errors,
                   sizeof(ParseError) * fresh.nerrors);
        } else {
            result.nerrors = 0;
            result.capacity = 0;
        }
    }

    /* Free the freshly-made ParseResult's error array (we copied it). */
    if (fresh.errors) free(fresh.errors);

    /* Step 8: leave the caller's working arena in place. The cache
     * now owns fresh_head. The caller reads result.program (into the
     * cached chain); the global arena head stays clean. This
     * eliminates the orphaned chains that caused the ~1 KB/cycle leak. */
    ast_mark_cache_owned(1);

    return result;
}

ParseResult parser_parse_cached(const char *source, const char *filename) {
    return cached_parse(source, filename, 0);
}

ParseResult parser_parse_module_cached(const char *source, const char *filename) {
    return cached_parse(source, filename, 1);
}

/* Clear entries WITHOUT freeing their arenas. Caller frees the arena
 * chain separately via ast_free_arena(). This avoids the double-free
 * that parser_cache_clear + ast_free_arena would cause when entries
 * share the current head. */
void parser_cache_forget(void) {
    for (int i = 0; i < g_cap; i++) {
        if (g_entries[i].valid) {
            if (g_entries[i].errors) free(g_entries[i].errors);
            g_entries[i].errors = NULL;
            g_entries[i].saved_arena_head = NULL;
            g_entries[i].valid = 0;
        }
    }
    g_next = 0;
}
