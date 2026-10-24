/** css_cache.c — token cache, stylesheet cache, selector interning. */

#include "../../include/css.h"
#include "../../include/css_types.h"
#include "css_selector.h"
#include "../tokenizer/css_token.h"
#include "../runtime/arena.h"
#include <string.h>
#include <stdlib.h>

#define TOK_CACHE_SIZE     64
#define SHEET_CACHE_SIZE   64
#define INTERN_TABLE_SIZE  512

/* ---- FNV-1a ---- */
static uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ull;
    }
    return h;
}

/* ---- Token cache ---- */
static css_tok_cache_entry_t g_tok_cache[TOK_CACHE_SIZE];
static int g_tok_next = 0;
static uint64_t g_tok_hits = 0, g_tok_misses = 0;

/* ---- Sheet cache ---- */
static css_sheet_cache_entry_t g_sheet_cache[SHEET_CACHE_SIZE];
static int g_sheet_next = 0;
static uint64_t g_sheet_hits = 0, g_sheet_misses = 0;

/* ---- Intern table (open addressing) ---- */
static css_sel_intern_entry_t g_intern[INTERN_TABLE_SIZE];
static uint64_t g_intern_hits = 0, g_intern_misses = 0;

static int g_cache_enabled = 0;

void css_cache_enable(int enable) { g_cache_enabled = enable ? 1 : 0; }

/* ============================================================
 * Token cache
 * ============================================================ */

static css_tok_cache_entry_t *tok_find(uint64_t h, size_t len) {
    for (int i = 0; i < TOK_CACHE_SIZE; i++) {
        if (g_tok_cache[i].valid &&
            g_tok_cache[i].hash == h &&
            g_tok_cache[i].length == len) return &g_tok_cache[i];
    }
    return NULL;
}

static void tok_evict(void) {
    css_tok_cache_entry_t *e = &g_tok_cache[g_tok_next];
    g_tok_next = (g_tok_next + 1) % TOK_CACHE_SIZE;
    if (e->valid) {
        free(e->tokens);
        e->tokens = NULL;
        e->valid = 0;
    }
}

/* Public: get tokens for source, cached. Returns NULL on error. */
css_token_t *css_tok_cache_get(const char *src, size_t len, int *out_n) {
    if (!g_cache_enabled) return NULL;
    uint64_t h = fnv1a(src, len);
    css_tok_cache_entry_t *e = tok_find(h, len);
    if (e) {
        g_tok_hits++;
        *out_n = e->n_tokens;
        return e->tokens;
    }
    g_tok_misses++;
    /* Miss — caller will tokenize and insert. */
    return NULL;
}

/* Public: insert tokens into cache. Takes ownership. */
void css_tok_cache_put(const char *src, size_t len,
                        css_token_t *tokens, int n) {
    if (!g_cache_enabled) { free(tokens); return; }
    tok_evict();
    int slot = (g_tok_next - 1 + TOK_CACHE_SIZE) % TOK_CACHE_SIZE;
    css_tok_cache_entry_t *e = &g_tok_cache[slot];
    e->hash = fnv1a(src, len);
    e->length = len;
    e->valid = 1;
    e->tokens = tokens;
    e->n_tokens = n;
}

/* ============================================================
 * Stylesheet cache
 * ============================================================ */

static css_sheet_cache_entry_t *sheet_find(uint64_t h, size_t len) {
    for (int i = 0; i < SHEET_CACHE_SIZE; i++) {
        if (g_sheet_cache[i].valid &&
            g_sheet_cache[i].hash == h &&
            g_sheet_cache[i].length == len) return &g_sheet_cache[i];
    }
    return NULL;
}

const css_stylesheet_t *css_parse_cached(const char *src, size_t len) {
    if (!src) return NULL;
    if (!g_cache_enabled) return css_parse(src, len);

    uint64_t h = fnv1a(src, len);
    css_sheet_cache_entry_t *e = sheet_find(h, len);
    if (e) { g_sheet_hits++; return (const css_stylesheet_t *)e->stylesheet; }
    g_sheet_misses++;

    /* Miss — parse and store. Result is owned by cache. */
    css_stylesheet_t *ss = css_parse(src, len);
    if (!ss) return NULL;

    css_sheet_cache_entry_t *slot = &g_sheet_cache[g_sheet_next];
    g_sheet_next = (g_sheet_next + 1) % SHEET_CACHE_SIZE;
    if (slot->valid) {
        /* Old entry gets replaced — its arena is released to pool.
         * Note: this could be problematic if user still holds a
         * pointer. Cache users must not free cached stylesheets. */
        slot->valid = 0;
    }
    slot->hash = h;
    slot->length = len;
    slot->valid = 1;
    slot->stylesheet = ss;
    return ss;
}

/* ============================================================
 * Selector intern
 * ============================================================ */

static uint32_t intern_hash(const char *s, int n) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    return h;
}

const css_selector_t *css_selector_intern(const char *text, int len,
                                          css_arena_t *ar) {
    if (!g_cache_enabled || len <= 0 || len > 512) return NULL;
    uint32_t idx = intern_hash(text, len) & (INTERN_TABLE_SIZE - 1);
    for (int probe = 0; probe < 8; probe++) {
        int i = (idx + probe) & (INTERN_TABLE_SIZE - 1);
        css_sel_intern_entry_t *e = &g_intern[i];
        if (!e->valid) return NULL;   /* empty slot — not interned */
        if (e->text_len == len && memcmp(e->text, text, (size_t)len) == 0) {
            g_intern_hits++;
            return (const css_selector_t *)e->parsed;
        }
    }
    g_intern_misses++;
    (void)ar;
    return NULL;
}

void css_selector_intern_put(const char *text, int len,
                             css_selector_t *sel) {
    if (!g_cache_enabled || len <= 0 || len > 512) return;
    uint32_t idx = intern_hash(text, len) & (INTERN_TABLE_SIZE - 1);
    for (int probe = 0; probe < 8; probe++) {
        int i = (idx + probe) & (INTERN_TABLE_SIZE - 1);
        css_sel_intern_entry_t *e = &g_intern[i];
        if (!e->valid) {
            e->text = text;   /* NOT owned — points into source */
            e->text_len = len;
            e->valid = 1;
            e->parsed = sel;
            return;
        }
        if (e->text_len == len && memcmp(e->text, text, (size_t)len) == 0) {
            return;   /* already there */
        }
    }
}

/* ============================================================
 * Stats & clear
 * ============================================================ */

void css_cache_stats(css_cache_stats_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->tok_hits = g_tok_hits;
    out->tok_misses = g_tok_misses;
    out->sheet_hits = g_sheet_hits;
    out->sheet_misses = g_sheet_misses;
    out->intern_hits = g_intern_hits;
    out->intern_misses = g_intern_misses;
    for (int i = 0; i < TOK_CACHE_SIZE; i++) if (g_tok_cache[i].valid) out->tok_entries++;
    for (int i = 0; i < SHEET_CACHE_SIZE; i++) if (g_sheet_cache[i].valid) out->sheet_entries++;
    for (int i = 0; i < INTERN_TABLE_SIZE; i++) if (g_intern[i].valid) out->intern_entries++;
}

void css_cache_clear(void) {
    for (int i = 0; i < TOK_CACHE_SIZE; i++) {
        if (g_tok_cache[i].valid) { free(g_tok_cache[i].tokens); g_tok_cache[i].valid = 0; }
    }
    for (int i = 0; i < SHEET_CACHE_SIZE; i++) g_sheet_cache[i].valid = 0;
    for (int i = 0; i < INTERN_TABLE_SIZE; i++) g_intern[i].valid = 0;
    g_tok_hits = g_tok_misses = g_sheet_hits = g_sheet_misses = 0;
    g_intern_hits = g_intern_misses = 0;
    g_tok_next = g_sheet_next = 0;
}
