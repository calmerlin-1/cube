/**
 * url_cache.c — URL parse cache. See include/url_cache.h.
 *
 * Design:
 *   - open-addressing hash table (single malloc for the array)
 *   - FNV-1a 64-bit hash over the input bytes
 *   - linear probe with tombstones for deletion
 *   - LRU eviction by monotonic counter
 *   - on miss, copy the input into a private buffer and store a
 *     url_view whose pointers point into that copy
 *   - on hit, `*out = entry->view` — one assignment, no per-field work
 *
 * The whole point: a hit costs one hash + one probe + one struct copy.
 * If you're doing more than that, the cache is wrong.
 */

#include "url_cache.h"

#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a(const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

typedef struct {
    uint64_t hash;
    uint64_t lru;
    char    *url;      /* owned copy of the input */
    size_t   url_len;
    url_err  error;
    url_view view;     /* points into url; valid on hits only */
} entry_t;

struct url_cache {
    entry_t *slots;
    size_t   cap;
    size_t   count;
    size_t   live;
    size_t   max;
    uint64_t tick;
    uint64_t hits, misses, evictions;
};

url_cache_t *url_cache_new(size_t max_entries) {
    if (max_entries < 8) max_entries = 8;
    size_t cap = 16;
    while (cap < max_entries * 2) cap <<= 1;
    url_cache_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->slots = calloc(cap, sizeof(*c->slots));
    if (!c->slots) { free(c); return NULL; }
    c->cap = cap;
    c->max = max_entries;
    return c;
}

static void entry_free(entry_t *e) {
    if (e->url) free(e->url);
    memset(e, 0, sizeof(*e));
}

void url_cache_clear(url_cache_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->cap; i++)
        if (c->slots[i].hash > 1)
            entry_free(&c->slots[i]);
    memset(c->slots, 0, c->cap * sizeof(*c->slots));
    c->count = c->live = 0;
}

void url_cache_free(url_cache_t *c) {
    if (!c) return;
    url_cache_clear(c);
    free(c->slots);
    free(c);
}

static void evict_lru(url_cache_t *c) {
    if (c->live < c->max) return;
    size_t worst = (size_t)-1;
    uint64_t worst_lru = UINT64_MAX;
    for (size_t i = 0; i < c->cap; i++) {
        if (c->slots[i].hash <= 1) continue;
        if (c->slots[i].lru < worst_lru) {
            worst_lru = c->slots[i].lru;
            worst = i;
        }
    }
    if (worst != (size_t)-1) {
        entry_free(&c->slots[worst]);
        c->slots[worst].hash = 1;
        c->live--;
        c->evictions++;
    }
}

/* Rebase a url_view so its pointers point into `base` (the cache copy)
 * instead of the caller's buffer. Computes offsets and re-adds. */
static void rebase_view(url_view *dst, const url_view *src, const char *base) {
    memset(dst, 0, sizeof(*dst));
    dst->raw     = base;
    dst->raw_len = src->raw_len;
    memcpy(dst->idna_storage, src->idna_storage, sizeof dst->idna_storage);

#define REB(field) \
    if (src->field) { \
        if (src->field >= src->raw && src->field < src->raw + src->raw_len) { \
            dst->field = base + (size_t)(src->field - src->raw); \
        } else if (src->field >= src->idna_storage && \
                   src->field <  src->idna_storage + sizeof src->idna_storage) { \
            dst->field = dst->idna_storage + (size_t)(src->field - src->idna_storage); \
        } else if (src->field##_len == 1 && *src->field == '/') { \
            dst->field = "/"; \
        } else { \
            dst->field = NULL; \
        } \
    } else { \
        dst->field = NULL; \
    } \
    dst->field##_len = src->field##_len
    REB(scheme);
    REB(userinfo);
    REB(host);
    REB(port_str);
    REB(path);
    REB(query);
    REB(fragment);
#undef REB
    dst->port            = src->port;
    dst->is_ipv6         = src->is_ipv6;
    dst->is_default_port = src->is_default_port;
    dst->has_authority   = src->has_authority;
}
static int store(url_cache_t *c, uint64_t hash,
                 const char *url, size_t url_len,
                 url_err err, const url_view *v)
{
    evict_lru(c);
    size_t mask = c->cap - 1;
    size_t i = hash & mask;
    size_t first_tombstone = (size_t)-1;

    for (size_t probe = 0; probe < c->cap; probe++) {
        entry_t *e = &c->slots[i];
        if (e->hash == 0) {
            size_t slot = first_tombstone != (size_t)-1 ? first_tombstone : i;
            entry_t *dst = &c->slots[slot];
            memset(dst, 0, sizeof(*dst));
            /* C1/C5: allocate URL copy BEFORE touching hash — on malloc
             * failure the slot stays empty, never poisoned */
            char *url_copy = NULL;
            if (err == URL_OK) {
                if (url_len >= SIZE_MAX - 1) return -1;   /* C8: overflow guard */
                url_copy = malloc(url_len + 1);
                if (!url_copy) return -1;
                memcpy(url_copy, url, url_len);
                url_copy[url_len] = 0;
            }
            dst->hash = hash ? hash : 2;
            dst->lru  = ++c->tick;
            dst->error = err;
            if (err == URL_OK) {
                dst->url = url_copy;
                dst->url_len = url_len;
                rebase_view(&dst->view, v, dst->url);
            }
            c->count++;
            c->live++;
            return 0;
        }
        if (e->hash == 1) {
            if (first_tombstone == (size_t)-1) first_tombstone = i;
        } else if (e->hash == hash && e->url_len == url_len &&
                   memcmp(e->url, url, url_len) == 0) {
            e->lru = ++c->tick;
            return 1;
        }
        i = (i + 1) & mask;
    }
    return -1;
}

static entry_t *find(url_cache_t *c, uint64_t hash,
                     const char *url, size_t url_len)
{
    size_t mask = c->cap - 1;
    size_t i = hash & mask;
    for (size_t probe = 0; probe < c->cap; probe++) {
        entry_t *e = &c->slots[i];
        if (e->hash == 0) return NULL;
        if (e->hash == hash && e->url_len == url_len &&
            memcmp(e->url, url, url_len) == 0)
            return e;
        i = (i + 1) & mask;
    }
    return NULL;
}

url_err url_cache_parse(url_cache_t *c,
                        const char *s, size_t len,
                        url_view *out)
{
    if (!c) return url_parse(s, len, out);

    uint64_t h = fnv1a(s, len);
    if (h <= 1) h = 2;

    entry_t *e = find(c, h, s, len);
    if (e) {
        c->hits++;
        e->lru = ++c->tick;
        if (e->error != URL_OK) return e->error;
        *out = e->view;      /* one struct copy — this is the fast path */
        return URL_OK;
    }

    c->misses++;
    url_view tmp;
    url_err err = url_parse(s, len, &tmp);
    store(c, h, s, len, err, err == URL_OK ? &tmp : NULL);
    if (err == URL_OK) *out = tmp;
    return err;
}

void url_cache_stats(const url_cache_t *c, url_cache_stats_t *out) {
    if (!c || !out) return;
    out->hits        = c->hits;
    out->misses      = c->misses;
    out->evictions   = c->evictions;
    out->entries     = c->live;
    out->max_entries = c->max;
}
