/** dns_pin.c — per-domain upstream preference with LRU eviction. */

#include "dns_pin.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define PIN_MAX_NAME 256
#define PIN_HASH_BUCKETS 256

typedef struct pin_entry {
    char     name[PIN_MAX_NAME];
    uint16_t type;
    size_t   upstream_idx;
    uint64_t last_used_ns;
    struct pin_entry *next;
} pin_entry_t;

struct dns_pin_store {
    pin_entry_t *buckets[PIN_HASH_BUCKETS];
    size_t       count;
    size_t       max;
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/** FNV-1a over name+type. */
static uint32_t hash_key(const char *name, uint16_t type) {
    uint32_t h = 2166136261u;
    while (*name) { h ^= (uint8_t)*name++; h *= 16777619u; }
    h ^= (uint8_t)(type & 0xFF);
    h *= 16777619u;
    h ^= (uint8_t)((type >> 8) & 0xFF);
    h *= 16777619u;
    return h;
}

dns_pin_store_t *dns_pin_new(size_t max_entries) {
    dns_pin_store_t *s = (dns_pin_store_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->max = max_entries ? max_entries : 1024;
    return s;
}

void dns_pin_free(dns_pin_store_t *s) {
    if (!s) return;
    for (size_t i = 0; i < PIN_HASH_BUCKETS; i++) {
        pin_entry_t *e = s->buckets[i];
        while (e) {
            pin_entry_t *n = e->next;
            free(e);
            e = n;
        }
    }
    free(s);
}

/** Find oldest entry across all buckets. Returns NULL if empty. */
static pin_entry_t *find_oldest(dns_pin_store_t *s) {
    pin_entry_t *oldest = NULL;
    uint64_t min_age = UINT64_MAX;
    for (size_t i = 0; i < PIN_HASH_BUCKETS; i++) {
        for (pin_entry_t *e = s->buckets[i]; e; e = e->next) {
            if (e->last_used_ns < min_age) {
                min_age = e->last_used_ns;
                oldest = e;
            }
        }
    }
    return oldest;
}

/** Remove entry from its bucket. */
static void unlink_entry(dns_pin_store_t *s, pin_entry_t *target) {
    uint32_t h = hash_key(target->name, target->type) % PIN_HASH_BUCKETS;
    pin_entry_t **pp = &s->buckets[h];
    while (*pp) {
        if (*pp == target) { *pp = target->next; s->count--; return; }
        pp = &(*pp)->next;
    }
}

void dns_pin_set(dns_pin_store_t *s, const char *name, uint16_t type, size_t upstream_idx) {
    if (!s || !name) return;
    size_t nlen = strlen(name);
    if (nlen >= PIN_MAX_NAME) return;

    uint32_t h = hash_key(name, type) % PIN_HASH_BUCKETS;
    for (pin_entry_t *e = s->buckets[h]; e; e = e->next) {
        if (e->type == type && strcmp(e->name, name) == 0) {
            e->upstream_idx = upstream_idx;
            e->last_used_ns = now_ns();
            return;
        }
    }
    /* evict oldest if full */
    if (s->count >= s->max) {
        pin_entry_t *victim = find_oldest(s);
        if (victim) unlink_entry(s, victim);
        free(victim);
    }
    pin_entry_t *e = (pin_entry_t *)calloc(1, sizeof(*e));
    if (!e) return;
    memcpy(e->name, name, nlen + 1);
    e->type = type;
    e->upstream_idx = upstream_idx;
    e->last_used_ns = now_ns();
    e->next = s->buckets[h];
    s->buckets[h] = e;
    s->count++;
}

size_t dns_pin_get(dns_pin_store_t *s, const char *name, uint16_t type) {
    if (!s || !name) return SIZE_MAX;
    uint32_t h = hash_key(name, type) % PIN_HASH_BUCKETS;
    for (pin_entry_t *e = s->buckets[h]; e; e = e->next) {
        if (e->type == type && strcmp(e->name, name) == 0) {
            e->last_used_ns = now_ns();
            return e->upstream_idx;
        }
    }
    return SIZE_MAX;
}

void dns_pin_clear(dns_pin_store_t *s) {
    if (!s) return;
    for (size_t i = 0; i < PIN_HASH_BUCKETS; i++) {
        pin_entry_t *e = s->buckets[i];
        while (e) {
            pin_entry_t *n = e->next;
            free(e);
            e = n;
        }
        s->buckets[i] = NULL;
    }
    s->count = 0;
}

size_t dns_pin_count(dns_pin_store_t *s) {
    return s ? s->count : 0;
}
