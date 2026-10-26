/** arena.c — bump allocator. Blocks grow geometrically. */

#include "arena.h"
#include <stdlib.h>
#include <string.h>

typedef struct block {
    struct block *next;
    size_t        used;
    size_t        cap;
    unsigned char data[];
} block_t;

struct css_arena {
    block_t *head;
    size_t   initial;
    size_t   total_bytes;
};

css_arena_t *css_arena_new(size_t initial) {
    if (initial < 512) initial = 512;
    css_arena_t *a = (css_arena_t *)calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->initial = initial;
    return a;
}

void *css_arena_alloc(css_arena_t *a, size_t n) {
    if (!a) return NULL;
    if (n == 0) n = 1;
    n = (n + 7u) & ~((size_t)7u);

    block_t *b = a->head;
    if (!b || b->used + n > b->cap) {
        size_t cap = (b && b->cap * 2 > n) ? b->cap * 2 : (n > a->initial ? n : a->initial);
        block_t *nb = (block_t *)malloc(sizeof(*nb) + cap);
        if (!nb) return NULL;
        nb->next = a->head;
        nb->used = 0;
        nb->cap = cap;
        a->head = nb;
        b = nb;
    }
    void *p = b->data + b->used;
    b->used += n;
    a->total_bytes += n;
    memset(p, 0, n);
    return p;
}

void *css_arena_realloc(css_arena_t *a, void *old, size_t old_n, size_t new_n) {
    if (!a) return NULL;
    if (new_n <= old_n) return old;
    /* If `old` is the most recent allocation, extend in place. */
    if (old && a->head) {
        unsigned char *end = (unsigned char *)old + old_n;
        if (end == a->head->data + a->head->used) {
            size_t extra = new_n - old_n;
            extra = (extra + 7u) & ~((size_t)7u);
            if (a->head->used + extra <= a->head->cap) {
                a->head->used += extra;
                a->total_bytes += extra;
                memset((unsigned char *)old + old_n, 0, extra);
                return old;
            }
        }
    }
    void *p = css_arena_alloc(a, new_n);
    if (p && old) memcpy(p, old, old_n);
    return p;
}

void css_arena_free(css_arena_t *a) {
    if (!a) return;
    block_t *b = a->head;
    while (b) {
        block_t *nx = b->next;
        free(b);
        b = nx;
    }
    free(a);
}

size_t css_arena_bytes(css_arena_t *a) {
    return a ? a->total_bytes : 0;
}

/* Arena pooling — reuse blocks across parses. */

void css_arena_reset(css_arena_t *a) {
    if (!a) return;
    /* Walk all blocks, set used = 0. Keep the blocks for reuse. */
    for (block_t *b = a->head; b; b = b->next) {
        b->used = 0;
    }
    a->total_bytes = 0;
}

/* Pool: keep a small stack of arenas ready to hand out. */
#define POOL_MAX 8
static css_arena_t *g_pool[POOL_MAX];
static int          g_pool_n = 0;

css_arena_t *css_arena_pool_acquire(void) {
    if (g_pool_n > 0) {
        css_arena_t *a = g_pool[--g_pool_n];
        css_arena_reset(a);
        return a;
    }
    return css_arena_new(4096);
}

void css_arena_pool_release(css_arena_t *a) {
    if (!a) return;
    if (g_pool_n >= POOL_MAX) {
        css_arena_free(a);
        return;
    }
    g_pool[g_pool_n++] = a;
}

void css_arena_pool_shutdown(void) {
    for (int i = 0; i < g_pool_n; i++) {
        css_arena_free(g_pool[i]);
    }
    g_pool_n = 0;
}

size_t css_arena_pool_size(void) {
    return (size_t)g_pool_n;
}
