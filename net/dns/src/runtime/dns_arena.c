/** dns_arena.c — bump allocator. Blocks grow geometrically. */

#include "dns_arena.h"
#include <stdlib.h>
#include <string.h>

typedef struct block {
    struct block *next;
    size_t        used;
    size_t        cap;
    unsigned char data[];
} block_t;

struct dns_arena {
    block_t *head;
    size_t   initial;
    size_t   total_bytes;
};

dns_arena_t *dns_arena_new(size_t initial) {
    if (initial < 256) initial = 256;
    dns_arena_t *a = (dns_arena_t *)calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->initial = initial;
    return a;
}

void *dns_arena_alloc(dns_arena_t *a, size_t n) {
    if (!a) return NULL;
    if (n == 0) n = 1;
    n = (n + 7u) & ~((size_t)7u);   /* 8-byte align */

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

void dns_arena_free(dns_arena_t *a) {
    if (!a) return;
    block_t *b = a->head;
    while (b) {
        block_t *nx = b->next;
        free(b);
        b = nx;
    }
    free(a);
}

size_t dns_arena_bytes(dns_arena_t *a) {
    return a ? a->total_bytes : 0;
}
