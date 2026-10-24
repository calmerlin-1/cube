/** dns_arena.h — minimal bump allocator. Free the whole arena at once. */

#ifndef FLYWHEEL_DNS_ARENA_H
#define FLYWHEEL_DNS_ARENA_H

#include <stddef.h>

typedef struct dns_arena dns_arena_t;

/** Create arena with an initial block size (bytes). */
dns_arena_t *dns_arena_new(size_t initial);

/** Allocate from arena. Returns NULL if OOM. Memory is zeroed. */
void *dns_arena_alloc(dns_arena_t *a, size_t n);

/** Free all blocks. */
void dns_arena_free(dns_arena_t *a);

/** Bytes currently allocated (for stats). */
size_t dns_arena_bytes(dns_arena_t *a);

#endif
