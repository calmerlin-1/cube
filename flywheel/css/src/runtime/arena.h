/** arena.h — bump allocator. Free the whole arena at once. */

#ifndef FLYWHEEL_CSS_ARENA_H
#define FLYWHEEL_CSS_ARENA_H

#include <stddef.h>

typedef struct css_arena css_arena_t;

css_arena_t *css_arena_new(size_t initial);
void        *css_arena_alloc(css_arena_t *a, size_t n);
void        *css_arena_realloc(css_arena_t *a, void *old, size_t old_n, size_t new_n);
void         css_arena_free(css_arena_t *a);
size_t       css_arena_bytes(css_arena_t *a);

/** Reset an arena to empty — all allocations discarded, blocks kept.
 *  This is the key to arena pooling: reuse the blocks, reuse the memory. */
void         css_arena_reset(css_arena_t *a);

/** Pool of arenas — one per parse, reused. Acquire returns a reset arena. */
css_arena_t *css_arena_pool_acquire(void);
void         css_arena_pool_release(css_arena_t *a);
void         css_arena_pool_shutdown(void);
size_t       css_arena_pool_size(void);

#endif
