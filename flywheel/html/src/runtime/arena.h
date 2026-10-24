/** arena.h — bump allocator. Free the whole arena at once. */

#ifndef FLYWHEEL_CSS_ARENA_H
#define FLYWHEEL_CSS_ARENA_H

#include <stddef.h>

typedef struct html_arena html_arena_t;

html_arena_t *html_arena_new(size_t initial);
void        *html_arena_alloc(html_arena_t *a, size_t n);
void        *html_arena_realloc(html_arena_t *a, void *old, size_t old_n, size_t new_n);
void         html_arena_free(html_arena_t *a);
size_t       html_arena_bytes(html_arena_t *a);

/** Reset an arena to empty — all allocations discarded, blocks kept.
 *  This is the key to arena pooling: reuse the blocks, reuse the memory. */
void         html_arena_reset(html_arena_t *a);

/** Pool of arenas — one per parse, reused. Acquire returns a reset arena. */
html_arena_t *html_arena_pool_acquire(void);
void         html_arena_pool_release(html_arena_t *a);
void         html_arena_pool_shutdown(void);
size_t       html_arena_pool_size(void);

#endif
