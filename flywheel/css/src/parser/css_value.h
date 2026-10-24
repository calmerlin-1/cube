/** css_value.h — parse a value slice into a structured css_value_t. */

#ifndef FLY_CSS_VALUE_H
#define FLY_CSS_VALUE_H

#include "../../include/css_types.h"
#include "../runtime/arena.h"

/** Parse a value string into a css_value_t. Uses arena for storage.
 *  Returns a pointer to the parsed value, or NULL on OOM. */
css_value_t *css_value_parse(css_arena_t *ar, const char *text, int len);

/** Debug print. */
void css_value_dump(const css_value_t *v);

#endif
