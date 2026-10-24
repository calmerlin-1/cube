/** css_selector.h — selector parser. */

#ifndef FLY_CSS_SELECTOR_H
#define FLY_CSS_SELECTOR_H

#include "../../include/css_types.h"
#include "../tokenizer/css_token.h"
#include "../runtime/arena.h"

/** Parse a selector list (top-level entry point). */
css_selector_list_t css_parse_selector_list(css_lexer_t *lx, css_arena_t *ar);

/** Parse a single selector (no commas). */
int css_parse_one_selector(css_lexer_t *lx, css_arena_t *ar, css_selector_t *out);

#endif
