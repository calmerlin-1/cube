/** css_token.h — CSS tokenizer. State machine over bytes. */

#ifndef FLY_CSS_TOKEN_H
#define FLY_CSS_TOKEN_H

#include "../../include/css_types.h"

typedef struct {
    const char *source;
    const char *cur;
    const char *end;
    int         line;
    int         column;
} css_lexer_t;

void        css_lexer_init(css_lexer_t *lx, const char *s, size_t n);
css_token_t css_lexer_next(css_lexer_t *lx);

/** Human-readable kind name. */
const char *css_tok_kind_name(css_tok_kind_t k);

#endif
