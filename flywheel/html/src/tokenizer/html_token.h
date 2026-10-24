/** html_token.h — HTML tokenizer. */

#ifndef FLY_HTML_TOKEN_H
#define FLY_HTML_TOKEN_H

#include "../../include/html_types.h"

typedef struct {
    const char *source;
    const char *cur;
    const char *end;
    int         line;
    int         column;
} html_lexer_t;

void         html_lexer_init(html_lexer_t *lx, const char *s, size_t n);
html_token_t html_lexer_next(html_lexer_t *lx);

const char  *html_tok_kind_name(html_tok_kind_t k);

#endif
