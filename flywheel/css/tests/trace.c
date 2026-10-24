/** trace.c — dump the token stream for a CSS source string. Debug only. */

#include "../include/css.h"
#include "../src/tokenizer/css_token.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *src = ".foo { color: red; }";
    css_lexer_t lx;
    css_lexer_init(&lx, src, strlen(src));
    printf("=== token trace of: %s ===\n", src);
    for (int i = 0; i < 20; i++) {
        css_token_t t = css_lexer_next(&lx);
        printf("  tok[%d] kind=%-10s len=%d text='%.*s'\n",
               i, css_tok_kind_name(t.kind), t.length, t.length,
               t.start ? t.start : "");
        if (t.kind == CSST_EOF) break;
    }
    return 0;
}
