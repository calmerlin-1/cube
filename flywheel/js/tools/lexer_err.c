#include <stdio.h>
#include "../include/lexer.h"
int main(void) {
    Lexer lx;
    lexer_init(&lx, "\"abc");
    Token t = lexer_next(&lx);
    printf("kind=%d has_error=%d msg=\"%s\" line=%d col=%d\n",
           t.kind, lx.has_error, lx.error_msg, lx.error_line, lx.error_column);
    return 0;
}
