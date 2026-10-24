/* demo.c — tiny program to test dbug's trace pass. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(16);
    if (!p) return 1;
    strcpy(p, "hello");
    printf("%s\n", p);
    char *q = realloc(p, 64);
    if (q) {
        strcat(q, " world");
        printf("%s\n", q);
        free(q);
    }
    return 0;
}
