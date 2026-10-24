#include <stdio.h>
#include <stdlib.h>
#include "../include/interp.h"
#include "../include/ast.h"

/* Hook malloc/free to count live allocations */
extern void *ast_arena_head(void);

static long mem_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) { sscanf(line + 6, "%ld", &kb); break; }
    }
    fclose(f);
    return kb;
}

int main(void) {
    const char *src = "let a=[1,2,3]; function f(x){return x*2;} f(a[0])+a.length";

    /* Measure one cycle in isolation, 5 times, with intermediate RSS */
    printf("measuring RSS after each of 5 single cycles:\n");
    for (int i = 0; i < 5; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<x>");
        (void)r;
        flywheel_free(I);
        printf("  cycle %d: %ld KB\n", i + 1, mem_kb());
    }

    /* Now check: is the arena head NULL after a full cycle? */
    printf("\nchecking arena head after free:\n");
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    void *h1 = ast_arena_head();
    printf("  head before eval:  %p\n", h1);
    FlyResult r = flywheel_eval(I, src, "<x>");
    void *h2 = ast_arena_head();
    printf("  head after eval:   %p\n", h2);
    flywheel_free(I);
    void *h3 = ast_arena_head();
    printf("  head after free:   %p\n", h3);
    printf("  (should be 0x0)\n");

    /* Check lexer cache */
    extern long lexer_cache_size(void);
    return 0;
}
