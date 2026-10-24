#include <stdio.h>
#include <stdlib.h>
#include "../include/interp.h"

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

    /* Warm up: run 100 cycles to reach steady state */
    for (int i = 0; i < 100; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<w>");
        (void)r;
        flywheel_free(I);
    }
    long after_warmup = mem_kb();

    /* Test A: 100 more cycles */
    for (int i = 0; i < 100; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<a>");
        (void)r;
        flywheel_free(I);
    }
    long after_100 = mem_kb();

    /* Test B: 1000 more cycles */
    for (int i = 0; i < 1000; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<b>");
        (void)r;
        flywheel_free(I);
    }
    long after_1100 = mem_kb();

    /* Test C: 10000 more cycles */
    for (int i = 0; i < 10000; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<c>");
        (void)r;
        flywheel_free(I);
    }
    long after_11100 = mem_kb();

    printf("after warmup (100):  %ld KB\n", after_warmup);
    printf("after +100:          %ld KB  (delta %+ld)\n", after_100, after_100 - after_warmup);
    printf("after +1000:         %ld KB  (delta %+ld)\n", after_1100, after_100 - after_warmup);
    printf("after +10000:        %ld KB  (delta %+ld)\n", after_11100, after_100 - after_warmup);
    printf("\n");
    printf("if delta stays FLAT while cycles go up 100x -> no leak, just malloc caching\n");
    printf("if delta grows linearly with cycles      -> real leak\n");

    return 0;
}
