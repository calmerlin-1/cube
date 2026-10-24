/** profile.c — category profiler for the flywheel interpreter.
 * Runs workloads with observation enabled, then dumps the category table. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/interp.h"
#include "category.h"

typedef struct {
    const char *label;
    const char *src;
    int iters;
} workload_t;

static const workload_t WORKLOADS[] = {
    {"1+2*3-4/2",       "1+2*3-4/2",                                         10000},
    {"loop 100",        "let s=0; for(let i=0;i<100;i=i+1) s+=i; s",        1000},
    {"loop 1k",         "let s=0; for(let i=0;i<1000;i=i+1) s+=i; s",        100},
    {"fib(15)",         "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(15)", 20},
    {"array push 100",  "let a=[]; for(let i=0;i<100;i=i+1) a.push(i); a.length", 200},
};

int main(int argc, char **argv) {
    const char *only = (argc > 1) ? argv[1] : NULL;

    g_cat_enabled = 1;

    for (size_t w = 0; w < sizeof(WORKLOADS)/sizeof(WORKLOADS[0]); w++) {
        const workload_t *wl = &WORKLOADS[w];
        if (only && strcmp(only, wl->label) != 0) continue;

        printf("\n========================================\n");
        printf("  workload: %s\n", wl->label);
        printf("========================================\n");

        cat_reset();

        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        /* warmup */
        for (int i = 0; i < 3; i++) flywheel_eval(I, wl->src, "<w>");

        for (int i = 0; i < wl->iters; i++) {
            FlyResult r = flywheel_eval(I, wl->src, "<p>");
            (void)r;
        }
        flywheel_free(I);

        cat_dump();
    }

    g_cat_enabled = 0;
    return 0;
}
