#include <stdio.h>
#include <time.h>
#include "../include/interp.h"
static double now_us(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}
static void probe(const char *label, const char *src) {
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    double t0 = now_us();
    FlyResult r = flywheel_eval(I, src, label);
    double dt = now_us() - t0;
    printf("  %-30s %10.0f us   ", label, dt);
    if (r.status == FLY_OK) val_print(r.value);
    else printf("status=%d", r.status);
    printf("\n");
    flywheel_free(I);
}
int main(void) {
    probe("push 100",   "let a=[]; for(let i=0;i<100;i=i+1) a.push(i); a.length");
    probe("push 1k",    "let a=[]; for(let i=0;i<1000;i=i+1) a.push(i); a.length");
    probe("push 10k",   "let a=[]; for(let i=0;i<10000;i=i+1) a.push(i); a.length");
    probe("push 100k",  "let a=[]; for(let i=0;i<100000;i=i+1) a.push(i); a.length");
    probe("deep 500",   "function d(n){if(n==0)return 0;return d(n-1)+1;} d(500)");
    probe("deep 1000",  "function d(n){if(n==0)return 0;return d(n-1)+1;} d(1000)");
    probe("deep 1900",  "function d(n){if(n==0)return 0;return d(n-1)+1;} d(1900)");
    probe("fib 20",     "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(20)");
    probe("fib 24",     "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(24)");
    probe("loop 10k",   "let s=0; for(let i=0;i<10000;i=i+1) s+=i; s");
    probe("loop 100k",  "let s=0; for(let i=0;i<100000;i=i+1) s+=i; s");
    probe("loop 1M",    "let s=0; for(let i=0;i<1000000;i=i+1) s+=i; s");
    return 0;
}
