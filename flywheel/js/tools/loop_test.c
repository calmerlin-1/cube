#include <stdio.h>
#include <time.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    FlyResult r = flywheel_eval(I,
        "let x = 0; for (let i = 0; i < 5000; i = i + 1) x = x + 1; x",
        "<t>");
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec-t0.tv_sec)*1000.0 + (t1.tv_nsec-t0.tv_nsec)/1e6;
    printf("status=%d value=", r.status);
    if (r.status == FLY_OK) val_print(r.value);
    printf(" time=%.1f ms\n", ms);
    flywheel_free(I);
    return 0;
}
