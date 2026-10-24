#include <stdio.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    const char *tests[] = {
        "let x = 5; x",
        "let x = 5; let y = x + 3; y",
        "let x = 1; x = 42; x",
        "let x = 10; x += 5; x",
        "let x = 10; x *= 2; x",
        "const c = 7; c",
        "let x = 100; if (x > 50) { x = 1; } else { x = 2; } x",
        "let x = 10; if (x < 5) { x = 0; } x",
        "let a = 1; let b = 2; { let a = 99; b = a; } b",
        "let n = 0; if (true) { n = 42; } n",
    };
    for (int i = 0; i < 10; i++) {
        FlyResult r = flywheel_eval(I, tests[i], "<t>");
        printf("[%d] %-55s -> ", i, tests[i]);
        if (r.status == FLY_OK) { val_print(r.value); printf("\n"); }
        else printf("ERROR: %s (line %d)\n", r.error_msg, r.error_line);
    }
    flywheel_free(I);
    return 0;
}
