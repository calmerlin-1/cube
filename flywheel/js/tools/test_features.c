#include <stdio.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    const char *tests[] = {
        /* --- functions --- */
        "function f(x) { return x * 2; } f(21)",
        "function add(a, b) { return a + b; } add(3, 4)",
        /* --- recursion --- */
        "function fib(n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } fib(10)",
        /* --- closure --- */
        "function outer() { let x = 100; function inner() { return x; } return inner(); } outer()",
        /* --- arrow --- */
        "let f = x => x + 1; f(41)",
        /* --- loops --- */
        "let s = 0; for (let i = 0; i < 5; i = i + 1) { s = s + i; } s",
        "let s = 0; let i = 0; while (i < 5) { s = s + i; i = i + 1; } s",
        "let s = 0; for (let i = 0; i < 10; i = i + 1) { if (i == 5) break; s = s + i; } s",
        "let s = 0; for (let i = 0; i < 5; i = i + 1) { if (i == 2) continue; s = s + i; } s",
        /* --- arrays --- */
        "let a = [1, 2, 3]; a[0]",
        "let a = [1, 2, 3]; a[1] + a[2]",
        "let a = [10, 20, 30]; a.length",
        "let a = []; a[0] = 99; a[0]",
        /* --- objects --- */
        "let o = { a: 1, b: 2 }; o.a",
        "let o = { a: 1, b: 2 }; o.a + o.b",
        "let o = { x: 10 }; o.x = 20; o.x",
        "let o = { a: 1, b: 1 + 1 }; o.b",
        "let x = 5; let o = { x }; o.x",
        "let o = { f() { return 42; } }; o.f()",
        /* --- real program --- */
        "function fib(n) { if (n < 2) return n; return fib(n-1) + fib(n-2); }"
        "let arr = [];"
        "for (let i = 0; i < 10; i = i + 1) { arr[i] = fib(i); }"
        "let total = 0;"
        "for (let i = 0; i < arr.length; i = i + 1) { total = total + arr[i]; }"
        "total",
    };
    int n = sizeof(tests) / sizeof(tests[0]);
    for (int i = 0; i < n; i++) {
        FlyResult r = flywheel_eval(I, tests[i], "<t>");
        printf("[%02d] -> ", i);
        if (r.status == FLY_OK) { val_print(r.value); printf("\n"); }
        else printf("ERROR: %s (line %d col %d)\n",
                    r.error_msg, r.error_line, r.error_column);
    }
    flywheel_free(I);
    return 0;
}
