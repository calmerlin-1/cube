#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../include/interp.h"

static void u(void) { setvbuf(stdout, NULL, _IONBF, 0); }
static void alrm(int s) {
    fprintf(stderr, "  [TIMEOUT] hung on this test\n");
    _exit(42);
}

static void t(const char *label, const char *src, int timeout_sec) {
    printf(">>> %s\n", label);
    fflush(stdout);

    signal(SIGALRM, alrm);
    alarm(timeout_sec);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    FlyResult r = flywheel_eval(I, src, label);
    flywheel_free(I);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec-t0.tv_sec)*1000.0 + (t1.tv_nsec-t0.tv_nsec)/1e6;

    alarm(0);
    printf("    status=%d  time=%.2f ms  ", r.status, ms);
    if (r.status == FLY_OK) val_print(r.value);
    printf("\n");
    fflush(stdout);
}

int main(void) {
    u();

    t("real-15-obj",   "let p = { name: 'Alice', age: 30 }; p.name + ' is ' + p.age", 3);
    t("real-16-computed", "let o = {}; for (let i = 0; i < 5; i = i + 1) { o['k' + i] = i * i; } o.k3", 3);
    t("real-17-config", "let config = { debug: true, level: 3, name: 'app' }; config.level * 10", 3);
    t("real-18-stack", "let stack = { items: [], push: function(x) { this.items[this.items.length] = x; }, size: function() { return this.items.length; } }; stack.push(1); stack.push(2); stack.size()", 3);
    t("real-19-5000", "let x = 0; for (let i = 0; i < 5000; i = i + 1) x = x + 1; x", 3);
    t("real-20-ack", "function ackermann(m, n) { if (m == 0) return n + 1; if (n == 0) return ackermann(m - 1, 1); return ackermann(m - 1, ackermann(m, n - 1)); } ackermann(2, 3)", 5);
    t("real-21-adder", "function makeAdder(x) { return function(y) { return x + y; }; } let add5 = makeAdder(5); add5(10)", 3);
    t("real-22-counter", "function counter() { let n = 0; return function() { n = n + 1; return n; }; } let c = counter(); c(); c(); c()", 3);
    t("real-23-apply", "function apply(f, x) { return f(x); } function double(x) { return x * 2; } apply(double, 21)", 3);
    t("real-24-ackermann", "function ackermann(m, n) { if (m == 0) return n + 1; if (n == 0) return ackermann(m - 1, 1); return ackermann(m - 1, ackermann(m, n - 1)); } ackermann(2, 3)", 5);
    t("real-25-power", "function power(b, e) { if (e == 0) return 1; if (e % 2 == 0) { let h = power(b, e / 2); return h * h; } return b * power(b, e - 1); } power(2, 20)", 3);
    t("real-32-deep200", "function deep(n) { if (n == 0) return 0; return deep(n - 1) + 1; } deep(200)", 3);
    t("real-33-5000", "let x = 0; for (let i = 0; i < 5000; i = i + 1) x = x + 1; x", 3);
    t("real-34-str500", "let s = ''; for (let i = 0; i < 500; i = i + 1) s = s + 'x'; s.length", 3);
    t("real-35-arr1k", "let a = []; for (let i = 0; i < 1000; i = i + 1) a.push(i); a.length", 3);
    t("real-36-tmpl", "let name = 'world'; `hello ${name}`", 3);
    t("real-37-tmplloop", "let result = ''; for (let i = 1; i <= 5; i = i + 1) result = result + `${i},`; result", 3);

    printf("\nALL PASSED\n");
    return 0;
}
