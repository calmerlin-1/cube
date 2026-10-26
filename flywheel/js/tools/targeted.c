/* targeted.c — is the exact bugs found earlier.
 * Focused tests: memory leak per Interp, array push quadratic,
 * undefined identifier parse-vs-runtime, and any other case flagged. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include "../include/interp.h"

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

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

static jmp_buf jmp;
static volatile int sig = 0;
static void trap(int s) { sig = s; longjmp(jmp, 1); }

/* TARGET 1 — Memory leak: 100 fresh Interp cycles */
static void target_memory(void) {
    printf("\n========================================\n");
    printf(" TARGET 1: Memory leak per Interp\n");
    printf("========================================\n");

    const char *src = "let a=[1,2,3]; function f(x){return x*2;} f(a[0])+a.length";

    /* Warm up */
    for (int i = 0; i < 10; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<w>");
        (void)r;
        flywheel_free(I);
    }

    long m0 = mem_kb();
    double t0 = now_us();

    for (int i = 0; i < 100; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<t>");
        (void)r;
        flywheel_free(I);
    }

    double dt = now_us() - t0;
    long m1 = mem_kb();

    printf("  100 fresh Interp cycles:\n");
    printf("    before:      %ld KB\n", m0);
    printf("    after:       %ld KB\n", m1);
    printf("    delta:       %+ld KB\n", m1 - m0);
    printf("    per Interp:  %+ld bytes\n", (m1 - m0) * 1024 / 100);
    printf("    time total:  %.1f ms\n", dt / 1000.0);
    printf("    time/interp: %.1f us\n", dt / 100.0);

    if (m1 - m0 > 100)
        printf("    [FAIL] leak confirmed: %+ld KB for 100 Interps\n", m1 - m0);
    else
        printf("    [PASS] memory stable across cycles\n");
}

/* TARGET 2 — Array push quadratic scaling */
static void target_push(void) {
    printf("\n========================================\n");
    printf(" TARGET 2: Array push scaling\n");
    printf("========================================\n");

    int sizes[] = {100, 500, 1000, 2000, 5000, 10000};
    int ns = sizeof(sizes) / sizeof(sizes[0]);

    double prev = 0;
    int prev_n = 0;

    for (int i = 0; i < ns; i++) {
        char src[256];
        snprintf(src, sizeof(src),
                 "let a=[]; for(let i=0;i<%d;i=i+1) a.push(i); a.length",
                 sizes[i]);

        Interp *I = flywheel_new();
        flywheel_load_natives(I);

        double t0 = now_us();
        FlyResult r = flywheel_eval(I, src, "<p>");
        double dt = now_us() - t0;
        flywheel_free(I);

        printf("  N=%-6d %9.0f us  %8.3f us/op",
               sizes[i], dt, dt / sizes[i]);
        if (prev > 0) {
            double scale = (double)sizes[i] / prev_n;
            double ratio = (dt / prev) / scale;
            printf("  ratio=%.2f", ratio);
            if (ratio > 2.5) printf("  [SUPER-LINEAR]");
            else if (ratio < 1.5) printf("  [linear]");
        }
        if (r.status != FLY_OK) printf("  ERR:%s", r.error_msg);
        printf("\n");
        prev = dt;
        prev_n = sizes[i];
    }

    /* Isolate: no method call, just index assign */
    printf("\n  Control — no method call:\n");
    prev = 0; prev_n = 0;
    for (int i = 0; i < ns; i++) {
        char src[256];
        snprintf(src, sizeof(src),
                 "let a=[]; for(let i=0;i<%d;i=i+1) a[i]=i; a.length",
                 sizes[i]);

        Interp *I = flywheel_new();
        flywheel_load_natives(I);

        double t0 = now_us();
        FlyResult r = flywheel_eval(I, src, "<p>");
        double dt = now_us() - t0;
        flywheel_free(I);

        printf("  N=%-6d %9.0f us  %8.3f us/op",
               sizes[i], dt, dt / sizes[i]);
        if (prev > 0) {
            double scale = (double)sizes[i] / prev_n;
            double ratio = (dt / prev) / scale;
            printf("  ratio=%.2f", ratio);
            if (ratio > 2.5) printf("  [SUPER-LINEAR]");
            else if (ratio < 1.5) printf("  [linear]");
        }
        printf("\n");
        prev = dt;
        prev_n = sizes[i];
    }

    /* Control 2: user function call */
    printf("\n  Control — user function per iteration:\n");
    prev = 0; prev_n = 0;
    for (int i = 0; i < ns; i++) {
        char src[512];
        snprintf(src, sizeof(src),
                 "function f(x){return x+1;} let s=0; "
                 "for(let i=0;i<%d;i=i+1) s=f(s); s",
                 sizes[i]);

        Interp *I = flywheel_new();
        flywheel_load_natives(I);

        double t0 = now_us();
        FlyResult r = flywheel_eval(I, src, "<p>");
        double dt = now_us() - t0;
        flywheel_free(I);

        printf("  N=%-6d %9.0f us  %8.3f us/op",
               sizes[i], dt, dt / sizes[i]);
        if (prev > 0) {
            double scale = (double)sizes[i] / prev_n;
            double ratio = (dt / prev) / scale;
            printf("  ratio=%.2f", ratio);
            if (ratio > 2.5) printf("  [SUPER-LINEAR]");
            else if (ratio < 1.5) printf("  [linear]");
        }
        printf("\n");
        prev = dt;
        prev_n = sizes[i];
    }
}

/* TARGET 3 — undefined identifier: PARSE vs RUNTIME */
static void target_undefined(void) {
    printf("\n========================================\n");
    printf(" TARGET 3: undefined identifier status\n");
    printf("========================================\n");

    struct { const char *label; const char *src; const char *should_be; } tests[] = {
        {"bare undefined",   "undefined",         "OK (value undefined)"},
        {"undefined prop",   "undefined.x",       "RUNTIME_ERR"},
        {"undefined call",   "undefined()",       "RUNTIME_ERR"},
        {"unknown var",      "notDefined",        "RUNTIME_ERR"},
        {"unknown + 1",      "notDefined + 1",    "RUNTIME_ERR"},
        {"null prop",        "null.x",            "RUNTIME_ERR"},
        {"null call",        "null()",            "RUNTIME_ERR"},
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, tests[i].src, "<u>");

        const char *got =
            r.status == FLY_OK ? "OK" :
            r.status == FLY_PARSE_ERROR ? "PARSE_ERR" :
            r.status == FLY_RUNTIME_ERROR ? "RUNTIME_ERR" : "INTERNAL";

        printf("  %-16s %-12s  got=", tests[i].label, got);
        if (r.status == FLY_OK) val_print(r.value);
        else printf("%s", r.error_msg);
        printf("\n");
        printf("    want: %s\n", tests[i].should_be);
        flywheel_free(I);
    }
}

/* TARGET 4 — Interp setup vs eval cost breakdown */
static void target_setup_cost(void) {
    printf("\n========================================\n");
    printf(" TARGET 4: Where does per-eval time go?\n");
    printf("========================================\n");

    int N = 10000;
    double t0, t1;

    /* A: flywheel_new alone */
    t0 = now_us();
    for (int i = 0; i < N; i++) {
        Interp *I = flywheel_new();
        flywheel_free(I);
    }
    t1 = now_us();
    printf("  flywheel_new + free:          %6.2f us\n", (t1 - t0) / N);

    /* B: + load_natives */
    t0 = now_us();
    for (int i = 0; i < N; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        flywheel_free(I);
    }
    t1 = now_us();
    printf("  + load_natives:               %6.2f us\n", (t1 - t0) / N);

    /* C: + parse + eval of empty */
    t0 = now_us();
    for (int i = 0; i < N; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, "", "<t>");
        (void)r;
        flywheel_free(I);
    }
    t1 = now_us();
    printf("  + empty eval:                 %6.2f us\n", (t1 - t0) / N);

    /* D: + eval of literal */
    t0 = now_us();
    for (int i = 0; i < N; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, "42", "<t>");
        (void)r;
        flywheel_free(I);
    }
    t1 = now_us();
    printf("  + eval 42:                    %6.2f us\n", (t1 - t0) / N);

    /* E: reuse Interp, eval literal (natives already loaded) */
    {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        t0 = now_us();
        for (int i = 0; i < N; i++) {
            FlyResult r = flywheel_eval(I, "42", "<t>");
            (void)r;
        }
        t1 = now_us();
        printf("  reuse Interp, eval 42:        %6.2f us\n", (t1 - t0) / N);
        flywheel_free(I);
    }

    /* F: reuse Interp, eval expression */
    {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        t0 = now_us();
        for (int i = 0; i < N; i++) {
            FlyResult r = flywheel_eval(I, "1+2*3-4/2", "<t>");
            (void)r;
        }
        t1 = now_us();
        printf("  reuse Interp, eval 1+2*3-4/2: %6.2f us\n", (t1 - t0) / N);
        flywheel_free(I);
    }

    /* G: reuse Interp, eval let+assign */
    {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        t0 = now_us();
        for (int i = 0; i < N; i++) {
            FlyResult r = flywheel_eval(I, "let x = 5; x * 2", "<t>");
            (void)r;
        }
        t1 = now_us();
        printf("  reuse Interp, eval let+use:   %6.2f us\n", (t1 - t0) / N);
        flywheel_free(I);
    }
}

int main(void) {
    signal(SIGSEGV, trap);
    signal(SIGABRT, trap);
    signal(SIGBUS, trap);
    signal(SIGFPE, trap);

    printf("########################################\n");
    printf("#  TARGETED TESTS — the bugs found\n");
    printf("########################################\n");

    target_memory();
    target_push();
    target_undefined();
    target_setup_cost();

    return 0;
}
