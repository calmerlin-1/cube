/* tracetime.c — instrument every operation, print per-step timing.
 * Each unique program measured in isolation, plus breakdown by
 * phase: lex, parse, eval, teardown. */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../include/interp.h"
#include "../include/parser.h"
#include "../include/lexer.h"
#include "../include/ast.h"

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

/* ---------- step-by-step timing of one full eval ---------- */
static void trace(const char *label, const char *src) {
    printf("\n### %s\n", label);
    printf("src: %.80s%s\n", src, strlen(src) > 80 ? "..." : "");

    double t0 = now_us();
    Interp *I = flywheel_new();
    double t1 = now_us();
    flywheel_load_natives(I);
    double t2 = now_us();

    /* lex alone */
    Lexer lx;
    lexer_init(&lx, src);
    int ntok = 0;
    double t3 = now_us();
    while (1) {
        Token tk = lexer_next(&lx);
        ntok++;
        if (tk.kind == TOK_EOF || tk.kind == TOK_ERROR) break;
    }
    double t4 = now_us();

    /* parse alone */
    ParseResult pr = parser_parse_nocache(src, "<t>");
    double t5 = now_us();

    /* eval (parse again inside, but the cached path will be fast) */
    FlyResult r = flywheel_eval(I, src, "<t>");
    double t6 = now_us();

    printf("  flywheel_new:      %8.1f us\n", t1 - t0);
    printf("  load_natives:      %8.1f us\n", t2 - t1);
    printf("  lex only:          %8.1f us (%d tokens)\n", t4 - t3, ntok);
    printf("  parse only:        %8.1f us (%d errors)\n", t5 - t4, pr.nerrors);
    printf("  eval total:        %8.1f us\n", t6 - t5);
    printf("  -----\n");
    printf("  eval actual work:  %8.1f us  (eval - parse, since parse reruns)\n",
           (t6 - t5) - (t5 - t4));
    printf("  total:             %8.1f us\n", t6 - t0);
    printf("  result: ");
    if (r.status == FLY_OK) val_print(r.value);
    else printf("status=%d %s", r.status, r.error_msg);
    printf("\n");

    parser_free_result(&pr);
    ast_free_arena();
    flywheel_free(I);
}

/* ---------- repeated eval to find per-op cost ---------- */
static void repeat(const char *label, const char *src, int reps) {
    Interp *I = flywheel_new();
    flywheel_load_natives(I);

    /* warm up */
    FlyResult r0 = flywheel_eval(I, src, "<warm>");

    double t0 = now_us();
    for (int i = 0; i < reps; i++) {
        FlyResult r = flywheel_eval(I, src, "<rep>");
        (void)r;
    }
    double dt = now_us() - t0;

    printf("  %-30s %6d reps  %10.1f us total  %8.2f us/rep  -> ",
           label, reps, dt, dt / reps);
    if (r0.status == FLY_OK) val_print(r0.value);
    else printf("status=%d", r0.status);
    printf("\n");

    flywheel_free(I);
}

/* ---------- scaling: run same program at N=10,100,1000,10000 ---------- */
static void scaling(const char *label, const char *pattern) {
    printf("\n  %s\n", label);
    printf("  %-8s %-12s %-12s %s\n", "N", "time_us", "per-op_us", "ratio");

    double prev_time = 0;
    int sizes[] = {10, 100, 1000, 10000};
    for (int i = 0; i < 4; i++) {
        char src[256];
        snprintf(src, sizeof(src), pattern, sizes[i]);

        Interp *I = flywheel_new();
        flywheel_load_natives(I);

        double t0 = now_us();
        FlyResult r = flywheel_eval(I, src, "<scale>");
        double dt = now_us() - t0;

        printf("  %-8d %-12.0f %-12.3f",
               sizes[i], dt, dt / sizes[i]);
        if (prev_time > 0) {
            double ratio = (dt / prev_time) / (double)(sizes[i] / sizes[i-1]);
            printf(" %.2fx (1.0 = linear, 10 = quadratic)", ratio);
        }
        printf("\n");

        if (r.status != FLY_OK) printf("    ERROR: %s\n", r.error_msg);
        prev_time = dt;
        flywheel_free(I);
    }
}

int main(void) {
    printf("=========================================================\n");
    printf(" FLYWHEEL TRACE + TIMING\n");
    printf("=========================================================\n");

    /* ---------- 1. single-op trace ---------- */
    printf("\n========== 1. phase breakdown per program ==========\n");
    trace("literal",              "42");
    trace("one add",              "1+2");
    trace("two adds",             "1+2+3");
    trace("ten adds",             "1+2+3+4+5+6+7+8+9+10");
    trace("variable",             "let x=5; x");
    trace("two variables",        "let x=5; let y=6; x+y");
    trace("string concat",        "\"a\"+\"b\"");
    trace("property access",      "({a:1}).a");
    trace("method call",          "[1,2,3].length");
    trace("array push",           "let a=[]; a.push(1); a.length");
    trace("function",             "function f(){return 1;} f()");
    trace("loop 10",              "let s=0;for(let i=0;i<10;i=i+1)s+=i;s");
    trace("loop 100",             "let s=0;for(let i=0;i<100;i=i+1)s+=i;s");

    /* ---------- 2. repeated eval, hot path ---------- */
    printf("\n========== 2. repeated eval (same source) ==========\n");
    repeat("literal 42",          "42",                      10000);
    repeat("1+2",                 "1+2",                     10000);
    repeat("let x=5; x",          "let x=5; x",              10000);
    repeat("array push x10",      "let a=[]; for(let i=0;i<10;i=i+1) a.push(i); a.length", 1000);
    repeat("loop 10",             "let s=0;for(let i=0;i<10;i=i+1)s+=i;s", 1000);
    repeat("loop 100",            "let s=0;for(let i=0;i<100;i=i+1)s+=i;s", 100);
    repeat("fib(10)",             "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(10)", 100);
    repeat("property chain",      "({a:{b:{c:{d:1}}}}).a.b.c.d", 1000);
    repeat("string method",       "\"abc\".toUpperCase()", 1000);

    /* ---------- 3. scaling ---------- */
    printf("\n========== 3. scaling (linear = good, quadratic = bad) ==========\n");
    scaling("arithmetic chain",
            "let s=0; s=1+2+3+4+5+6+7+8+9+10; s");
    scaling("loop sum",
            "let s=0; for(let i=0;i<%d;i=i+1) s+=i; s");
    scaling("array push",
            "let a=[]; for(let i=0;i<%d;i=i+1) a.push(i); a.length");
    scaling("string concat",
            "let s=''; for(let i=0;i<%d;i=i+1) s=s+'x'; s.length");
    scaling("fib scaling",
            "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(%d)");

    /* ---------- 4. unique ops ---------- */
    printf("\n========== 4. unique op isolation ==========\n");
    repeat("empty program",       "",                        10000);
    repeat("single ident",        "undefined",               10000);
    repeat("single number",       "0",                       10000);
    repeat("single string",       "\"\"",                    10000);
    repeat("single object",       "({})",                    10000);
    repeat("single array",        "[]",                      10000);
    repeat("single template",     "``",                      10000);
    repeat("let+nothing",         "let x",                   10000);
    repeat("4 var decls",         "let a=1;let b=2;let c=3;let d=4", 10000);
    repeat("20 var decls",
           "let a1=1;let a2=2;let a3=3;let a4=4;let a5=5;"
           "let a6=6;let a7=7;let a8=8;let a9=9;let a10=10;"
           "let a11=11;let a12=12;let a13=13;let a14=14;let a15=15;"
           "let a16=16;let a17=17;let a18=18;let a19=19;let a20=20;"
           "a1+a2+a3+a4+a5+a6+a7+a8+a9+a10+a11+a12+a13+a14+a15+a16+a17+a18+a19+a20",
           1000);
    repeat("nested objects",
           "({a:{b:{c:{d:{e:1}}}}}).a.b.c.d.e", 1000);
    repeat("chained string methods",
           "\"hello\".toUpperCase().toLowerCase().toUpperCase()", 1000);
    repeat("try no throw",        "try{1}catch(e){2}",       10000);
    repeat("throw+catch",         "try{throw 1}catch(e){e}", 10000);
    repeat("closure",
           "function c(){let n=0;return function(){n=n+1;return n;};}let x=c();x();x()", 1000);

    return 0;
}
