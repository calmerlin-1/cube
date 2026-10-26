/* fulltrace.c — every category of test, detailed trace per category.
 * For each test: what it does, time, memory before/after, result,
 * exit code, and any anomaly. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/resource.h>
#include "../include/interp.h"
#include "../include/parser.h"
#include "../include/lexer.h"

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
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
}

static jmp_buf g_jmp;
static volatile int g_sig = 0;
static void trap(int s) { g_sig = s; longjmp(g_jmp, 1); }

/* Category 1: LEXER only                                       */
static void cat_lexer(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 1: LEXER\n");
    printf("========================================\n");

    struct { const char *label; const char *src; int expect_tokens; } tests[] = {
        {"empty",         "",                       1},
        {"one token",     "42",                     2},
        {"ident",         "foo",                    2},
        {"keyword",       "let",                    2},
        {"operator",      "==",                     2},
        {"string",        "\"hi\"",                 2},
        {"template",      "`x`",                    2},
        {"template sub",  "`a${1}b`",               6},
        {"nested tmpl",   "`a${`b${1}`}c`",         11},
        {"regex",         "/abc/g",                 2},
        {"hex number",    "0xFF",                   2},
        {"float",         "3.14",                   2},
        {"binary",        "0b1010",                 2},
        {"comments",      "//a\n/*b*/42",           2},
        {"unicode ident", "π",                      2},
        {"emoji string",  "\"🔥\"",                 2},
        {"100 idents",    "a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a",  51},
        {"100 numbers",   "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1",  51},
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        long mem_before = mem_kb();
        double t0 = now_us();

        g_sig = 0;
        int ntok = 0;
        if (setjmp(g_jmp) == 0) {
            Lexer lx;
            lexer_init(&lx, tests[i].src);
            while (1) {
                Token tk = lexer_next(&lx);
                ntok++;
                if (tk.kind == TOK_EOF || tk.kind == TOK_ERROR) break;
            }
        }

        double dt = now_us() - t0;
        long mem_after = mem_kb();

        printf("  %-16s %7.1f us  %4ld KB -> %4ld KB  tokens=%d",
               tests[i].label, dt, mem_before, mem_after, ntok);
        if (g_sig) printf("  SIG=%d", g_sig);
        if (tests[i].expect_tokens && ntok != tests[i].expect_tokens)
            printf("  [expect=%d]", tests[i].expect_tokens);
        printf("\n");
    }
}

/* Category 2: PARSER only                                      */
static void cat_parser(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 2: PARSER\n");
    printf("========================================\n");

    struct { const char *label; const char *src; int expect_errs; } tests[] = {
        {"literal",       "42",                              0},
        {"add",           "1+2",                             0},
        {"let",           "let x=5",                         0},
        {"function",      "function f(){return 1;}",         0},
        {"if/else",       "if(1)2;else 3",                   0},
        {"loop",          "for(let i=0;i<10;i=i+1){}",       0},
        {"array",         "[1,2,3]",                         0},
        {"object",        "({a:1,b:2})",                     0},
        {"template",      "`x=${1}`",                        0},
        {"try/catch",     "try{}catch(e){}",                 0},
        {"class",         "class A{}",                       0},
        {"arrow",         "x=>x*2",                          0},
        {"destructure",   "let {a}=b",                       0},
        {"nested object", "({a:{b:{c:{d:1}}}})",             0},
        {"bad syntax 1",  "let x=",                          1},
        {"bad syntax 2",  "function f(",                     1},
        {"bad syntax 3",  "if(",                             1},
        {"bad syntax 4",  "1+",                              1},
        {"bad syntax 5",  "[1,2,",                           1},
        {"deep nest 50",  "((((((((((((((((((((((((((((((((((((((((((((((((1))))))))))))))))))))))))))))))))))))))))))))))))",  0},
        {"real fib",      "function f(n){if(n<2)return n;return f(n-1)+f(n-2);}f(10)", 0},
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        long mem_before = mem_kb();
        double t0 = now_us();

        g_sig = 0;
        int nerrs = -1;
        if (setjmp(g_jmp) == 0) {
            ParseResult r = parser_parse(tests[i].src, "<t>");
            nerrs = r.nerrors;
            parser_free_result(&r);
            ast_free_arena();
        }

        double dt = now_us() - t0;
        long mem_after = mem_kb();

        printf("  %-16s %7.1f us  %4ld KB -> %4ld KB  errors=%d",
               tests[i].label, dt, mem_before, mem_after, nerrs);
        if (g_sig) printf("  SIG=%d", g_sig);
        if (tests[i].expect_errs >= 0 && nerrs != tests[i].expect_errs)
            printf("  [expect=%d]", tests[i].expect_errs);
        printf("\n");
    }
}

/* Category 3: INTERPRETER — behavior                          */
static void cat_interp(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 3: INTERPRETER BEHAVIOR\n");
    printf("========================================\n");

    struct { const char *label; const char *src; const char *expect; } tests[] = {
        {"arithmetic",       "1+2*3",                              "7"},
        {"string concat",    "\"a\"+\"b\"",                       "ab"},
        {"let + assign",     "let x=5; x=10; x",                  "10"},
        {"if true",          "if(1) 42; else 0",                  "42"},
        {"if false",         "if(0) 42; else 99",                 "99"},
        {"while",            "let i=0;while(i<5)i=i+1;i",         "5"},
        {"for",              "let s=0;for(let i=0;i<10;i=i+1)s+=i;s", "45"},
        {"function",         "function f(x){return x*2;}f(21)",   "42"},
        {"recursion",        "function f(n){if(n<2)return n;return f(n-1)+f(n-2);}f(10)", "55"},
        {"closure",          "function m(x){return function(y){return x+y;};}m(5)(10)", "15"},
        {"array",            "[1,2,3].length",                    "3"},
        {"array push",       "let a=[];a.push(1);a.push(2);a.length", "2"},
        {"array join",       "[1,2,3].join(\"-\")",               "1-2-3"},
        {"object",           "({a:1,b:2}).a",                     "1"},
        {"nested object",    "({a:{b:{c:42}}}).a.b.c",            "42"},
        {"template",         "`x=${5}`",                          "x=5"},
        {"try no throw",     "try{1}catch(e){2}",                 "1"},
        {"try throw+catch",  "try{throw 5}catch(e){e*2}",         "10"},
        {"method call",      "\"hello\".toUpperCase()",           "HELLO"},
        {"math",             "Math.max(1,5,3)",                   "5"},
        {"json",             "JSON.stringify([1,2])",             "[1,2]"},
        {"string length",    "\"hello\".length",                  "5"},
        {"boolean",          "1<2",                               "true"},
        {"nullish",          "null ?? 42",                        "42"},
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    int pass = 0, fail = 0;
    for (int i = 0; i < n; i++) {
        long mem_before = mem_kb();
        double t0 = now_us();

        g_sig = 0;
        char actual[128] = "(crash)";
        if (setjmp(g_jmp) == 0) {
            Interp *I = flywheel_new();
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, tests[i].src, "<t>");
            if (r.status == FLY_OK) {
                snprintf(actual, sizeof(actual), "%s", val_to_cstr(r.value));
            } else {
                snprintf(actual, sizeof(actual), "ERR:%s", r.error_msg);
            }
            flywheel_free(I);
        }

        double dt = now_us() - t0;
        long mem_after = mem_kb();

        int ok = (strcmp(actual, tests[i].expect) == 0);
        if (ok) pass++; else fail++;

        printf("  %-16s %7.1f us  %4ld KB -> %4ld KB  %s  got=%s",
               tests[i].label, dt, mem_before, mem_after,
               ok ? "OK  " : "FAIL", actual);
        if (!ok) printf("  want=%s", tests[i].expect);
        if (g_sig) printf("  SIG=%d", g_sig);
        printf("\n");
    }
    printf("  -----\n  pass=%d fail=%d\n", pass, fail);
}

/* Category 4: MEMORY leak check across many evals              */
static void cat_memory(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 4: MEMORY FOOTPRINT\n");
    printf("========================================\n");

    const char *src = "let a=[1,2,3]; function f(x){return x*2;} f(a[0])+a.length";

    long mem_start = mem_kb();
    double t0 = now_us();

    for (int i = 0; i < 1000; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, src, "<t>");
        (void)r;
        flywheel_free(I);
    }

    double dt = now_us() - t0;
    long mem_end = mem_kb();

    printf("  1000 fresh Interp + eval:\n");
    printf("    total time:   %.1f ms\n", dt / 1000.0);
    printf("    per eval:     %.2f us\n", dt / 1000.0 / 1000.0);
    printf("    memory:       %ld KB -> %ld KB  (delta %+ld KB)\n",
           mem_start, mem_end, mem_end - mem_start);
    if (mem_end - mem_start > 500)
        printf("    [WARN] memory grew by >500 KB — possible leak\n");
    else
        printf("    [OK] memory stable\n");
}

/* Category 5: STRESS on scaling                                */
static void cat_scale(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 5: SCALING\n");
    printf("========================================\n");

    struct { const char *label; const char *fmt; } tests[] = {
        {"loop",  "let s=0;for(let i=0;i<%d;i=i+1)s+=i;s"},
        {"push",  "let a=[];for(let i=0;i<%d;i=i+1)a.push(i);a.length"},
        {"strcat","let s='';for(let i=0;i<%d;i=i+1)s=s+'x';s.length"},
        {"objset","let o={};for(let i=0;i<%d;i=i+1)o.k=i;o.k"},
    };
    int n = sizeof(tests) / sizeof(tests[0]);
    int sizes[] = {100, 1000, 10000};

    for (int t = 0; t < n; t++) {
        printf("  %s:\n", tests[t].label);
        double prev = 0;
        for (int s = 0; s < 3; s++) {
            char src[512];
            snprintf(src, sizeof(src), tests[t].fmt, sizes[s]);

            double t0 = now_us();
            Interp *I = flywheel_new();
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, src, "<s>");
            double dt = now_us() - t0;
            flywheel_free(I);

            printf("    N=%-6d %8.0f us  %.3f us/op",
                   sizes[s], dt, dt / sizes[s]);
            if (prev > 0) {
                double ratio = (dt / prev) / 10.0;
                printf("  ratio=%.2f", ratio);
                if (ratio > 3) printf("  [QUADRATIC]");
            }
            if (r.status != FLY_OK) printf("  ERR:%s", r.error_msg);
            printf("\n");
            prev = dt;
        }
    }
}

/* Category 6: EDGE CASES                                       */
static void cat_edge(void) {
    printf("\n========================================\n");
    printf(" CATEGORY 6: EDGE CASES\n");
    printf("========================================\n");

    struct { const char *label; const char *src; int expect_status; } tests[] = {
        {"empty src",         "",                         0},
        {"just space",        "   ",                      0},
        {"just newline",      "\n",                       0},
        {"just comment",      "// hi",                    0},
        {"one semicolon",     ";",                        0},
        {"empty block",       "{}",                       0},
        {"empty array",       "[]",                       0},
        {"empty object",      "({})",                     0},
        {"empty string",      "\"\"",                     0},
        {"empty template",    "``",                       0},
        {"0 div 0",           "0/0",                      0},
        {"1 div 0",           "1/0",                      0},
        {"neg 1 div 0",       "-1/0",                     0},
        {"NaN compare",       "1/0 > 5",                  0},
        {"undefined ident",   "undefined",                0},
        {"null prop",         "null.x",                   2},
        {"undef prop",        "undefined.x",              2},
        {"call number",       "5()",                      2},
        {"call string",       "\"x\"()",                  2},
        {"unterminated str",  "\"abc",                    1},
        {"unterminated tmpl", "`abc",                     1},
        {"bad token",         "@#$%",                     1},
        {"deep parens 500",   "((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))", 0},
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    int crashed = 0;
    for (int i = 0; i < n; i++) {
        double t0 = now_us();
        g_sig = 0;
        int status = -1;
        if (setjmp(g_jmp) == 0) {
            Interp *I = flywheel_new();
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, tests[i].src, "<t>");
            status = r.status;
            flywheel_free(I);
        }
        double dt = now_us() - t0;

        const char *status_name =
            status == 0 ? "OK" :
            status == 1 ? "PARSE_ERR" :
            status == 2 ? "RUNTIME_ERR" :
            status == 3 ? "INTERNAL" : "CRASH";

        printf("  %-18s %7.1f us  %-11s", tests[i].label, dt, status_name);
        if (g_sig) printf("  SIG=%d", g_sig);
        printf("\n");
        if (g_sig) crashed++;
    }
    printf("  -----\n  crashed: %d\n", crashed);
}

int main(void) {
    signal(SIGSEGV, trap);
    signal(SIGABRT, trap);
    signal(SIGBUS, trap);
    signal(SIGFPE, trap);

    printf("########################################\n");
    printf("#  FLYWHEEL FULL TRACE — every category\n");
    printf("########################################\n");

    cat_lexer();
    cat_parser();
    cat_interp();
    cat_memory();
    cat_scale();
    cat_edge();

    return 0;
}
