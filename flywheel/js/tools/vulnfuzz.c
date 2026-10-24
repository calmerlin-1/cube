/* flywheel/build/vulnfuzz.c
 *
 * Aggressive vulnerability fuzzer. Every test runs under signal traps
 * for SIGSEGV / SIGABRT / SIGBUS / SIGFPE. Every phase is timed
 * separately. Every crash is logged with the exact input.
 *
 * Purpose: find every input that makes flywheel crash, hang, or
 * misbehave. Report timing for each phase so we see where time goes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/resource.h>
#include "../include/interp.h"

/* ============================================================ */
/* Crash trap                                                   */
/* ============================================================ */
static jmp_buf g_jmp;
static volatile const char *g_cur = "(idle)";
static volatile int g_crashed = 0;
static volatile int g_sig = 0;

static void trap(int sig) {
    g_crashed = 1;
    g_sig = sig;
    longjmp(g_jmp, 1);
}

/* ============================================================ */
/* Timing                                                       */
/* ============================================================ */
static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

/* ============================================================ */
/* Stats                                                        */
/* ============================================================ */
typedef struct {
    const char *name;
    int total;
    int ok;
    int perr;
    int rerr;
    int crash;
    int hang;
    double total_us;
    double slowest_us;
    char slowest_src[256];
} Phase;

static void phase_start(Phase *p, const char *name) {
    memset(p, 0, sizeof(*p));
    p->name = name;
    printf("\n=== %s ===\n", name);
    fflush(stdout);
}

static void phase_end(Phase *p) {
    printf("  -- summary --\n");
    printf("  total:    %d\n", p->total);
    printf("  ok:       %d\n", p->ok);
    printf("  parse:    %d\n", p->perr);
    printf("  runtime:  %d\n", p->rerr);
    printf("  crash:    %d\n", p->crash);
    printf("  hang:     %d\n", p->hang);
    printf("  time:     %.1f ms\n", p->total_us / 1000.0);
    if (p->total > 0) {
        printf("  avg/test: %.1f us\n", p->total_us / p->total);
    }
    printf("  slowest:  %.0f us\n", p->slowest_us);
    if (p->slowest_us > 1000) {
        printf("  slowest input: %.200s\n", p->slowest_src);
    }
    fflush(stdout);
}

/* Run one input with a 3-second alarm. */
static void run_input(Phase *p, const char *label, const char *src) {
    p->total++;
    g_cur = label;
    g_crashed = 0;
    g_sig = 0;

    /* Copy slowest source for later */
    if (strlen(src) < sizeof(p->slowest_src)) {
        strcpy(p->slowest_src, src);
    }

    /* Set alarm to catch hangs */
    alarm(3);

    double t0 = now_us();

    if (setjmp(g_jmp) == 0) {
        Interp *I = flywheel_new();
        if (I) {
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, src, label);
            flywheel_free(I);
            switch (r.status) {
            case FLY_OK:            p->ok++; break;
            case FLY_PARSE_ERROR:   p->perr++; break;
            case FLY_RUNTIME_ERROR: p->rerr++; break;
            default:                p->crash++; break;
            }
        } else {
            p->crash++;
        }
    } else {
        /* caught a signal */
        p->crash++;
        printf("  [CRASH sig=%d] %s\n", g_sig, src);
        fflush(stdout);
    }

    double elapsed = now_us() - t0;
    p->total_us += elapsed;
    if (elapsed > p->slowest_us) {
        p->slowest_us = elapsed;
        if (strlen(src) < sizeof(p->slowest_src)) {
            strcpy(p->slowest_src, src);
        }
    }
    alarm(0);

    /* Report any individual test over 5 ms */
    if (elapsed > 5000) {
        printf("  [SLOW %.0f us] %s\n", elapsed, src);
        fflush(stdout);
    }
}

/* ============================================================ */
/* Phase 1 — real JS programs, timed one by one                 */
/* ============================================================ */
static void phase_real_programs(void) {
    Phase p;
    phase_start(&p, "Phase 1: real JS programs");

    static const char *progs[] = {
        "1 + 2",
        "let x = 5; x * 2",
        "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(10)",
        "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(20)",
        "let s = 0; for (let i = 0; i < 1000; i = i + 1) s += i; s",
        "let s = 0; for (let i = 0; i < 10000; i = i + 1) s += i; s",
        "function mk(x){return function(y){return x+y;};} let a=mk(5); a(10)",
        "function c(){let n=0;return function(){n=n+1;return n;};} let x=c(); x(); x(); x()",
        "function d(n){if(n==0)return 0;return d(n-1)+1;} d(500)",
        "function d(n){if(n==0)return 0;return d(n-1)+1;} d(1000)",
        "let a=[]; for (let i=0;i<1000;i=i+1) a.push(i); a.length",
        "let a=[]; for (let i=0;i<5000;i=i+1) a.push(i); a.length",
        "let s=''; for (let i=0;i<500;i=i+1) s=s+'x'; s.length",
        "let s=''; for (let i=0;i<2000;i=i+1) s=s+'x'; s.length",
        "let o = {a: 1, b: 2, c: 3}; o.a + o.b + o.c",
        "[1,2,3,4,5].join('-')",
        "[1,2,3].push(4)",
        "Math.max(1,2,3,4,5)",
        "JSON.stringify({x:1,y:2,z:[1,2,3]})",
        "`hello ${1+2} ${3*4}`",
    };
    int n = sizeof(progs) / sizeof(progs[0]);
    for (int i = 0; i < n; i++) {
        char label[32];
        snprintf(label, sizeof(label), "real-%02d", i);
        double t0 = now_us();
        run_input(&p, label, progs[i]);
        double dt = now_us() - t0;
        printf("  [%7.0f us] %s\n", dt, progs[i]);
        fflush(stdout);
    }
    phase_end(&p);
}

/* ============================================================ */
/* Phase 2 — structured token fuzz                              */
/* ============================================================ */
static void phase_token_fuzz(int N) {
    Phase p;
    phase_start(&p, "Phase 2: structured token fuzz");

    static const char *TOK[] = {
        "function","if","else","for","while","return","let","var","const",
        "class","new","typeof","delete","in","instanceof","of",
        "try","catch","finally","throw","switch","case","default","break","continue",
        "async","await","yield","static","get","set","extends","super",
        "{","}","(",")","[","]",";",",",".","=>","...",
        "=","+=","-=","*=","/=","==","===","!=","!==","<",">","<=",">=",
        "+","-","*","/","%","**","&&","||","??","!","~","&","|","^",
        "?","?:",":","?.",
        "`","${","\"","'","/","//",
        "a","b","c","x","y","z","foo","bar","baz","this",
        "0","1","2","42","100","3.14","0xFF","1e10",
        "true","false","null","undefined","NaN","Infinity",
        " ","\n","\t","//comment\n","/* c */",
    };
    int NT = sizeof(TOK) / sizeof(TOK[0]);

    for (int i = 0; i < N; i++) {
        char buf[512];
        size_t pos = 0;
        int ntok = 1 + rand() % 25;
        for (int j = 0; j < ntok && pos < sizeof(buf) - 40; j++) {
            const char *t = TOK[rand() % NT];
            size_t l = strlen(t);
            memcpy(buf + pos, t, l);
            pos += l;
            if (rand() % 4 == 0) buf[pos++] = ' ';
            buf[pos] = 0;
        }
        char label[32];
        snprintf(label, sizeof(label), "tok-%04d", i);
        run_input(&p, label, buf);
    }
    phase_end(&p);
}

/* ============================================================ */
/* Phase 3 — byte fuzz (raw random bytes, no printable guarantee) */
/* ============================================================ */
static void phase_byte_fuzz(int N, int max_len) {
    Phase p;
    phase_start(&p, "Phase 3: byte fuzz");

    unsigned char *buf = malloc(max_len + 2);
    if (!buf) { printf("  cannot alloc\n"); return; }

    for (int i = 0; i < N; i++) {
        int len = 1 + rand() % max_len;
        for (int j = 0; j < len; j++) {
            buf[j] = (unsigned char)(rand() & 0xFF);
        }
        buf[len] = 0;
        /* Skip if it contains embedded nulls in the middle */
        for (int j = 0; j < len; j++) {
            if (buf[j] == 0) buf[j] = 'a';
        }
        char label[32];
        snprintf(label, sizeof(label), "byte-%04d", i);
        run_input(&p, label, (const char *)buf);
    }
    free(buf);
    phase_end(&p);
}

/* ============================================================ */
/* Phase 4 — adversarial structured patterns                    */
/* ============================================================ */
static void phase_adversarial(void) {
    Phase p;
    phase_start(&p, "Phase 4: adversarial patterns");

    static const char *cases[] = {
        /* deeply nested */
        "((((((((((((((((((((1))))))))))))))))))))",
        "[[[[[[[[[[1]]]]]]]]]]",
        "{{{{{{a:1}}}}}}",
        "!!!!!!!!!!!!!!!!!!1",
        "----------1",
        "++++++++++1",
        "~~~~~~~~~~1",
        /* long chains */
        "1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1",
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z",
        "f(f(f(f(f(f(f(f(f(f(f(f(f(f(f(f(f(1))))))))))))))))))",
        /* empty everything */
        "", " ", "\n", "\t", "//", "/*", "/**/", ";;;", ",,,", ")))", "{{{",
        /* unterminated */
        "\"abc", "'abc", "`abc", "`abc${", "/*comment", "//comment",
        "function f(", "if (", "[1,2,3", "({a:1", "class X {",
        /* operators */
        "++++++++++", "==========", "===========", "!!!", "&&&", "|||",
        "=>=>=>", "......", ",,,,,,", ";;;;;;", "??????", ":::::",
        /* mixed */
        "let x = let y = let z = 1",
        "function function function",
        "if if if",
        "return return return",
        "1 ? 2 ? 3 ? 4 : 5 : 6 : 7",
        "1 ? 2 : 3 ? 4 : 5",
        "true ? 1 : false ? 2 : 3",
        /* pathological numbers */
        "1e999", "1e-999", "0xFFFFFFFFFFFFFFFFFFFF",
        "999999999999999999999999999999",
        "0.00000000000000000000000001",
        /* pathological strings */
        "\"\\n\\t\\r\\0\"",
        "\"\\u0041\"",
        "\"日本語\"",
        "\"🔥🔥🔥\"",
        /* templates */
        "`${`${`${1}`}`}`",
        "`${\"nested\"}`",
        "`${1}${2}${3}${4}${5}`",
        /* call patterns */
        "5()",
        "null()",
        "undefined()",
        "\"str\"()",
        "({})()",
        "[]()",
        "0..toString()",
        "(5).toString()",
        /* property access */
        "null.foo",
        "undefined.foo",
        "(5).foo",
        "\"abc\".foo",
        "true.foo",
        /* throws */
        "throw 1",
        "throw null",
        "throw undefined",
        "throw {a:1}",
        "throw [1,2,3]",
        "throw function(){}",
        /* try patterns */
        "try {} finally {}",
        "try { throw 1 } finally {}",
        "try { throw 1 } catch(e) {} finally {}",
        /* weird but valid */
        "let _ = 1; let $ = 2; let x1 = 3; _ + $ + x1",
        "let a=1, b=2, c=3; a+b+c",
        "(function(){ return 42; })()",
        "(() => 42)()",
        "(x => x * 2)(21)",
        "(function named(){ return named; })",
    };
    int n = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < n; i++) {
        char label[32];
        snprintf(label, sizeof(label), "adv-%02d", i);
        double t0 = now_us();
        run_input(&p, label, cases[i]);
        double dt = now_us() - t0;
        if (dt > 1000) {
            printf("  [%7.0f us] %s\n", dt, cases[i]);
            fflush(stdout);
        }
    }
    phase_end(&p);
}

/* ============================================================ */
/* Phase 5 — long-running programs, timed                       */
/* ============================================================ */
static void phase_perf(void) {
    Phase p;
    phase_start(&p, "Phase 5: performance probes");

    static struct { const char *label; const char *src; } probes[] = {
        {"1 add",           "1+2"},
        {"10 adds",         "1+2+3+4+5+6+7+8+9+10"},
        {"100 adds",        "1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20+21+22+23+24+25+26+27+28+29+30+31+32+33+34+35+36+37+38+39+40+41+42+43+44+45+46+47+48+49+50+51+52+53+54+55+56+57+58+59+60+61+62+63+64+65+66+67+68+69+70+71+72+73+74+75+76+77+78+79+80+81+82+83+84+85+86+87+88+89+90+91+92+93+94+95+96+97+98+99+100"},
        {"loop 100",        "let s=0; for(let i=0;i<100;i=i+1) s+=i; s"},
        {"loop 1k",         "let s=0; for(let i=0;i<1000;i=i+1) s+=i; s"},
        {"loop 10k",        "let s=0; for(let i=0;i<10000;i=i+1) s+=i; s"},
        {"loop 100k",       "let s=0; for(let i=0;i<100000;i=i+1) s+=i; s"},
        {"fib(15)",         "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(15)"},
        {"fib(20)",         "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(20)"},
        {"fib(24)",         "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(24)"},
        {"array push 1k",   "let a=[]; for(let i=0;i<1000;i=i+1) a.push(i); a.length"},
        {"array push 10k",  "let a=[]; for(let i=0;i<10000;i=i+1) a.push(i); a.length"},
        {"string concat 500", "let s=''; for(let i=0;i<500;i=i+1) s=s+'x'; s.length"},
        {"string concat 2k",  "let s=''; for(let i=0;i<2000;i=i+1) s=s+'x'; s.length"},
        {"deep 500",        "function d(n){if(n==0)return 0;return d(n-1)+1;} d(500)"},
        {"deep 1000",       "function d(n){if(n==0)return 0;return d(n-1)+1;} d(1000)"},
    };
    int n = sizeof(probes) / sizeof(probes[0]);
    printf("  %-22s %-10s %-10s\n", "label", "time_us", "result");
    for (int i = 0; i < n; i++) {
        double t0 = now_us();
        int ok = 0;
        char result[64] = "";

        g_cur = probes[i].label;
        g_crashed = 0;
        alarm(10);
        if (setjmp(g_jmp) == 0) {
            Interp *I = flywheel_new();
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, probes[i].src, probes[i].label);
            if (r.status == FLY_OK) {
                ok = 1;
                snprintf(result, sizeof(result), "%s", val_to_cstr(r.value));
            } else {
                snprintf(result, sizeof(result), "ERR:%d", r.status);
            }
            flywheel_free(I);
        } else {
            snprintf(result, sizeof(result), "CRASH sig=%d", g_sig);
        }
        alarm(0);
        double dt = now_us() - t0;
        printf("  %-22s %-10.0f %s\n", probes[i].label, dt, result);
        fflush(stdout);
        p.total++;
        p.total_us += dt;
        if (dt > p.slowest_us) {
            p.slowest_us = dt;
            snprintf(p.slowest_src, sizeof(p.slowest_src), "%s", probes[i].label);
        }
        if (!ok) p.crash++;
    }
    phase_end(&p);
}

/* ============================================================ */
/* Main                                                         */
/* ============================================================ */
int main(void) {
    srand((unsigned)time(NULL));

    signal(SIGSEGV, trap);
    signal(SIGABRT, trap);
    signal(SIGBUS,  trap);
    signal(SIGFPE,  trap);

    printf("#################################################\n");
    printf("#  FLYWHEEL VULNERABILITY FUZZ\n");
    printf("#  date: %s", ctime(&(time_t){time(NULL)}));
    printf("#################################################\n");

    double t0 = now_us();
    phase_real_programs();
    phase_token_fuzz(3000);
    phase_byte_fuzz(2000, 80);
    phase_adversarial();
    phase_perf();
    double t_all = now_us() - t0;

    printf("\n#################################################\n");
    printf("#  TOTAL TIME: %.1f ms\n", t_all / 1000.0);
    printf("#################################################\n");

    return 0;
}
