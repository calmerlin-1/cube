#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include "../include/interp.h"

/* ============================================================
 * Crash trap — if the engine segfaults, we catch it, print,
 * and jump back to the loop so we can continue with the next test.
 * ============================================================ */
static jmp_buf g_crash_jmp;
static volatile const char *g_current = NULL;
static volatile int g_crashed = 0;

static void crash_handler(int sig) {
    const char *name = (sig == SIGSEGV) ? "SIGSEGV" :
                       (sig == SIGABRT) ? "SIGABRT" :
                       (sig == SIGBUS)  ? "SIGBUS"  :
                       (sig == SIGFPE)  ? "SIGFPE"  : "SIGNAL";
    fprintf(stderr, "\n  [CRASH] %s during: %s\n", name,
            g_current ? g_current : "(unknown)");
    g_crashed = 1;
    longjmp(g_crash_jmp, 1);
}

/* ============================================================
 * Timing helper
 * ============================================================ */
static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

/* ============================================================
 * Test runner — catches crashes, times, records status
 * ============================================================ */
typedef struct {
    const char *label;
    const char *src;
} TestCase;

static int total = 0, ok = 0, perr = 0, rerr = 0, crash = 0;
static double slowest = 0;
static const char *slowest_src = "";

static void run_one(const char *label, const char *src) {
    total++;
    g_current = label;
    g_crashed = 0;

    double t0 = now_us();

    if (setjmp(g_crash_jmp) == 0) {
        Interp *I = flywheel_new();
        if (I) {
            flywheel_load_natives(I);
            FlyResult r = flywheel_eval(I, src, label);
            if (r.status == FLY_OK) ok++;
            else if (r.status == FLY_PARSE_ERROR) perr++;
            else if (r.status == FLY_RUNTIME_ERROR) rerr++;
            else crash++;
            flywheel_free(I);
        } else {
            crash++;
        }
    } else {
        crash++;
    }

    double elapsed = now_us() - t0;
    if (elapsed > slowest) { slowest = elapsed; slowest_src = src; }

    if (elapsed > 100.0 || g_crashed) {
        printf("  [%.0f us] %-40s -> %s\n",
               elapsed, label, g_crashed ? "CRASH" : "slow");
    }
}

/* ============================================================
 * Real JS corpus — programs that real-world code contains
 * ============================================================ */
static const char *REAL_JS[] = {
    /* --- 1. classic algorithms --- */
    "function fib(n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } fib(15)",
    "function fact(n) { if (n <= 1) return 1; return n * fact(n-1); } fact(10)",
    "function gcd(a, b) { while (b) { let t = b; b = a % b; a = t; } return a; } gcd(48, 18)",
    "function isPrime(n) { if (n < 2) return false; for (let i = 2; i * i <= n; i = i + 1) { if (n % i == 0) return false; } return true; } isPrime(97)",
    "let sum = 0; for (let i = 1; i <= 100; i = i + 1) sum += i; sum",
    "let s = 0; for (let i = 0; i < 1000; i = i + 1) { s = s + i * i; } s",

    /* --- 2. string manipulation --- */
    "let s = 'hello world'; let r = ''; for (let i = s.length - 1; i >= 0; i = i - 1) r = r + s.charAt(i); r",
    "let s = 'a,b,c,d'; let parts = 0; for (let i = 0; i < s.length; i = i + 1) { if (s.charAt(i) == ',') parts += 1; } parts + 1",
    "function rev(s) { if (s.length <= 1) return s; return rev(s.slice(1)) + s.charAt(0); } rev('hello')",
    "'hello world'.toUpperCase().toLowerCase().toUpperCase()",

    /* --- 3. array work --- */
    "let a = []; for (let i = 0; i < 20; i = i + 1) a.push(i * i); a.join(',')",
    "let a = [5, 3, 8, 1, 9, 2]; let max = a[0]; for (let i = 1; i < a.length; i = i + 1) { if (a[i] > max) max = a[i]; } max",
    "let a = [5, 3, 8, 1, 9, 2]; let sum = 0; for (let i = 0; i < a.length; i = i + 1) sum += a[i]; sum / a.length",
    "let arr = [1, 2, 3, 4, 5]; let filtered = []; for (let i = 0; i < arr.length; i = i + 1) { if (arr[i] > 2) filtered.push(arr[i]); } filtered.length",
    "function sumTo(n) { let s = 0; for (let i = 1; i <= n; i = i + 1) s += i; return s; } sumTo(50)",
    "function countDown(n) { let out = []; for (let i = n; i > 0; i = i - 1) out.push(i); return out.join('-'); } countDown(10)",

    /* --- 4. objects --- */
    "let p = { name: 'Alice', age: 30 }; p.name + ' is ' + p.age",
    "let o = {}; for (let i = 0; i < 5; i = i + 1) { o['k' + i] = i * i; } o.k3",
    "let config = { debug: true, level: 3, name: 'app' }; config.level * 10",
    "let stack = { items: [], push: function(x) { this.items[this.items.length] = x; }, size: function() { return this.items.length; } }; stack.push(1); stack.push(2); stack.size()",

    /* --- 5. closures & higher-order --- */
    "function makeAdder(x) { return function(y) { return x + y; }; } let add5 = makeAdder(5); add5(10)",
    "function counter() { let n = 0; return function() { n = n + 1; return n; }; } let c = counter(); c(); c(); c()",
    "function apply(f, x) { return f(x); } function double(x) { return x * 2; } apply(double, 21)",

    /* --- 6. recursion trees --- */
    "function ackermann(m, n) { if (m == 0) return n + 1; if (n == 0) return ackermann(m - 1, 1); return ackermann(m - 1, ackermann(m, n - 1)); } ackermann(2, 3)",
    "function power(b, e) { if (e == 0) return 1; if (e % 2 == 0) { let h = power(b, e / 2); return h * h; } return b * power(b, e - 1); } power(2, 20)",

    /* --- 7. exceptions --- */
    "function safeDiv(a, b) { if (b == 0) throw 'divide by zero'; return a / b; } try { safeDiv(10, 2) } catch (e) { -1 }",
    "let r = 0; try { throw 42 } catch (e) { r = e * 2 } r",
    "function check(n) { if (n < 0) throw 'negative'; return n; } let out = 0; try { out = check(-1); } catch (e) { out = -999; } out",

    /* --- 8. mixed real programs --- */
    "function map(arr, f) { let out = []; for (let i = 0; i < arr.length; i = i + 1) out.push(f(arr[i])); return out; } function sq(x) { return x * x; } map([1, 2, 3, 4], sq).join(',')",
    "function filter(arr, pred) { let out = []; for (let i = 0; i < arr.length; i = i + 1) { if (pred(arr[i])) out.push(arr[i]); } return out; } function isEven(n) { return n % 2 == 0; } filter([1, 2, 3, 4, 5, 6], isEven).length",
    "function reduce(arr, f, init) { let acc = init; for (let i = 0; i < arr.length; i = i + 1) acc = f(acc, arr[i]); return acc; } function add(a, b) { return a + b; } reduce([1, 2, 3, 4, 5], add, 0)",

    /* --- 9. pathological for stack/time --- */
    "function deep(n) { if (n == 0) return 0; return deep(n - 1) + 1; } deep(200)",
    "let x = 0; for (let i = 0; i < 5000; i = i + 1) x = x + 1; x",
    "let s = ''; for (let i = 0; i < 500; i = i + 1) s = s + 'x'; s.length",
    "let a = []; for (let i = 0; i < 1000; i = i + 1) a.push(i); a.length",

    /* --- 10. template heavy --- */
    "let name = 'world'; `hello ${name}`",
    "let a = 1; let b = 2; `${a} + ${b} = ${a + b}`",
    "let result = ''; for (let i = 1; i <= 5; i = i + 1) result = result + `${i},`; result",
};

/* ============================================================
 * C-level fuzz — random bytes (includes nulls and 0x80+ bytes)
 * ============================================================ */
static void fuzz_bytes(int N, int max_len) {
    unsigned char *buf = malloc(max_len + 1);
    if (!buf) return;
    for (int i = 0; i < N; i++) {
        int len = 1 + rand() % max_len;
        for (int j = 0; j < len; j++) {
            buf[j] = (unsigned char)(rand() & 0xFF);
        }
        buf[len] = 0;
        /* skip inputs with embedded nulls for eval but note we tested them */
        g_current = "fuzz-bytes";
        g_crashed = 0;
        if (setjmp(g_crash_jmp) == 0) {
            Interp *I = flywheel_new();
            if (I) {
                flywheel_load_natives(I);
                FlyResult r = flywheel_eval(I, (const char *)buf, "<bytes>");
                (void)r;
                flywheel_free(I);
            }
        } else {
            crash++;
        }
    }
    free(buf);
}

/* ============================================================
 * Structured fuzz — random JS-ish tokens
 * ============================================================ */
static const char *TOKENS[] = {
    "function","if","else","for","while","return","let","var","const",
    "class","new","typeof","delete","in","instanceof",
    "try","catch","finally","throw","switch","case","default","break","continue",
    "async","await","yield",
    "{","}","(",")","[","]",";",",",".","=>","...",
    "=","+=","-=","*=","/=","==","===","!=","!==","<",">","<=",">=",
    "+","-","*","/","%","**","&&","||","??","!","~","&","|","^",
    "?","?:",":","?.",
    "`","${","}","\"","'",
    "a","b","c","x","y","z","foo","bar","baz","this","super",
    "0","1","2","3","42","100","3.14","0xFF","1e10","true","false","null","undefined",
    " ","\n","\t","//comment\n","/* block */",
};
static const int NTOK = sizeof(TOKENS) / sizeof(TOKENS[0]);

static void fuzz_tokens(int N) {
    char buf[512];
    for (int i = 0; i < N; i++) {
        int n = 1 + rand() % 30;
        buf[0] = 0;
        size_t pos = 0;
        for (int j = 0; j < n && pos < sizeof(buf) - 40; j++) {
            const char *t = TOKENS[rand() % NTOK];
            size_t l = strlen(t);
            memcpy(buf + pos, t, l);
            pos += l;
            if (rand() % 3 == 0) buf[pos++] = ' ';
            buf[pos] = 0;
        }
        g_current = "fuzz-tokens";
        g_crashed = 0;
        if (setjmp(g_crash_jmp) == 0) {
            Interp *I = flywheel_new();
            if (I) {
                flywheel_load_natives(I);
                FlyResult r = flywheel_eval(I, buf, "<tok>");
                if (r.status == FLY_OK) ok++;
                else if (r.status == FLY_PARSE_ERROR) perr++;
                else if (r.status == FLY_RUNTIME_ERROR) rerr++;
                else crash++;
                flywheel_free(I);
            }
        } else {
            crash++;
        }
        total++;
    }
}

/* ============================================================
 * Instruction trace — for one specific program, print every step
 * ============================================================ */
static void trace_program(const char *src) {
    printf("\n=== TRACE: %s ===\n", src);
    double t0 = now_us();
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    FlyResult r = flywheel_eval(I, src, "<trace>");
    double elapsed = now_us() - t0;
    printf("  status: %d\n", r.status);
    printf("  value:  ");
    if (r.status == FLY_OK) val_print(r.value);
    else printf("ERROR: %s", r.error_msg);
    printf("\n");
    printf("  time:   %.1f us\n", elapsed);
    flywheel_free(I);
}

int main(void) {
    srand((unsigned)time(NULL));

    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGBUS,  crash_handler);
    signal(SIGFPE,  crash_handler);

    printf("========================================\n");
    printf(" FLYWHEEL HARDCORE TEST\n");
    printf("========================================\n\n");

    /* ---- 1. Real JS corpus ---- */
    printf("--- 1. Real JS corpus (%d programs) ---\n",
           (int)(sizeof(REAL_JS)/sizeof(REAL_JS[0])));
    double t_all_start = now_us();
    for (size_t i = 0; i < sizeof(REAL_JS)/sizeof(REAL_JS[0]); i++) {
        char label[32];
        snprintf(label, sizeof(label), "real-%zu", i);
        double t0 = now_us();
        run_one(label, REAL_JS[i]);
        double t1 = now_us();
        if (t1 - t0 > 5000.0) {
            printf("  [SLOW %.0f us] %s\n", t1 - t0, REAL_JS[i]);
        }
    }
    double t_all_end = now_us();
    printf("  Real corpus total: %.1f ms\n", (t_all_end - t_all_start) / 1000.0);

    /* ---- 2. Structured token fuzz ---- */
    printf("\n--- 2. Structured token fuzz (2000 inputs) ---\n");
    int before_total = total, before_crash = crash;
    fuzz_tokens(2000);
    printf("  fuzz_tokens: %d inputs, %d crashes\n",
           total - before_total, crash - before_crash);

    /* ---- 3. Byte-level fuzz ---- */
    printf("\n--- 3. Byte-level fuzz (1000 inputs, random bytes) ---\n");
    before_crash = crash;
    fuzz_bytes(1000, 80);
    printf("  fuzz_bytes: 1000 inputs, %d crashes\n", crash - before_crash);

    /* ---- 4. Instruction-level traces on selected programs ---- */
    printf("\n--- 4. Instruction traces ---\n");
    trace_program("1 + 2");
    trace_program("let x = 5; x * 2");
    trace_program("function f(n) { if (n < 2) return n; return f(n-1) + f(n-2); } f(10)");
    trace_program("let a = [1,2,3,4,5]; let s = 0; for (let i = 0; i < a.length; i = i + 1) s += a[i]; s");
    trace_program("try { throw 'x' } catch (e) { e + '!' }");
    trace_program("`hello ${1+2}`");

    /* ---- 5. Summary ---- */
    printf("\n========================================\n");
    printf(" TOTAL:          %d\n", total);
    printf(" OK:             %d\n", ok);
    printf(" PARSE_ERROR:    %d\n", perr);
    printf(" RUNTIME_ERROR:  %d\n", rerr);
    printf(" CRASH:          %d\n", crash);
    printf(" SLOWEST (us):   %.0f\n", slowest);
    printf("========================================\n");

    return crash > 0 ? 1 : 0;
}
