/** fuzz_hard.c — heavy fuzzing: mutations, scaling, deep nesting, chaos. */

#include "../include/css.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <time.h>

static jmp_buf g_jmp;
static volatile int g_sig = 0;

static void trap(int sig) { g_sig = sig; longjmp(g_jmp, 1); }

static int passed = 0, crashed = 0, hung = 0;
static uint64_t total_ns = 0;
static uint64_t slowest_ns = 0;
static char slowest_label[128];
static int verbose_flag = 0;

/* ---- RNG ---- */
static uint64_t rng = 0xC0FFEE1234567890ull;
static uint32_t rnd(void) {
    uint64_t x = rng;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng = x;
    return (uint32_t)(x >> 32);
}

/* ---- one test ---- */
static void run(const char *label, const char *src, size_t len) {
    g_sig = 0;
    void (*old_segv)(int) = signal(SIGSEGV, trap);
    void (*old_abrt)(int) = signal(SIGABRT, trap);
    void (*old_bus)(int)  = signal(SIGBUS, trap);
    (void)old_abrt; (void)old_bus;

    if (setjmp(g_jmp) != 0) {
        printf("  CRASH[%d] %s\n", g_sig, label);
        crashed++;
        signal(SIGSEGV, old_segv);
        return;
    }

    uint64_t t0 = plat_now_ns();
    css_stylesheet_t *ss = css_parse(src, len);
    uint64_t dt = plat_now_ns() - t0;
    css_free(ss);

    total_ns += dt;
    passed++;

    if (dt > slowest_ns) {
        slowest_ns = dt;
        snprintf(slowest_label, sizeof(slowest_label), "%s", label);
    }

    if (verbose_flag || dt > 1000000ull) {
        printf("  %-50s  %10llu ns  len=%zu\n",
               label, (unsigned long long)dt, len);
    }

    signal(SIGSEGV, old_segv);
}

/* ---- 1. byte-level mutation of real CSS ---- */
static const char *BASE_CSS =
    "html, body { margin: 0; padding: 0; font-family: sans-serif; }\n"
    ".container > .row + .row { margin-top: 10px; }\n"
    "a:hover, a:focus { color: #06c; text-decoration: underline; }\n"
    "input[type=\"text\"], input[type=\"email\"] { border: 1px solid #ccc; }\n"
    "@media (min-width: 768px) { .sidebar { width: 250px; } }\n"
    "@keyframes spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }\n"
    "/* end */\n";

static void test_mutations(int n) {
    printf("\n=== BYTE MUTATIONS (%d) ===\n", n);
    size_t base_len = strlen(BASE_CSS);

    for (int i = 0; i < n; i++) {
        char *buf = (char *)malloc(base_len + 1);
        if (!buf) break;
        memcpy(buf, BASE_CSS, base_len + 1);

        int nmut = 1 + (int)(rnd() % 8);
        for (int k = 0; k < nmut; k++) {
            size_t pos = rnd() % base_len;
            buf[pos] = (char)(rnd() & 0xFF);
        }

        char label[64];
        snprintf(label, sizeof(label), "mutate_%04d", i);
        run(label, buf, base_len);
        free(buf);
    }
}

/* ---- 2. token-level structural mutation ---- */
static const char *TOK[] = {
    ".", "#", ":", ";", ",", "{", "}", "(", ")", "[", "]",
    "div", "color", "red", "url(", "\"", "'", "\\",
    "/*", "*/", "@media", "@import", "@", "!important",
    " ", "\n"
};
#define NTOK (sizeof(TOK)/sizeof(TOK[0]))

static void test_structural(int n) {
    printf("\n=== STRUCTURAL FUZZ (%d) ===\n", n);
    for (int i = 0; i < n; i++) {
        char buf[512];
        size_t w = 0;
        int ntok = 5 + (int)(rnd() % 80);
        for (int k = 0; k < ntok && w < sizeof(buf) - 20; k++) {
            const char *t = TOK[rnd() % NTOK];
            size_t tl = strlen(t);
            memcpy(buf + w, t, tl); w += tl;
        }
        buf[w] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "struct_%04d", i);
        run(label, buf, w);
    }
}

/* ---- 3. length scaling ---- */
static void test_scaling(void) {
    printf("\n=== LENGTH SCALING ===\n");
    const char *unit = ".a { color: red; }\n";
    size_t unit_len = strlen(unit);

    size_t sizes[] = { 10, 100, 1000, 10000, 100000 };
    for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
        size_t reps = sizes[s];
        size_t total = unit_len * reps;
        if (total > 10 * 1024 * 1024) continue;   /* skip huge */
        char *buf = (char *)malloc(total + 1);
        if (!buf) continue;
        for (size_t i = 0; i < reps; i++) memcpy(buf + i * unit_len, unit, unit_len);
        buf[total] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "scale_%zux", reps);
        run(label, buf, total);
        free(buf);
    }
}

/* ---- 4. deep nesting ---- */
static void test_deep(int depth) {
    printf("\n=== DEEP NESTING (depth=%d) ===\n", depth);
    size_t cap = (size_t)depth * 20 + 100;
    char *buf = (char *)malloc(cap);
    if (!buf) return;
    size_t w = 0;
    for (int i = 0; i < depth; i++) {
        int n = snprintf(buf + w, cap - w, "@media x { ");
        if (n < 0) break;
        w += (size_t)n;
    }
    int n = snprintf(buf + w, cap - w, ".a { y: z } ");
    if (n > 0) w += (size_t)n;
    for (int i = 0; i < depth; i++) {
        n = snprintf(buf + w, cap - w, " }");
        if (n < 0) break;
        w += (size_t)n;
    }
    char label[64];
    snprintf(label, sizeof(label), "deep_%d", depth);
    run(label, buf, w);
    free(buf);
}

/* ---- 5. selectors with heavy combinator chains ---- */
static void test_combinators(int n, int max_depth) {
    printf("\n=== COMBINATOR CHAINS (%d) ===\n", n);
    for (int i = 0; i < n; i++) {
        char buf[2048];
        size_t w = 0;
        int parts = 1 + (int)(rnd() % max_depth);
        for (int k = 0; k < parts && w < sizeof(buf) - 20; k++) {
            const char *comb = " > + ~ ";
            const char *part;
            switch (rnd() % 5) {
                case 0: part = "div"; break;
                case 1: part = ".cls"; break;
                case 2: part = "#id"; break;
                case 3: part = "[attr]"; break;
                default: part = ":hover"; break;
            }
            if (k > 0) {
                size_t cl = strlen(comb);
                memcpy(buf + w, comb, cl); w += cl;
            }
            size_t pl = strlen(part);
            memcpy(buf + w, part, pl); w += pl;
        }
        n = snprintf(buf + w, sizeof(buf) - w, " { x: y }");
        if (n > 0) w += (size_t)n;
        char label[64];
        snprintf(label, sizeof(label), "comb_%04d_d%d", i, parts);
        run(label, buf, w);
    }
}

/* ---- 6. random bytes ---- */
static void test_random_bytes(int n, int max_len) {
    printf("\n=== RANDOM BYTES (%d) ===\n", n);
    for (int i = 0; i < n; i++) {
        int len = 1 + (int)(rnd() % max_len);
        char buf[512];
        for (int k = 0; k < len && k < (int)sizeof(buf) - 1; k++) {
            buf[k] = (char)(rnd() & 0xFF);
        }
        buf[len < (int)sizeof(buf) ? len : (int)sizeof(buf) - 1] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "rand_%04d_len%d", i, len);
        run(label, buf, (size_t)len);
    }
}

int main(int argc, char **argv) {
    int mut_n = 2000;
    int struct_n = 2000;
    int comb_n = 2000;
    int rand_n = 2000;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose_flag = 1;
        else if (!strncmp(argv[i], "--mut=", 6)) mut_n = atoi(argv[i] + 6);
        else if (!strncmp(argv[i], "--struct=", 9)) struct_n = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "--comb=", 7)) comb_n = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--rand=", 7)) rand_n = atoi(argv[i] + 7);
    }

    printf("=== CSS HEAVY FUZZ ===\n");
    printf("  platform: %s %s\n", plat_name(), plat_arch());

    uint64_t t0 = plat_now_ns();

    test_mutations(mut_n);
    test_structural(struct_n);
    test_scaling();
    test_deep(100);
    test_deep(1000);
    test_deep(5000);
    test_combinators(comb_n, 200);
    test_random_bytes(rand_n, 500);

    uint64_t dt = plat_now_ns() - t0;

    printf("\n=== SUMMARY ===\n");
    printf("  passed:      %d\n", passed);
    printf("  crashed:     %d\n", crashed);
    printf("  hung:        %d\n", hung);
    printf("  total time:  %.3f ms\n", (double)dt / 1e6);
    printf("  avg per:     %.1f ns\n",
           passed ? (double)total_ns / passed : 0.0);
    printf("  slowest:     %llu ns (%s)\n",
           (unsigned long long)slowest_ns, slowest_label);

    return (crashed || hung) ? 1 : 0;
}
