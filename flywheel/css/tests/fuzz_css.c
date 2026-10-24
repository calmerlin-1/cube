/** fuzz_css.c — fuzz and vulnerability test for CSS parser.
 * Runs hand-picked adversarial inputs and random fuzz cases.
 * Records per-test timing and memory usage. */

#include "../include/css.h"
#include "../src/tokenizer/css_token.h"
#include "../src/runtime/arena.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

/* ---- signal handling for crash detection ---- */
static jmp_buf g_jmp;
static volatile int g_crashed = 0;

static void trap(int sig) {
    g_crashed = sig;
    longjmp(g_jmp, 1);
}

/* ---- per-test stats ---- */
typedef struct {
    int      passed;
    int      parse_err;
    int      crashed;
    int      timeout;
    uint64_t total_ns;
} stats_t;

static stats_t g_stats;
static int     g_index = 0;

/* ---- helpers ---- */
static uint64_t now_ns(void) { return plat_now_ns(); }

static long rss_kb(void) {
    long b = plat_rss_bytes();
    return b > 0 ? b / 1024 : -1;
}

/* Run one test: parse the input, time it, classify the result. */
static void run_test(const char *label, const char *src, size_t len, int verbose) {
    g_crashed = 0;
    int sig_saved = 0;

    /* Install handlers to detect segfaults */
    void (*old_segv)(int) = signal(SIGSEGV, trap);
    void (*old_abrt)(int) = signal(SIGABRT, trap);
    void (*old_bus)(int)  = signal(SIGBUS, trap);
    (void)old_abrt; (void)old_bus;

    if (setjmp(g_jmp) != 0) {
        /* Crashed */
        printf("  [%03d] CRASH[%d] %s\n",
               g_index++, g_crashed, label);
        g_stats.crashed++;
        signal(SIGSEGV, old_segv);
        return;
    }

    long rss0 = rss_kb();
    uint64_t t0 = now_ns();
    css_stylesheet_t *ss = css_parse(src, len);
    uint64_t dt = now_ns() - t0;
    long rss1 = rss_kb();

    g_stats.total_ns += dt;

    int rules = ss ? ss->n_rules : -1;
    int errs  = css_error_count();

    css_free(ss);

    if (rules < 0) {
        printf("  [%03d] FAIL      %-40s  %8llu ns\n",
               g_index++, label, (unsigned long long)dt);
        g_stats.parse_err++;
    } else {
        if (verbose || errs == 0) {
            printf("  [%03d] PASS      %-40s  %8llu ns  rules=%-3d errs=%d  rss=%+ldKB\n",
                   g_index++, label, (unsigned long long)dt,
                   rules, errs, (rss1 - rss0));
        } else {
            g_index++;
        }
        g_stats.passed++;
    }

    signal(SIGSEGV, old_segv);
    (void)sig_saved;
}

/* ---- hand-picked vulnerability tests ---- */

static void run_vuln_tests(int verbose) {
    printf("\n=== VULNERABILITY / EDGE-CASE TESTS ===\n");

    struct { const char *label; const char *src; } cases[] = {
        /* Empty / trivial */
        {"empty",                     ""},
        {"whitespace only",           "   \n\t  "},
        {"single comment",            "/* hi */"},

        /* Unterminated constructs */
        {"unterminated block comment","/* never ends"},
        {"unterminated string",       ".a { content: \"no close }"},
        {"unterminated url",          ".a { background: url(foo"},
        {"unterminated rule",         ".a { color: red"},
        {"unterminated selector",     ".a"},

        /* Bracket chaos */
        {"unbalanced lbrace",         ".a {{ color: red; }"},
        {"unbalanced rbrace",         ".a { color: red; }}"},
        {"unbalanced lparen",         ".a { color: rgb(1,2"},
        {"unbalanced rparen",         ".a { color: rgb(1,2))}"},
        {"only lbrace",               "{"},
        {"only rbrace",               "}"},
        {"only lparen",               "("},
        {"nested parens",             ".a { color: rgb(1, rgb(2,3,4)) }"},

        /* Selector abuse */
        {"selector ending at EOF",    "div"},
        {"comma at end",              "div,"},
        {"comma at start",            ",div { }"},
        {"only commas",               ",,,,"},
        {"only dots",                 "...."},
        {"only hashes",               "####"},
        {"only pseudo",               "::::"},
        {"deep descendant",           ".a .b .c .d .e .f .g .h .i .j .k .l { color: red }"},
        {"many selectors",            ".a, .b, .c, .d, .e, .f, .g, .h, .i, .j { color: red }"},
        {"attribute chaos",           "[a][b][c][d][e] { color: red }"},
        {"attr with weird op",        "[a~=b][c|=d][e^=f] { }"},

        /* Value abuse */
        {"empty value",               ".a { color: }"},
        {"empty prop",                ".a { : red }"},
        {"no colon",                  ".a { color red }"},
        {"many semicolons",           ".a { ;;;; color: red ;;;; }"},
        {"huge number",               ".a { width: 999999999999999999999999 }"},
        {"negative huge",             ".a { margin: -999999999999999999999 }"},
        {"scientific",                ".a { width: 1e999 }"},
        {"percent",                   ".a { width: 50% }"},
        {"complex value",             ".a { font: italic bold 12px/1.5 \"Helvetica\", sans-serif }"},
        {"url value",                 ".a { background: url('http://x.com/y.png') }"},
        {"data url",                  ".a { background: url(data:image/png;base64,AAA) }"},

        /* At-rule abuse */
        {"@ with no name",            "@ { color: red }"},
        {"@media no body",            "@media screen;"},
        {"@media unterminated",       "@media screen { .a { color: red }"},
        {"@import no semicolon",      "@import url(x)"},
        {"@ charset",                 "@charset \"utf-8\";"},
        {"@ keyframes",               "@keyframes spin { from { } to { } }"},

        /* Invalid UTF-8 / control chars */
        {"null byte in value",        ".a { color: red\0; }"},
        {"control char",              ".a { color: \x01red; }"},
        {"high bytes",                ".a { color: \xff\xfe\xfd }"},

        /* Whitespace / comments */
        {"comment in selector",       ".a /* hi */ .b { color: red }"},
        {"comment in value",          ".a { color: /* c */ red }"},
        {"comment splits ident",      ".a { col/* */or: red }"},

        /* Deep nesting */
        {"nested media x3",           "@media a { @media b { @media c { .x { y: z } } } }"},
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_test(cases[i].label, cases[i].src, strlen(cases[i].src), verbose);
    }
}

/* ---- random fuzz ---- */

static uint64_t rng_state = 0x123456789ABCDEFull;

static uint32_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 32);
}

static const char *TOKENS[] = {
    ".", "#", ":", ";", ",", "{", "}", "(", ")", "[", "]",
    " ", "\n", "\t",
    "div", "color", "red", "width", "100px", "50%", "url(x)",
    "/*", "*/", "\"", "'", "\\", "@media", "@import", "!important",
    "hover", "first-child", "not", ":", ">", "+", "~", "*",
    "0", "1", "99999", "1e10", "-5", "+3",
    "\x01", "\xff", "a", "B", "_", "-"
};
#define NTOKENS (sizeof(TOKENS)/sizeof(TOKENS[0]))

static void run_fuzz_tests(int N, int verbose) {
    printf("\n=== FUZZ (%d random inputs) ===\n", N);

    for (int i = 0; i < N; i++) {
        char buf[256];
        size_t w = 0;
        int ntokens = 2 + (int)(rng_next() % 40);
        for (int k = 0; k < ntokens && w < sizeof(buf) - 16; k++) {
            const char *t = TOKENS[rng_next() % NTOKENS];
            size_t tl = strlen(t);
            if (w + tl + 1 > sizeof(buf)) break;
            memcpy(buf + w, t, tl);
            w += tl;
        }
        buf[w] = '\0';

        char label[32];
        snprintf(label, sizeof(label), "fuzz_%04d", i);
        run_test(label, buf, w, verbose);
    }
}

int main(int argc, char **argv) {
    int verbose = 0;
    int fuzz_n = 200;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strncmp(argv[i], "--n=", 4)) fuzz_n = atoi(argv[i] + 4);
    }

    memset(&g_stats, 0, sizeof(g_stats));
    uint64_t t0 = now_ns();

    printf("=== CSS parser fuzz + vulnerability test ===\n");
    printf("  platform: %s %s\n", plat_name(), plat_arch());
    printf("  fuzz iterations: %d\n", fuzz_n);

    /* Output produced by run_test is verbose enough on PASS; use
     * verbose flag to also print rules/errors. */
    run_vuln_tests(verbose);
    run_fuzz_tests(fuzz_n, verbose);

    uint64_t dt = now_ns() - t0;

    printf("\n=== SUMMARY ===\n");
    printf("  passed (parsed):     %d\n", g_stats.passed);
    printf("  parse_err (recover): %d\n", g_stats.parse_err);
    printf("  CRASH:               %d\n", g_stats.crashed);
    printf("  TIMEOUT:             %d\n", g_stats.timeout);
    printf("  total time:          %.3f ms\n", (double)dt / 1e6);
    printf("  total parse time:    %.3f ms\n", (double)g_stats.total_ns / 1e6);

    return (g_stats.crashed || g_stats.timeout) ? 1 : 0;
}
