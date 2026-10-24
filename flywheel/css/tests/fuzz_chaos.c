/** fuzz_chaos.c — systematic chaos: bit flips, truncation, insertion,
 * grammar recursion, cross-product torture, huge tokens. */

#include "../include/css.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

static jmp_buf g_jmp;
static volatile int g_sig = 0;
static void trap(int s) { g_sig = s; longjmp(g_jmp, 1); }

static int passed = 0, crashed = 0;
static uint64_t total_ns = 0;
static uint64_t slowest_ns = 0;

/* Read current CPU frequency (kHz) from sysfs. Returns 0 if unavailable. */
static int cpu_freq_mhz(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!f) f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq", "r");
    if (!f) return 0;
    int khz = 0;
    if (fscanf(f, "%d", &khz) != 1) khz = 0;
    fclose(f);
    return khz / 1000;
#else
    return 0;
#endif
}

static int cpu_temp_c10(void) {
#if defined(__linux__) || defined(__ANDROID__)
    /* Find max thermal zone temperature */
    int maxt = -1;
    char path[256];
    for (int z = 0; z < 32; z++) {
        snprintf(path, sizeof(path),
                 "/sys/class/thermal/thermal_zone%d/temp", z);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        int t = 0;
        if (fscanf(f, "%d", &t) == 1 && t > maxt) maxt = t;
        fclose(f);
    }
    return maxt > 0 ? maxt / 100 : -1;
#else
    return -1;
#endif
}
static char slowest_label[128];
static int verbose_flag = 0;

/* track crashes with the exact input so we can replay them */
#define CRASH_BUF_SIZE 8192
static char crash_replay[64][CRASH_BUF_SIZE];
static int crash_n = 0;

/* ---- RNG (super random — no fixed seed, mix time) ---- */
static uint64_t rng_state;
static void rng_seed(void) {
    uint64_t t = plat_now_ns();
    rng_state = 0x9E3779B97F4A7C15ull ^ t ^ ((uint64_t)getpid() << 32);
}
static uint32_t rnd(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 32);
}

static void run(const char *label, const char *src, size_t len) {
    g_sig = 0;
    void (*old_segv)(int) = signal(SIGSEGV, trap);
    void (*old_abrt)(int) = signal(SIGABRT, trap);
    void (*old_bus)(int)  = signal(SIGBUS, trap);
    void (*old_ill)(int)  = signal(SIGILL, trap);
    void (*old_fpe)(int)  = signal(SIGFPE, trap);
    (void)old_abrt; (void)old_bus; (void)old_ill; (void)old_fpe;

    if (setjmp(g_jmp) != 0) {
        printf("  *** CRASH[%d] %s ***\n", g_sig, label);
        /* Save the exact input for replay */
        if (crash_n < 64) {
            size_t copy = len < CRASH_BUF_SIZE - 1 ? len : CRASH_BUF_SIZE - 1;
            memcpy(crash_replay[crash_n], src, copy);
            crash_replay[crash_n][copy] = '\0';
            crash_n++;
        }
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
    if (verbose_flag || dt > 5000000ull) {
        printf("  %-52s  %10llu ns  len=%zu\n",
               label, (unsigned long long)dt, len);
    }

    signal(SIGSEGV, old_segv);
}

/* ---- 1. BIT FLIPS of a valid stylesheet ---- */
static const char *VALID_CSS =
    "html, body { margin: 0; padding: 0; }\n"
    ".container > .row + .row { margin-top: 10px; }\n"
    "a:hover { color: #06c; }\n"
    "@media (min-width: 768px) { .sidebar { width: 250px; } }\n";

static void test_bit_flips(int max_flips_per_byte) {
    printf("\n=== BIT FLIPS ===\n");
    size_t base_len = strlen(VALID_CSS);
    char buf[1024];
    if (base_len + 1 > sizeof(buf)) return;

    for (size_t pos = 0; pos < base_len; pos++) {
        for (int bit = 0; bit < 8; bit++) {
            if ((int)(rnd() % 10) >= max_flips_per_byte) continue;
            memcpy(buf, VALID_CSS, base_len + 1);
            buf[pos] = (char)((unsigned char)buf[pos] ^ (1 << bit));
            char label[64];
            snprintf(label, sizeof(label), "bitflip_p%zu_b%d", pos, bit);
            run(label, buf, base_len);
        }
    }
}

/* ---- 2. TRUNCATION SWEEP: parse prefix [0..N) for every N ---- */
static void test_truncation(void) {
    printf("\n=== TRUNCATION SWEEP ===\n");
    size_t base_len = strlen(VALID_CSS);
    for (size_t n = 0; n <= base_len; n++) {
        char label[64];
        snprintf(label, sizeof(label), "trunc_%zu", n);
        run(label, VALID_CSS, n);
    }
}

/* ---- 3. INSERTION SWEEP: insert byte X at position P ---- */
static void test_insertions(int sample_rate) {
    printf("\n=== INSERTION SWEEP ===\n");
    size_t base_len = strlen(VALID_CSS);
    char buf[1024];
    if (base_len + 2 > sizeof(buf)) return;

    for (size_t pos = 0; pos <= base_len; pos++) {
        for (int b = 0; b < 256; b++) {
            if ((int)(rnd() % 100) >= sample_rate) continue;
            memcpy(buf, VALID_CSS, pos);
            buf[pos] = (char)b;
            memcpy(buf + pos + 1, VALID_CSS + pos, base_len - pos + 1);
            char label[64];
            snprintf(label, sizeof(label), "ins_p%zu_b%d", pos, b);
            run(label, buf, base_len + 1);
        }
    }
}

/* ---- 4. RECURSIVE GRAMMAR GENERATION ---- */

static const char *SELECTORS[] = {
    "div", ".c", "#i", "*", "a", "[x]", ":hover", "::before",
    "div.foo", "a#id.cls", "[a=\"b\"]", ":not(.x)", "input[type=text]"
};
static const char *COMBINATORS[] = { " ", ">", "+", "~", " > ", " + " };
static const char *PROPS[] = { "color", "width", "margin", "padding", "border", "background" };
static const char *VALUES[] = { "red", "100px", "50%", "#fff", "rgb(1,2,3)", "url(x.png)", "1em 2em 3em" };
static const char *AT_RULES[] = {
    "@media screen { %s }",
    "@supports (display: flex) { %s }",
    "@media (min-width: 100px) { %s }"
};

static void gen_rule(char *buf, size_t cap, size_t *w, int depth);

static void gen_selector(char *buf, size_t cap, size_t *w) {
    int parts = 1 + (int)(rnd() % 5);
    for (int i = 0; i < parts; i++) {
        if (i > 0) {
            const char *c = COMBINATORS[rnd() % (sizeof(COMBINATORS)/sizeof(COMBINATORS[0]))];
            size_t cl = strlen(c);
            if (*w + cl > cap - 1) return;
            memcpy(buf + *w, c, cl); *w += cl;
        }
        const char *s = SELECTORS[rnd() % (sizeof(SELECTORS)/sizeof(SELECTORS[0]))];
        size_t sl = strlen(s);
        if (*w + sl > cap - 1) return;
        memcpy(buf + *w, s, sl); *w += sl;
    }
    /* sometimes add a comma + another selector */
    if (rnd() % 3 == 0) {
        if (*w + 2 > cap - 1) return;
        buf[(*w)++] = ',';
        buf[(*w)++] = ' ';
        gen_selector(buf, cap, w);
    }
}

static void gen_body(char *buf, size_t cap, size_t *w) {
    int n = 1 + (int)(rnd() % 8);
    for (int i = 0; i < n; i++) {
        const char *p = PROPS[rnd() % (sizeof(PROPS)/sizeof(PROPS[0]))];
        const char *v = VALUES[rnd() % (sizeof(VALUES)/sizeof(VALUES[0]))];
        size_t pl = strlen(p), vl = strlen(v);
        if (*w + pl + vl + 6 > cap - 1) return;
        memcpy(buf + *w, p, pl); *w += pl;
        buf[(*w)++] = ':';
        buf[(*w)++] = ' ';
        memcpy(buf + *w, v, vl); *w += vl;
        if (rnd() % 5 == 0) {
            const char *imp = " !important";
            size_t il = strlen(imp);
            if (*w + il > cap - 1) return;
            memcpy(buf + *w, imp, il); *w += il;
        }
        buf[(*w)++] = ';';
        buf[(*w)++] = ' ';
    }
}

static void gen_rule(char *buf, size_t cap, size_t *w, int depth) {
    if (depth <= 0 || *w > cap - 100) return;

    /* Maybe an at-rule that recurses */
    if (rnd() % 8 == 0 && depth > 1) {
        const char *at = AT_RULES[rnd() % (sizeof(AT_RULES)/sizeof(AT_RULES[0]))];
        /* build inner first */
        char inner[2048];
        size_t iw = 0;
        gen_rule(inner, sizeof(inner), &iw, depth - 1);
        inner[iw] = '\0';
        int n = snprintf(buf + *w, cap - *w, at, inner);
        if (n > 0) *w += (size_t)n;
        return;
    }

    gen_selector(buf, cap, w);
    if (*w + 3 > cap - 1) return;
    buf[(*w)++] = ' ';
    buf[(*w)++] = '{';
    buf[(*w)++] = ' ';
    gen_body(buf, cap, w);
    buf[(*w)++] = '}';
    buf[(*w)++] = '\n';
}

static void test_grammar(int n, int max_depth) {
    printf("\n=== GRAMMAR RECURSION (%d, depth<=%d) ===\n", n, max_depth);
    for (int i = 0; i < n; i++) {
        char buf[4096];
        size_t w = 0;
        int d = 1 + (int)(rnd() % max_depth);
        gen_rule(buf, sizeof(buf), &w, d);
        buf[w] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "gram_%04d_d%d", i, d);
        run(label, buf, w);
    }
}

/* ---- 5. HUGE SINGLE TOKENS ---- */
static void test_huge_tokens(void) {
    printf("\n=== HUGE SINGLE TOKENS ===\n");
    const char *prefixes[] = {
        "/* ",        /* comment */
        ".a { ",      /* value context */
        "url(",       /* url body */
        "\""          /* string */
    };
    size_t sizes[] = { 1000, 10000, 100000, 1000000 };
    for (size_t p = 0; p < sizeof(prefixes)/sizeof(prefixes[0]); p++) {
        for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
            size_t len = sizes[s];
            char *buf = (char *)malloc(len + 32);
            if (!buf) continue;
            size_t pw = strlen(prefixes[p]);
            memcpy(buf, prefixes[p], pw);
            memset(buf + pw, 'a', len);
            buf[pw + len] = '\0';
            char label[64];
            snprintf(label, sizeof(label), "huge_p%zu_%zux", p, sizes[s]);
            run(label, buf, pw + len);
            free(buf);
        }
    }
}

/* ---- 6. CHARSET CHAOS: every byte alone, then sequences ---- */
static void test_charset(void) {
    printf("\n=== CHARSET CHAOS ===\n");
    for (int b = 0; b < 256; b++) {
        char buf[64];
        buf[0] = (char)b;
        buf[1] = '\0';
        char label[32];
        snprintf(label, sizeof(label), "solo_%d", b);
        run(label, buf, 1);
    }
    /* random 3-byte sequences */
    for (int i = 0; i < 2000; i++) {
        char buf[8];
        buf[0] = (char)(rnd() & 0xFF);
        buf[1] = (char)(rnd() & 0xFF);
        buf[2] = (char)(rnd() & 0xFF);
        buf[3] = '\0';
        char label[32];
        snprintf(label, sizeof(label), "tri_%d_%d_%d",
                 (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2]);
        run(label, buf, 3);
    }
}

/* ---- 7. MEMORY PRESSURE: parse 10,000 times ---- */
static void test_memory_pressure(int n) {
    printf("\n=== MEMORY PRESSURE (%d parses) ===\n", n);
    long rss0 = plat_rss_bytes();
    for (int i = 0; i < n; i++) {
        css_stylesheet_t *ss = css_parse(VALID_CSS, strlen(VALID_CSS));
        css_free(ss);
    }
    long rss1 = plat_rss_bytes();
    printf("  rss delta after %d parses: %+ld KB\n", n, (rss1 - rss0) / 1024);
}

/* ---- 8. INTERLEAVED: valid+invalid+valid+invalid ---- */
static void test_interleaved(int n) {
    printf("\n=== INTERLEAVED GARBAGE ===\n");
    for (int i = 0; i < n; i++) {
        char buf[2048];
        size_t w = 0;
        int segments = 2 + (int)(rnd() % 20);
        for (int s = 0; s < segments && w < sizeof(buf) - 100; s++) {
            if (rnd() % 2) {
                /* valid-ish */
                const char *frag = ".x { color: red; }\n";
                size_t fl = strlen(frag);
                memcpy(buf + w, frag, fl); w += fl;
            } else {
                /* pure garbage */
                int gl = 1 + (int)(rnd() % 50);
                for (int k = 0; k < gl && w < sizeof(buf) - 2; k++) {
                    buf[w++] = (char)(rnd() & 0xFF);
                }
            }
        }
        buf[w] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "inter_%04d", i);
        run(label, buf, w);
    }
}

int main(int argc, char **argv) {
    int mut_rate = 4;
    int ins_rate = 15;
    int gram_n = 3000;
    int gram_depth = 6;
    int inter_n = 2000;
    int mem_n = 10000;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose_flag = 1;
        else if (!strncmp(argv[i], "--mut=", 6)) mut_rate = atoi(argv[i] + 6);
        else if (!strncmp(argv[i], "--ins=", 6)) ins_rate = atoi(argv[i] + 6);
        else if (!strncmp(argv[i], "--gram=", 7)) gram_n = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--depth=", 8)) gram_depth = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--inter=", 8)) inter_n = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--mem=", 6)) mem_n = atoi(argv[i] + 6);
    }

    rng_seed();

    printf("=== CSS CHAOS FUZZ ===\n");
    printf("  platform:   %s %s\n", plat_name(), plat_arch());
    printf("  seed:       0x%llx  pid: %d\n",
           (unsigned long long)rng_state, (int)getpid());
    {
        int f = cpu_freq_mhz(), t = cpu_temp_c10();
        if (t >= 0) printf("  cpu at start: %d MHz  temp: %d.%d C\n", f, t/10, t%10);
        else        printf("  cpu at start: %d MHz  temp: n/a\n", f);
    }

    uint64_t t0 = plat_now_ns();

    test_bit_flips(mut_rate);
    test_truncation();
    test_insertions(ins_rate);
    test_grammar(gram_n, gram_depth);
    test_huge_tokens();
    test_charset();
    test_memory_pressure(mem_n);
    test_interleaved(inter_n);

    uint64_t dt = plat_now_ns() - t0;

    printf("\n=== SUMMARY ===\n");
    {
        int f = cpu_freq_mhz(), t = cpu_temp_c10();
        if (t >= 0) printf("  cpu at end:   %d MHz  temp: %d.%d C\n", f, t/10, t%10);
        else        printf("  cpu at end:   %d MHz  temp: n/a\n", f);
    }
    printf("  passed:      %d\n", passed);
    printf("  crashed:     %d\n", crashed);
    printf("  total time:  %.3f ms\n", (double)dt / 1e6);
    printf("  avg per:     %.0f ns\n",
           passed ? (double)total_ns / passed : 0.0);
    printf("  slowest:     %llu ns (%s)\n",
           (unsigned long long)slowest_ns, slowest_label);

    if (crash_n > 0) {
        printf("\n=== CRASH REPLAYS ===\n");
        for (int i = 0; i < crash_n; i++) {
            printf("  [%d] len=%zu: ", i, strlen(crash_replay[i]));
            /* Show first 200 bytes with escapes */
            for (size_t k = 0; k < 200 && crash_replay[i][k]; k++) {
                unsigned char c = (unsigned char)crash_replay[i][k];
                if (c >= 32 && c < 127) putchar(c);
                else printf("\\x%02x", c);
            }
            printf("\n");
        }
    }

    return crashed ? 1 : 0;
}
