/** fuzz_html.c — HTML parser fuzz + vulnerability test with timing. */

#include "../include/html.h"
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

static int passed = 0, failed = 0, crashed = 0;
static uint64_t total_ns = 0;
static uint64_t slowest_ns = 0;
static char slowest_label[128];
static int verbose_flag = 0;
static int verbose_pass = 1;   /* print every pass by default */

static int cpu_freq_mhz(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!f) return 0;
    int khz = 0;
    if (fscanf(f, "%d", &khz) != 1) khz = 0;
    fclose(f);
    return khz / 1000;
#else
    return 0;
#endif
}

static void run(const char *label, const char *src, size_t len) {
    g_sig = 0;
    void (*old_segv)(int) = signal(SIGSEGV, trap);
    void (*old_abrt)(int) = signal(SIGABRT, trap);
    void (*old_bus)(int)  = signal(SIGBUS, trap);
    (void)old_abrt; (void)old_bus;

    if (setjmp(g_jmp) != 0) {
        printf("  *** CRASH[%d] %s ***\n", g_sig, label);
        crashed++;
        signal(SIGSEGV, old_segv);
        return;
    }

    uint64_t t0 = plat_now_ns();
    html_document_t *doc = html_parse(src, len);
    uint64_t dt = plat_now_ns() - t0;
    int nodes = doc ? doc->n_nodes : -1;
    html_free(doc);

    total_ns += dt;
    if (dt > slowest_ns) {
        slowest_ns = dt;
        snprintf(slowest_label, sizeof(slowest_label), "%s", label);
    }

    if (verbose_pass || dt > 1000000ull) {
        printf("  %-52s  %10llu ns  len=%zu  nodes=%d\n",
               label, (unsigned long long)dt, len, nodes);
    }
    passed++;
    signal(SIGSEGV, old_segv);
}

/* ---- Hand-picked vulnerability tests ---- */
static void run_vuln_tests(void) {
    printf("\n=== VULN TESTS ===\n    (cpu: %d MHz)\n", cpu_freq_mhz());

    struct { const char *label; const char *src; } cases[] = {
        {"empty",                       ""},
        {"whitespace",                  "   \n\t  "},
        {"lone <",                      "<"},
        {"lone >",                      ">"},
        {"lone </",                     "</"},
        {"lone <!--",                   "<!--"},
        {"unterminated comment",        "<!-- no end"},
        {"unterminated tag",            "<div"},
        {"unterminated attr value",     "<div class=\"foo"},
        {"unterminated string attr",    "<div class='foo"},
        {"self-closing no close",       "<br/"},
        {"empty tag",                   "<>"},
        {"tag with only space",         "< >"},
        {"close tag no name",           "</>"},
        {"nested identical",            "<div><div><div></div></div></div>"},
        {"mismatched close",            "<div></span>"},
        {"too many close",              "</div></div></div>"},
        {"void with close",             "<br></br>"},
        {"deep nesting 100",            NULL},  /* built below */
        {"deep nesting 1000",           NULL},
        {"deep nesting 10000",          NULL},
        {"many siblings",               NULL},
        {"huge attr value",             NULL},
        {"huge text",                   NULL},
        {"null byte",                   "<p>a\0b</p>"},
        {"control char",                "<p>\x01\x02\x03</p>"},
        {"high bytes",                  "<p>\xff\xfe</p>"},
        {"cdata",                       "<![CDATA[ raw ]]>"},
        {"doctype only",                "<!DOCTYPE html>"},
        {"script tag",                  "<script>var x = 1;</script>"},
        {"script with <",               "<script>if (a<b) c();</script>"},
        {"style tag",                   "<style>.a { color: red }</style>"},
        {"attr no value",               "<input disabled>"},
        {"attr empty value",            "<input value=\"\">"},
        {"attr unquoted",               "<a href=/x>"},
        {"attr with entity",            "<a href=\"a&amp;b\">"},
    };

    /* Build the programmatic cases */
    static char deep100[512];
    static char deep1000[5120];
    static char deep10000[51200];
    static char many_sibs[8192];
    static char huge_attr[16000];
    static char huge_text[16000];

    {
        int w = 0;
        for (int i = 0; i < 100; i++) { int n = snprintf(deep100+w, sizeof(deep100)-w, "<div>");  if (n<0||(size_t)(w+n)>=sizeof(deep100)) break; w += n; }
        for (int i = 0; i < 100; i++) { int n = snprintf(deep100+w, sizeof(deep100)-w, "</div>"); if (n<0||(size_t)(w+n)>=sizeof(deep100)) break; w += n; }
        deep100[w] = 0;
    }
    {
        int w = 0;
        for (int i = 0; i < 1000; i++) { int n = snprintf(deep1000+w, sizeof(deep1000)-w, "<d>");  if (n<0||(size_t)(w+n)>=sizeof(deep1000)) break; w += n; }
        for (int i = 0; i < 1000; i++) { int n = snprintf(deep1000+w, sizeof(deep1000)-w, "</d>"); if (n<0||(size_t)(w+n)>=sizeof(deep1000)) break; w += n; }
        deep1000[w] = 0;
    }
    {
        int w = 0;
        for (int i = 0; i < 10000; i++) { int n = snprintf(deep10000+w, sizeof(deep10000)-w, "<d>");  if (n<0||(size_t)(w+n)>=sizeof(deep10000)) break; w += n; }
        for (int i = 0; i < 10000; i++) { int n = snprintf(deep10000+w, sizeof(deep10000)-w, "</d>"); if (n<0||(size_t)(w+n)>=sizeof(deep10000)) break; w += n; }
        deep10000[w] = 0;
    }
    {
        int w = 0;
        for (int i = 0; i < 500; i++) { int n = snprintf(many_sibs+w, sizeof(many_sibs)-w, "<p>x</p>"); if (n<0||(size_t)(w+n)>=sizeof(many_sibs)) break; w += n; }
        many_sibs[w] = 0;
    }
    {
        int w = 0;
        int n = snprintf(huge_attr, sizeof(huge_attr), "<a x=\"");
        if (n > 0) w = n;
        for (int i = 0; i < 15000 && w < (int)sizeof(huge_attr)-3; i++)
            huge_attr[w++] = 'A';
        if (w < (int)sizeof(huge_attr)-2) {
            huge_attr[w++] = '"';
            huge_attr[w++] = '>';
        }
        huge_attr[w] = '\0';
    }
    {
        int w = 0;
        int n = snprintf(huge_text, sizeof(huge_text), "<p>");
        if (n > 0) w = n;
        for (int i = 0; i < 15000 && w < (int)sizeof(huge_text)-6; i++)
            huge_text[w++] = 'x';
        if (w < (int)sizeof(huge_text)-4) {
            huge_text[w++] = '<'; huge_text[w++] = '/'; huge_text[w++] = 'p'; huge_text[w++] = '>';
        }
        huge_text[w] = '\0';
    }

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        const char *src = cases[i].src;
        size_t len = src ? strlen(src) : 0;
        if (!src) {
            /* programmatic */
            if (strcmp(cases[i].label, "deep nesting 100") == 0) { src = deep100; len = strlen(deep100); }
            else if (strcmp(cases[i].label, "deep nesting 1000") == 0) { src = deep1000; len = strlen(deep1000); }
            else if (strcmp(cases[i].label, "deep nesting 10000") == 0) { src = deep10000; len = strlen(deep10000); }
            else if (strcmp(cases[i].label, "many siblings") == 0) { src = many_sibs; len = strlen(many_sibs); }
            else if (strcmp(cases[i].label, "huge attr value") == 0) { src = huge_attr; len = strlen(huge_attr); }
            else if (strcmp(cases[i].label, "huge text") == 0) { src = huge_text; len = strlen(huge_text); }
        }
        run(cases[i].label, src, len);
    }
}

/* ---- Random token fuzz ---- */
static uint64_t rng = 0xCAFEBABE12345678ull;
static uint32_t rnd(void) {
    uint64_t x = rng;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng = x;
    return (uint32_t)(x >> 32);
}

static const char *TOKENS[] = {
    "<", ">", "/", "=", "\"", "'", "<!--", "-->", "<![CDATA[", "]]>",
    "<!DOCTYPE", "<p>", "</p>", "<div>", "</div>", "<br>", "<br/>",
    "<img src=\"a\">", "<input disabled>", "<script>", "</script>",
    "<style>", "</style>", "text", " ", "\n", "\t",
    "class", "id", "href", "src", "attr", "\x00", "\xff",
    "<a", ">", "<b>", "</b>", "<!>", "<?", "<?php", "<%"
};
#define NTOK (sizeof(TOKENS)/sizeof(TOKENS[0]))

static void run_fuzz(int n) {
    printf("\n=== FUZZ (%d) ===\n    (cpu: %d MHz)\n", n, cpu_freq_mhz());
    int old = verbose_pass;
    verbose_pass = 0;   /* only show slow/crash during fuzz */

    for (int i = 0; i < n; i++) {
        char buf[512];
        size_t w = 0;
        int ntok = 2 + (int)(rnd() % 40);
        for (int k = 0; k < ntok; k++) {
            const char *t = TOKENS[rnd() % NTOK];
            size_t tl = strlen(t);
            if (w + tl + 1 > sizeof(buf)) break;
            memcpy(buf + w, t, tl);
            w += tl;
        }
        buf[w] = '\0';
        char label[64];
        snprintf(label, sizeof(label), "fuzz_%04d", i);
        run(label, buf, w);
    }
    verbose_pass = old;
}

int main(int argc, char **argv) {
    int fuzz_n = 500;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose_flag = 1;
        else if (!strncmp(argv[i], "--n=", 4)) fuzz_n = atoi(argv[i] + 4);
        else if (!strcmp(argv[i], "-q")) verbose_pass = 0;
    }

    printf("=== HTML parser fuzz + vuln test ===\n");
    printf("  platform: %s %s\n", plat_name(), plat_arch());
    printf("  cpu at start: %d MHz\n", cpu_freq_mhz());

    uint64_t t0 = plat_now_ns();
    run_vuln_tests();
    run_fuzz(fuzz_n);
    uint64_t dt = plat_now_ns() - t0;

    printf("\n=== SUMMARY ===\n");
    printf("  cpu at end:  %d MHz\n", cpu_freq_mhz());
    printf("  passed:      %d\n", passed);
    printf("  crashed:     %d\n", crashed);
    printf("  total time:  %.3f ms\n", (double)dt / 1e6);
    printf("  avg per:     %.0f ns\n",
           passed ? (double)total_ns / passed : 0.0);
    printf("  slowest:     %llu ns (%s)\n",
           (unsigned long long)slowest_ns, slowest_label);

    return crashed ? 1 : 0;
}
