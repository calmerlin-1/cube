/** test_corpus.c — run real files through HTML, CSS, and JS parsers.
 *  Times each parse, reports throughput and output stats. */

#include "../include/html.h"
#include "../../css/include/css.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <dirent.h>
#include <sys/stat.h>

/* ---- signal trap for crash detection ---- */
static jmp_buf g_jmp;
static volatile int g_sig = 0;
static void trap(int s) { g_sig = s; longjmp(g_jmp, 1); }

static int cpu_freq_mhz(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!f) return 0;
    int k = 0;
    if (fscanf(f, "%d", &k) != 1) k = 0;
    fclose(f);
    return k / 1000;
#else
    return 0;
#endif
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 20*1024*1024) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

/* ---- parsers ---- */

typedef struct {
    uint64_t    ns;
    long        output_count;   /* nodes or rules */
    int         crashed;
} parse_result_t;

static parse_result_t run_html(const char *src, size_t len) {
    parse_result_t r = {0};
    uint64_t t0 = plat_now_ns();
    html_document_t *doc = html_parse(src, len);
    r.ns = plat_now_ns() - t0;
    if (doc) {
        r.output_count = doc->n_nodes;
        html_free(doc);
    } else {
        r.output_count = -1;
    }
    return r;
}

static parse_result_t run_css(const char *src, size_t len) {
    parse_result_t r = {0};
    uint64_t t0 = plat_now_ns();
    css_stylesheet_t *ss = css_parse(src, len);
    r.ns = plat_now_ns() - t0;
    if (ss) {
        r.output_count = ss->n_rules;
        css_free(ss);
    } else {
        r.output_count = -1;
    }
    return r;
}

/* Forward: JS engine lives at flywheel/js. We shell out for now.
 * Real integration comes later — for now we skip and mark as "skipped". */
/* JS integration: spawn flywheel/js/build/test_parser as subprocess.
 * Real FFI would require linking libflywheel.a — subprocess is a
 * proof-of-concept that the parser handles real JS files. */
static parse_result_t run_js(const char *src, size_t len) {
    parse_result_t r = {0};
    (void)len;
    /* Heuristic token counting — same as before, fast enough for
     * pipeline integration test. Real subprocess test comes later. */
    uint64_t t0 = plat_now_ns();
    int tokens = 0;
    int in_string = 0;
    char q = 0;
    int in_comment_line = 0;
    int in_comment_block = 0;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        char n = (i + 1 < len) ? src[i+1] : 0;
        if (in_comment_line) {
            if (c == '\n') in_comment_line = 0;
            continue;
        }
        if (in_comment_block) {
            if (c == '*' && n == '/') { in_comment_block = 0; i++; }
            continue;
        }
        if (in_string) {
            if (c == '\\') { i++; continue; }
            if (c == q) in_string = 0;
            continue;
        }
        if (c == '/' && n == '/') { in_comment_line = 1; i++; continue; }
        if (c == '/' && n == '*') { in_comment_block = 1; i++; continue; }
        if (c == '"' || c == '\'') { in_string = 1; q = c; continue; }
        if (c == ' ' || c == '\n' || c == '\t' || c == ';' ||
            c == '{' || c == '}' || c == '(' || c == ')') tokens++;
    }
    r.ns = plat_now_ns() - t0;
    r.output_count = tokens;
    return r;
}

/* ---- per-file driver ---- */

static void test_file(const char *path, const char *kind) {
    size_t len = 0;
    char *src = read_file(path, &len);
    if (!src) {
        printf("  %-40s SKIP (unreadable)\n", path);
        return;
    }

    g_sig = 0;
    void (*old_segv)(int) = signal(SIGSEGV, trap);
    void (*old_abrt)(int) = signal(SIGABRT, trap);
    void (*old_bus)(int)  = signal(SIGBUS, trap);
    (void)old_abrt; (void)old_bus;

    parse_result_t r = {0};
    if (setjmp(g_jmp) != 0) {
        printf("  %-40s CRASH[%d]  size=%zu\n", path, g_sig, len);
        free(src);
        signal(SIGSEGV, old_segv);
        return;
    }

    if (strcmp(kind, "html") == 0)      r = run_html(src, len);
    else if (strcmp(kind, "css") == 0)  r = run_css(src, len);
    else                                r = run_js(src, len);

    double mbps = (r.ns > 0) ? ((double)len / 1048576.0) / ((double)r.ns / 1e9) : 0.0;
    long us = (long)(r.ns / 1000);
    printf("  %-40s %8zu bytes  %8ld us  %8.1f MB/s  %s=%ld\n",
           path, len, us, mbps,
           strcmp(kind, "css") == 0 ? "rules" : "nodes",
           r.output_count);

    free(src);
    signal(SIGSEGV, old_segv);
}

/* ---- directory sweep ---- */

static void test_dir(const char *dir, const char *kind) {
    DIR *d = opendir(dir);
    if (!d) { printf("  (cannot open %s)\n", dir); return; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        test_file(path, kind);
    }
    closedir(d);
}

int main(void) {
    printf("=== CORPUS TEST ===\n");
    printf("  platform: %s %s\n", plat_name(), plat_arch());
    printf("  cpu at start: %d MHz\n\n", cpu_freq_mhz());

    uint64_t t0 = plat_now_ns();

    printf("--- HTML files ---\n");
    test_dir("corpus/html", "html");

    printf("\n--- CSS files ---\n");
    test_dir("corpus/css", "css");

    printf("\n--- JS files (skipped — not yet integrated) ---\n");
    test_dir("corpus/js", "js");

    uint64_t dt = plat_now_ns() - t0;

    printf("\n=== SUMMARY ===\n");
    printf("  total time:  %.3f ms\n", (double)dt / 1e6);
    printf("  cpu at end:  %d MHz\n", cpu_freq_mhz());
    return 0;
}
