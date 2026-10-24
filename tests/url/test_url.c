/* test_url.c — URL stress: permutations, port sweep, IP chaos, subdomain fuzz. */

#include "url_parser.h"
#include "url_schemes.h"
#include "url_percent.h"
#include "url_idna.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

static long page_size = 4096;

/* Read RSS bytes from /proc/self/statm. */
static long read_rss_bytes(void) {
    int fd = open("/proc/self/statm", O_RDONLY);
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    long size, resident;
    if (sscanf(buf, "%ld %ld", &size, &resident) != 2) return -1;
    return resident * page_size;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* xorshift PRNG — deterministic. */
static uint64_t rng_state = 0xDEADBEEF12345678ull;
static uint32_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 32);
}
static size_t rng_pick(size_t n) { return n ? rng_next() % n : 0; }

/* Case counters. */
static int passed = 0;
static int failed = 0;
static uint64_t total_ns = 0;
static long rss_baseline = 0;

/* Sentinel: any parse result is a pass, as long as no crash. */
#define URL_ERR_NONE_SENTINEL  ((url_err)999)

/* Print one case result. Only fails print by default; every 1000th case prints a tick. */
static void report(int idx, const char *label, const char *url, size_t len,
                   url_err got, url_err want, uint64_t ns, long rss_delta) {
    total_ns += ns;
    int ok = (want == URL_ERR_NONE_SENTINEL) ? 1 : (got == want);
    if (ok) passed++; else failed++;
    if (!ok) {
        printf("  FAIL [%05d] %6llu ns  rss %+5ld B  got %-14s want %-14s  %s\n",
               idx, (unsigned long long)ns, rss_delta,
               url_err_name(got), url_err_name(want), label);
        printf("        input: %.*s\n", (int)len, url);
    } else if ((idx % 1000) == 0) {
        printf("  . %05d cases  pass=%d fail=%d\n", idx, passed, failed);
    }
    (void)url;
}

/* Run one case: parse, time, measure RSS, build href if ok. */
static void run_one(int idx, const char *label, const char *url, size_t len,
                    url_err want, int verbose) {
    long rb = read_rss_bytes();
    uint64_t t0 = now_ns();

    url_view v;
    url_err e = url_parse(url, len, &v);
    char out[2048]; size_t on = 0;
    if (e == URL_OK) url_build_href(&v, out, sizeof(out), &on);

    uint64_t dt = now_ns() - t0;
    long ra = read_rss_bytes();
    long delta = (ra >= 0 && rb >= 0) ? (ra - rb) : 0;

    if (verbose) {
        char disp[256];
        if (e == URL_OK && on > 0) snprintf(disp, sizeof(disp), "%s", out);
        else                       snprintf(disp, sizeof(disp), "%.*s", (int)(len < 100 ? len : 100), url);
        printf("  [%05d] %6llu ns  rss %+5ld B  %-14s  %s | %s\n",
               idx, (unsigned long long)dt, delta, url_err_name(e), label, disp);
    }
    report(idx, label, url, len, e, want, dt, delta);
}

/* ---------- Mode 1: port sweep 0..70000 ---------- */

static void mode_port_sweep(int verbose) {
    printf("=== PORT SWEEP (http://h:N/ for N in 0..70000 step 7) ===\n");
    int idx = 0;
    for (int p = 0; p <= 70000; p += 7) {
        char url[64];
        int n = snprintf(url, sizeof(url), "http://h:%d/", p);
        url_err want;
        if (p == 0 || p > 65535) want = URL_ERR_PORT_RANGE;
        else                     want = URL_OK;
        if (verbose || (idx % 500) == 0) run_one(idx, "port-sweep", url, (size_t)n, want, 1);
        else                              run_one(idx, "port-sweep", url, (size_t)n, want, 0);
        idx++;
    }
    printf("  --- port-sweep: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 2: IPv4 full chaos ---------- */

static void mode_ipv4(int verbose) {
    printf("=== IPv4 CHAOS ===\n");
    /* Fixed edge cases */
    const char *cases[] = {
        "http://0.0.0.0/",
        "http://255.255.255.255/",
        "http://127.0.0.1/",
        "http://192.168.0.1/",
        "http://256.0.0.1/",
        "http://999.999.999.999/",
        "http://1.2.3/",
        "http://1.2.3.4.5/",
        "http://01.02.03.04/",
        "http://0x7f.0.0.1/",
        "http://1.2.3.4./",
        "http://.1.2.3.4/",
        "http://1..2.3/",
        "http://255.255.255.256/",
        "http://1.2.3.4:0/",
        "http://1.2.3.4:65535/",
        "http://1.2.3.4:65536/",
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_one(idx++, "ipv4-edge", cases[i], strlen(cases[i]), URL_ERR_NONE_SENTINEL, verbose);
    }
    /* Random 4-octet chaos */
    for (int i = 0; i < 500; i++) {
        char url[64];
        int a = rng_next() % 300;
        int b = rng_next() % 300;
        int c = rng_next() % 300;
        int d = rng_next() % 300;
        int n = snprintf(url, sizeof(url), "http://%d.%d.%d.%d/", a, b, c, d);
        run_one(idx++, "ipv4-rand", url, (size_t)n, URL_ERR_NONE_SENTINEL, verbose);
    }
    printf("  --- ipv4: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 3: IPv6 chaos ---------- */

static void mode_ipv6(int verbose) {
    printf("=== IPv6 CHAOS ===\n");
    const char *cases[] = {
        "http://[::1]/",
        "http://[::]/",
        "http://[::ffff:192.168.1.1]/",
        "http://[2001:db8::1]/",
        "http://[2001:db8::1]:8080/",
        "http://[fe80::1%eth0]/",
        "http://[fe80::1%25eth0]/",
        "http://[]/",
        "http://[::1/",
        "http://[::1]]/",
        "http://[[::1]]/",
        "http://[1:2:3:4:5:6:7:8]/",
        "http://[1:2:3:4:5:6:7:8:9]/",
        "http://[gggg::1]/",
        "http://[::1]:0/",
        "http://[::1]:65535/",
        "http://[::1]:65536/",
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_one(idx++, "ipv6-edge", cases[i], strlen(cases[i]), URL_ERR_NONE_SENTINEL, verbose);
    }
    /* Random hex-group chaos */
    for (int i = 0; i < 300; i++) {
        char url[128];
        int w = snprintf(url, sizeof(url), "http://[");
        int groups = 1 + rng_next() % 10;
        for (int g = 0; g < groups && w < (int)sizeof(url) - 10; g++) {
            unsigned v = rng_next() & 0xFFFF;
            w += snprintf(url + w, sizeof(url) - w, "%x:", v);
        }
        if (w > 0 && url[w-1] == ':') w--;
        w += snprintf(url + w, sizeof(url) - w, "]/");
        run_one(idx++, "ipv6-rand", url, (size_t)w, URL_ERR_NONE_SENTINEL, verbose);
    }
    printf("  --- ipv6: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 4: subdomain chaos ---------- */

static void mode_subdomain(int verbose) {
    printf("=== SUBDOMAIN CHAOS ===\n");
    const char *cases[] = {
        "http://example.com/",
        "http://a.example.com/",
        "http://a.b.c.d.example.com/",
        "http://example.com./",
        "http://.example.com/",
        "http://..example.com/",
        "http://example..com/",
        "http://-example.com/",
        "http://example-.com/",
        "http://exa_mple.com/",
        "http://EXAMPLE.COM/",
        "http://ExAmPlE.CoM/",
        "http://xn--fsq.com/",
        "http://例え.jp/",
        "http://sub.例え.jp/",
        "http://verylongsubdomainnamethatgoesonandonandonandon.example.com/",
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_one(idx++, "subdomain", cases[i], strlen(cases[i]), URL_ERR_NONE_SENTINEL, verbose);
    }
    /* Random subdomain chains */
    const char *labels[] = {"a", "b", "x", "www", "api", "cdn", "mail", "sub", ""};
    const char *tlds[]   = {"com", "org", "net", "io", "co", "jp", "example"};
    for (int i = 0; i < 300; i++) {
        char url[256];
        int w = snprintf(url, sizeof(url), "http://");
        int depth = 1 + rng_next() % 6;
        for (int d = 0; d < depth && w < (int)sizeof(url) - 20; d++) {
            const char *lbl = labels[rng_pick(sizeof(labels)/sizeof(labels[0]))];
            w += snprintf(url + w, sizeof(url) - w, "%s.", lbl);
        }
        const char *tld = tlds[rng_pick(sizeof(tlds)/sizeof(tlds[0]))];
        w += snprintf(url + w, sizeof(url) - w, "%s/", tld);
        run_one(idx++, "subdomain-rand", url, (size_t)w, URL_ERR_NONE_SENTINEL, verbose);
    }
    printf("  --- subdomain: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 5: scheme chaos ---------- */

static void mode_scheme(int verbose) {
    printf("=== SCHEME CHAOS ===\n");
    const char *cases[] = {
        "http://h/", "https://h/", "HTTP://h/", "HtTpS://h/",
        "ftp://h/", "ftps://h/", "ssh://h/", "sftp://h/",
        "ws://h/", "wss://h/",
        "mysql://h/", "postgresql://h/", "redis://h/", "mongodb://h/",
        "dns://h/", "doh://h/", "irc://h/", "ircs://h/",
        "file:///path", "data:text/html,x", "mailto:a@b.c", "javascript:alert(1)",
        "magnet:?xt=urn:btih:abc", "ipfs://QmHash", "ipns://name",
        "myscheme://h/", "x-custom://h/", "a+b-c.d://h/",
        "1bad://h/", "-bad://h/", ".bad://h/", "+bad://h/",
        "://h/", "ht tp://h/", "ht\ttp://h/",
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_one(idx++, "scheme", cases[i], strlen(cases[i]), URL_ERR_NONE_SENTINEL, verbose);
    }
    printf("  --- scheme: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 6: control chars / whitespace ---------- */

static void mode_ctrl(int verbose) {
    printf("=== CTRL / WHITESPACE ===\n");
    struct { const char *label; const char *url; size_t len; url_err want; } cases[] = {
        {"null",        "http://h/\x00",       10, URL_ERR_CTRL},
        {"ctrl-0x01",   "http://h/\x01",       10, URL_ERR_CTRL},
        {"ctrl-0x1f",   "http://h/\x1f",       10, URL_ERR_CTRL},
        {"DEL",         "http://h/\x7f",       10, URL_ERR_CTRL},
        {"space-lead",  " http://h/",          10, URL_ERR_SPACE},
        {"space-trail", "http://h/ ",          10, URL_ERR_SPACE},
        {"space-mid",   "http://ho st/",       13, URL_ERR_SPACE},
        {"tab",         "http://h/\t",         10, URL_ERR_SPACE},
        {"newline",     "http://h/\n",         10, URL_ERR_SPACE},
        {"cr",          "http://h/\r",         10, URL_ERR_SPACE},
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        run_one(idx++, cases[i].label, cases[i].url, cases[i].len, cases[i].want, verbose);
    }
    printf("  --- ctrl: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 7: join chaos ---------- */

static void mode_join(int verbose) {
    printf("=== JOIN CHAOS ===\n");
    const char *base = "http://a/b/c/d;p?q";
    struct { const char *rel; url_err want; } rels[] = {
        {"",             URL_OK},
        {"g",            URL_OK},
        {"./g",          URL_OK},
        {"../g",         URL_OK},
        {"../../g",      URL_OK},
        {"../../../g",   URL_OK},
        {"/g",           URL_OK},
        {"//g",          URL_OK},
        {"///g",         URL_OK},
        {"?y",           URL_OK},
        {"#s",           URL_OK},
        {"?#",           URL_OK},
        {"#?",           URL_OK},
        {"http://x/y",   URL_OK},
        {"https://x",    URL_OK},
        {"//x:99/y",     URL_OK},
        {"/./x",         URL_OK},
        {"/../x",        URL_OK},
        {"a/./b",        URL_OK},
        {"a/../b",       URL_OK},
        {" ",            URL_OK},          /* space -> path (rejected at parse only for whole-URL whitespace) */
        {"\t",          URL_ERR_CTRL},     /* tab -> control */
        {"\x00",        URL_OK},           /* strlen==0, join returns base */
    };
    int idx = 0;
    for (size_t i = 0; i < sizeof(rels)/sizeof(rels[0]); i++) {
        url_view basev;
        if (url_parse(base, strlen(base), &basev) != URL_OK) continue;
        long rb = read_rss_bytes();
        uint64_t t0 = now_ns();
        char out[512]; size_t on = 0;
        url_err e = url_join(&basev, rels[i].rel, strlen(rels[i].rel), out, sizeof(out), &on);
        uint64_t dt = now_ns() - t0;
        long ra = read_rss_bytes();
        long delta = (ra >= 0 && rb >= 0) ? (ra - rb) : 0;
        total_ns += dt;
        int ok = (e == rels[i].want);
        if (ok) {
            passed++;
            printf("  PASS [%05d] %6llu ns  rss %+5ld B  %-14s  base=%s + rel='%s' -> %s\n",
                   idx, (unsigned long long)dt, delta, url_err_name(e), base, rels[i].rel, out);
        } else {
            failed++;
            printf("  FAIL [%05d] %6llu ns  rss %+5ld B  got %-14s want %-14s  base=%s + rel='%s'\n",
                   idx, (unsigned long long)dt, delta, url_err_name(e), url_err_name(rels[i].want), base, rels[i].rel);
        }
        idx++;
    }
    printf("  --- join: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 8: random byte fuzz ---------- */

static void mode_fuzz(int verbose, int N) {
    printf("=== RANDOM BYTE FUZZ (N=%d) ===\n", N);
    const char *bases[] = {
        "http://example.com/path?x=1#top",
        "https://user:pass@host:8443/a/b/c",
        "ftp://192.168.1.1:21/file.txt",
        "myscheme://[::1]:9999/x",
        "http://host./",
        "http://a.b.c.d.example.com:1234/x?y=z#f",
    };
    int nbase = sizeof(bases)/sizeof(bases[0]);
    for (int i = 0; i < N; i++) {
        const char *base = bases[rng_pick(nbase)];
        size_t blen = strlen(base);
        char url[512];
        if (blen >= sizeof(url) - 8) blen = sizeof(url) - 8;
        memcpy(url, base, blen);
        size_t n = blen;
        int muts = 1 + rng_pick(6);
        for (int m = 0; m < muts; m++) {
            if (n == 0) break;
            size_t j = rng_pick(n);
            switch (rng_next() % 10) {
                case 0: url[j] = (char)(rng_next() & 0xFF); break;
                case 1: url[j] = '/'; break;
                case 2: url[j] = ':'; break;
                case 3: url[j] = '?'; break;
                case 4: url[j] = '#'; break;
                case 5: url[j] = '@'; break;
                case 6: url[j] = '['; break;
                case 7: url[j] = ']'; break;
                case 8: url[j] = '%'; break;
                case 9: url[j] = '\x00'; break;
            }
        }
        if ((rng_next() & 3) == 0 && n + 8 < sizeof(url)) {
            size_t add = rng_pick(8) + 1;
            for (size_t k = 0; k < add; k++) url[n++] = (char)(rng_next() & 0xFF);
        }
        url[n] = '\0';
        run_one(i, "fuzz", url, n, URL_ERR_NONE_SENTINEL, verbose);
    }
    printf("  --- fuzz: passed=%d failed=%d\n\n", passed, failed);
}

/* ---------- Mode 9: percent decode / encode ---------- */

static void expect_dec(const char *label, const char *in, int plus,
                       const char *want) {
    char out[512];
    size_t n = 0;
    int r = url_percent_decode(in, strlen(in), out, sizeof(out), &n, plus);
    out[n] = '\0';
    if (r == URLP_OK && strcmp(out, want) == 0) {
        passed++;
        printf("  PASS  %-24s '%s' -> '%s'\n", label, in, out);
    } else if (r != URLP_OK) {
        failed++;
        printf("  FAIL  %-24s decode err %d\n", label, r);
    } else {
        failed++;
        printf("  FAIL  %-24s got '%s' want '%s'\n", label, out, want);
    }
}

static void expect_enc(const char *label, const char *in, int strict,
                       const char *want) {
    char out[512];
    size_t n = 0;
    int r = strict ? url_percent_encode_strict(in, strlen(in), out, sizeof(out), &n)
                   : url_percent_encode_path (in, strlen(in), out, sizeof(out), &n);
    out[n] = '\0';
    if (r == URLP_OK && strcmp(out, want) == 0) {
        passed++;
        printf("  PASS  %-24s '%s' -> '%s'\n", label, in, out);
    } else {
        failed++;
        printf("  FAIL  %-24s got '%s' want '%s' (r=%d)\n", label, out, want, r);
    }
}

static void mode_percent(int verbose) {
    printf("=== PERCENT DECODE ===\n");
    expect_dec("space",        "%20",   0, " ");
    expect_dec("slash",        "%2F",   0, "/");
    expect_dec("uppercase hex","%C3%A9",0, "\xC3\xA9");
    expect_dec("lowercase hex","%c3%a9",0, "\xC3\xA9");
    expect_dec("plus-as-space","a+b",   1, "a b");
    expect_dec("plus-kept",    "a+b",   0, "a+b");
    expect_dec("bare-percent", "100%",  0, "100%");
    expect_dec("bad-hex",      "%GG",   0, "%GG");
    expect_dec("short-hex",    "%A",    0, "%A");
    expect_dec("empty",        "",      0, "");

    printf("\n=== PERCENT ENCODE (path) ===\n");
    expect_enc("spaces",       "a b",       0, "a%20b");
    expect_enc("preserve-/-",  "a/b",       0, "a/b");
    expect_enc("preserve-~",   "a~b",       0, "a~b");
    expect_enc("encode-nonascii","\xC3\xA9", 0, "%C3%A9");
    expect_enc("encode-brackets","a[b]",    0, "a%5Bb%5D");

    printf("\n=== PERCENT ENCODE (strict) ===\n");
    expect_enc("strict-slash", "a/b",     1, "a%2Fb");
    expect_enc("strict-only",  "abc123",  1, "abc123");
    printf("\n");
}

/* ---------- Mode 10: IDN / punycode ---------- */

static void expect_idn(const char *label, const char *in, const char *want) {
    char out[512];
    size_t n = 0;
    int r = url_idna_to_ascii(in, strlen(in), out, sizeof(out), &n);
    out[n] = '\0';
    if (r == URLI_OK && strcmp(out, want) == 0) {
        passed++;
        printf("  PASS  %-24s '%s' -> '%s'\n", label, in, out);
    } else if (r != URLI_OK) {
        failed++;
        printf("  FAIL  %-24s err %d\n", label, r);
    } else {
        failed++;
        printf("  FAIL  %-24s got '%s' want '%s'\n", label, out, want);
    }
}

static void mode_idn(int verbose) {
    printf("=== IDN / PUNYCODE ===\n");
    expect_idn("ascii-unchanged", "example.com",  "example.com");
    expect_idn("ascii-lowercase", "ExAmPle.COM",  "example.com");
    expect_idn("münchen",         "m\xC3\xBCnchen",  "xn--mnchen-3ya");
    expect_idn("例え",            "\xE4\xBE\x8B\xE3\x81\x88",  "xn--r8jz45g");
    expect_idn("例え.jp",         "\xE4\xBE\x8B\xE3\x81\x88.jp", "xn--r8jz45g.jp");
    expect_idn("sub.例え.jp",     "sub.\xE4\xBE\x8B\xE3\x81\x88.jp", "sub.xn--r8jz45g.jp");
    printf("\n");
}

/* ---------- Mode 11: URL + IDN integration ---------- */

static void expect_url_idn(const char *label, const char *in, const char *want_href) {
    url_view v;
    url_err e = url_parse(in, strlen(in), &v);
    if (e) {
        failed++;
        printf("  FAIL  %-24s parse err %s\n", label, url_err_name(e));
        return;
    }
    char out[1024]; size_t n = 0;
    url_build_href(&v, out, sizeof(out), &n);
    if (strcmp(out, want_href) == 0) {
        passed++;
        printf("  PASS  %-24s -> %s\n", label, out);
    } else {
        failed++;
        printf("  FAIL  %-24s got '%s' want '%s'\n", label, out, want_href);
    }
}

static void mode_url_idn(int verbose) {
    printf("=== URL + IDN ===\n");
    expect_url_idn("例え.jp",     "http://\xE4\xBE\x8B\xE3\x81\x88.jp/",   "http://xn--r8jz45g.jp/");
    expect_url_idn("sub.例え.jp", "http://sub.\xE4\xBE\x8B\xE3\x81\x88.jp/", "http://sub.xn--r8jz45g.jp/");
    printf("\n");
}

/* ---------- Mode 12: encoded build ---------- */

static void expect_href_enc(const char *label, const char *in, const char *want) {
    url_view v;
    url_err e = url_parse_ex(in, strlen(in), URL_F_ALLOW_SPACE, &v);
    if (e) { failed++; printf("  FAIL  %-24s parse err %s\n", label, url_err_name(e)); return; }
    char out[1024]; size_t n = 0;
    e = url_build_href_encoded(&v, out, sizeof(out), &n);
    if (e) { failed++; printf("  FAIL  %-24s build err %s\n", label, url_err_name(e)); return; }
    if (strcmp(out, want) == 0) { passed++; printf("  PASS  %-24s -> %s\n", label, out); }
    else { failed++; printf("  FAIL  %-24s got '%s' want '%s'\n", label, out, want); }
}

static void mode_encoded_build(int verbose) {
    printf("=== ENCODED BUILD ===\n");
    expect_href_enc("plain",     "http://h/a/b",         "http://h/a/b");
    expect_href_enc("space",     "http://h/a b",         "http://h/a%20b");
    expect_href_enc("nonascii",  "http://h/\xC3\xA9",   "http://h/%C3%A9");
    expect_href_enc("query",     "http://h/a?x=1 2",     "http://h/a?x=1%202");
    printf("\n");
}

int main(int argc, char **argv) {
    int verbose = 0, N = 2000, modes = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) verbose = 1;
        else if (!strncmp(argv[i], "--n=", 4)) N = atoi(argv[i] + 4);
        else if (!strcmp(argv[i], "--ports"))    modes |= 1;
        else if (!strcmp(argv[i], "--ipv4"))     modes |= 2;
        else if (!strcmp(argv[i], "--ipv6"))     modes |= 4;
        else if (!strcmp(argv[i], "--sub"))      modes |= 8;
        else if (!strcmp(argv[i], "--scheme"))   modes |= 16;
        else if (!strcmp(argv[i], "--ctrl"))     modes |= 32;
        else if (!strcmp(argv[i], "--join"))     modes |= 64;
        else if (!strcmp(argv[i], "--fuzz"))     modes |= 128;
        else if (!strcmp(argv[i], "--percent"))  modes |= 256;
        else if (!strcmp(argv[i], "--idn"))      modes |= 512;
        else if (!strcmp(argv[i], "--url-idn"))  modes |= 1024;
        else if (!strcmp(argv[i], "--encoded"))  modes |= 2048;
        else if (!strcmp(argv[i], "--all"))      modes = 0xFFFF;
    }
    if (modes == 0) modes = 0xFF;

    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0) page_size = ps;
    rss_baseline = read_rss_bytes();

    printf("=== URL stress test ===\n");
    printf("  page: %ld  rss: %ld B  verbose: %s\n\n", page_size, rss_baseline, verbose ? "yes" : "no");

    uint64_t t0 = now_ns();

    if (modes & 1)   mode_port_sweep(verbose);
    if (modes & 2)   mode_ipv4(verbose);
    if (modes & 4)   mode_ipv6(verbose);
    if (modes & 8)   mode_subdomain(verbose);
    if (modes & 16)  mode_scheme(verbose);
    if (modes & 32)  mode_ctrl(verbose);
    if (modes & 64)  mode_join(verbose);
    if (modes & 128)  mode_fuzz(verbose, N);
    if (modes & 256)  mode_percent(verbose);
    if (modes & 512)  mode_idn(verbose);
    if (modes & 1024) mode_url_idn(verbose);
    if (modes & 2048) mode_encoded_build(verbose);

    uint64_t dt = now_ns() - t0;
    long rss_final = read_rss_bytes();

    printf("=== SUMMARY ===\n");
    printf("  passed: %d\n", passed);
    printf("  failed: %d\n", failed);
    printf("  total time: %llu ns  (%.3f ms)\n",
           (unsigned long long)dt, (double)dt / 1e6);
    printf("  avg per case: %llu ns\n",
           (unsigned long long)(total_ns / (uint64_t)(passed + failed > 0 ? passed + failed : 1)));
    printf("  rss baseline: %ld B\n", rss_baseline);
    printf("  rss final:    %ld B\n", rss_final);
    printf("  rss delta:    %+ld B\n", rss_final - rss_baseline);
    return failed ? 1 : 0;
}
