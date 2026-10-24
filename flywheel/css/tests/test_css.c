/** test_css.c — CSS parser test suite. */

#include "../include/css.h"
#include "../src/tokenizer/css_token.h"
#include "../src/parser/css_selector.h"
#include "../src/runtime/arena.h"
#include "../src/runtime/platform.h"
#include <stdio.h>
#include <string.h>

static int passed = 0, failed = 0;

static void check(int cond, const char *msg) {
    if (cond) { passed++; printf("  PASS  %s\n", msg); }
    else      { failed++; printf("  FAIL  %s\n", msg); }
}

static void test_simple_rule(void) {
    printf("\n=== simple rule ===\n");
    const char *src = ".foo { color: red; }";
    css_stylesheet_t *ss = css_parse(src, strlen(src));
    check(ss != NULL, "parse succeeds");
    if (!ss) return;
    check(ss->n_rules == 1, "1 rule");
    if (ss->n_rules == 1) {
        css_rule_t *r = &ss->rules[0];
        check(r->kind == RULE_STYLE, "rule is STYLE");
        check(r->selectors.n == 1, "1 selector");
        check(r->n_decls == 1, "1 declaration");
        if (r->n_decls == 1) {
            check(r->decls[0].prop_len == 5, "prop is 5 chars");
            check(memcmp(r->decls[0].prop, "color", 5) == 0, "prop == color");
        }
    }
    css_dump(ss);
    css_free(ss);
}

static void test_multiple_rules(void) {
    printf("\n=== multiple rules ===\n");
    const char *src =
        "body { margin: 0; }\n"
        "h1, h2 { font-weight: bold; color: #333; }\n"
        ".container .item:hover > a { text-decoration: none; }\n";
    css_stylesheet_t *ss = css_parse(src, strlen(src));
    check(ss != NULL, "parse succeeds");
    if (ss) {
        check(ss->n_rules == 3, "3 rules");
        if (ss->n_rules >= 2) {
            check(ss->rules[1].selectors.n == 2, "rule 2 has 2 selectors");
        }
        css_dump(ss);
        css_free(ss);
    }
}

static void test_at_media(void) {
    printf("\n=== @media ===\n");
    const char *src =
        "@media (max-width: 600px) {\n"
        "  .foo { color: blue; }\n"
        "}\n";
    css_stylesheet_t *ss = css_parse(src, strlen(src));
    check(ss != NULL, "parse succeeds");
    if (ss) {
        check(ss->n_rules >= 1, "at least 1 rule");
        if (ss->n_rules > 0) {
            check(ss->rules[0].kind == RULE_AT_MEDIA, "@media detected");
        }
        css_dump(ss);
        css_free(ss);
    }
}

static void test_comments(void) {
    printf("\n=== comments ===\n");
    const char *src =
        "/* header */\n"
        ".a { color: red; /* inline */ }\n"
        "/* tail */\n";
    css_stylesheet_t *ss = css_parse(src, strlen(src));
    check(ss != NULL, "parse succeeds");
    if (ss) {
        check(ss->n_rules == 1, "1 rule");
        css_free(ss);
    }
}

static void test_real_world(void) {
    printf("\n=== real-world fragment ===\n");
    const char *src =
        "* { box-sizing: border-box; }\n"
        "html, body { margin: 0; padding: 0; font-family: -apple-system, sans-serif; }\n"
        "a:hover, a:focus { color: #0055cc; text-decoration: underline; }\n"
        "input[type=\"text\"], input[type=\"email\"] { border: 1px solid #ccc; }\n"
        ".grid > .col + .col { margin-left: 20px; }\n"
        "@import url(\"fonts.css\");\n"
        "@media screen and (min-width: 768px) {\n"
        "  .sidebar { width: 250px; }\n"
        "}\n";
    css_stylesheet_t *ss = css_parse(src, strlen(src));
    check(ss != NULL, "parse succeeds");
    if (ss) {
        check(ss->n_rules >= 6, "at least 6 rules");
        css_dump(ss);
        css_free(ss);
    }
}

static void test_specificity(void) {
    printf("\n=== specificity ===\n");
    css_selector_t sel;
    memset(&sel, 0, sizeof(sel));
    const char *src = "#main .item:hover";
    css_lexer_t lx;
    css_lexer_init(&lx, src, strlen(src));
    css_arena_t *ar = css_arena_new(1024);
    css_parse_one_selector(&lx, ar, &sel);
    check(sel.spec_a == 1, "1 id");
    check(sel.spec_b >= 2, "2 classes/pseudo");
    check(sel.spec_c == 0, "0 elements");
    printf("  specificity: (%u,%u,%u)\n", sel.spec_a, sel.spec_b, sel.spec_c);
    css_arena_free(ar);
}

static void test_cache_hits(void) {
    printf("\n=== cache ===\n");
    css_cache_enable(1);
    css_cache_clear();

    const char *src = ".a { color: red; } .b { color: blue; }";
    size_t len = strlen(src);

    /* First parse — miss */
    const css_stylesheet_t *ss1 = css_parse_cached(src, len);
    check(ss1 != NULL, "first parse ok");

    /* Second parse — hit */
    uint64_t t0 = plat_now_ns();
    const css_stylesheet_t *ss2 = css_parse_cached(src, len);
    uint64_t dt = plat_now_ns() - t0;
    check(ss2 == ss1, "cache returns same pointer");

    /* Third parse — hit, verify speed */
    t0 = plat_now_ns();
    for (int i = 0; i < 1000; i++) {
        const css_stylesheet_t *s3 = css_parse_cached(src, len);
        (void)s3;
    }
    dt = plat_now_ns() - t0;

    css_cache_stats_t st;
    css_cache_stats(&st);
    printf("  cache: sheet hits=%llu misses=%llu\n",
           (unsigned long long)st.sheet_hits,
           (unsigned long long)st.sheet_misses);
    printf("  1000 cached parses: %llu ns total, %llu ns each\n",
           (unsigned long long)dt, (unsigned long long)(dt / 1000));
    check(st.sheet_hits >= 1000, "at least 1000 cache hits");
    check(dt / 1000 < 200, "cached parse under 200 ns");
}

int main(void) {
    printf("=== CSS parser test suite ===\n");
    test_simple_rule();
    test_multiple_rules();
    test_at_media();
    test_comments();
    test_real_world();
    test_specificity();
    test_cache_hits();

    printf("\n=== summary ===\n");
    printf("  passed: %d\n", passed);
    printf("  failed: %d\n", failed);
    return failed ? 1 : 0;
}
