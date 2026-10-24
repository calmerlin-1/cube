#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/parser.h"
#include "../include/cache.h"
#include "../include/ast.h"

/* Generate N different small JS sources and parse each one twice. */
static char *make_src(int i) {
    char *buf = (char*)malloc(256);
    switch (i % 8) {
    case 0: sprintf(buf, "var x%d = %d + %d * %d;", i, i, i*2, i+1); break;
    case 1: sprintf(buf, "function f%d(a,b){return a+b+%d;}", i, i); break;
    case 2: sprintf(buf, "const c%d = [%d,%d,%d];", i, i, i+1, i+2); break;
    case 3: sprintf(buf, "let o%d = {a:%d,b:%d};", i, i, i*3); break;
    case 4: sprintf(buf, "if (a%d) b(); else c%d();", i, i); break;
    case 5: sprintf(buf, "for (let j%d=0;j%d<%d;j%d++) s+=j%d;", i, i, i%10, i, i); break;
    case 6: sprintf(buf, "x%d = y%d ? z%d : w%d;", i, i, i, i); break;
    default: sprintf(buf, "class K%d { m(){return %d} }", i, i); break;
    }
    return buf;
}

int main(void) {
    struct timespec t0, t1;
    double sec;

    /* -------- Test 1: 1000 distinct sources, each parsed once -------- */
    int N1 = 1000;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N1; i++) {
        char *src = make_src(i);
        ParseResult r = parser_parse_cached(src, "<gen>");
        parser_free_result(&r);
        free(src);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sec = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    printf("Test 1: 1000 distinct sources, one parse each: %.2f us/parse\n", sec*1e6/N1);

    ParseCacheStats s1 = parser_cache_stats();
    printf("        hits=%llu misses=%llu evictions=%llu entries=%d/%d\n",
           (unsigned long long)s1.hits, (unsigned long long)s1.misses,
           (unsigned long long)s1.evictions, s1.entries, s1.capacity);
    parser_cache_clear();

    /* -------- Test 2: 10 distinct sources, each parsed 1000 times -------- */
    int NSRC = 10;
    parser_cache_set_capacity(32);   /* 10 sources fit easily */
    int NREP = 1000;
    char *sources[10];
    for (int i = 0; i < NSRC; i++) sources[i] = make_src(i);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < NSRC * NREP; i++) {
        ParseResult r = parser_parse_cached(sources[i % NSRC], "<gen>");
        parser_free_result(&r);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sec = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    printf("Test 2: 10 sources x 1000 reps = 10000 parses: %.2f us/parse\n", sec*1e6/(NSRC*NREP));

    ParseCacheStats s2 = parser_cache_stats();
    printf("        hits=%llu misses=%llu evictions=%llu entries=%d/%d\n",
           (unsigned long long)s2.hits, (unsigned long long)s2.misses,
           (unsigned long long)s2.evictions, s2.entries, s2.capacity);
    for (int i = 0; i < NSRC; i++) free(sources[i]);
    parser_cache_clear();

    /* -------- Test 3: 100 distinct, capacity=8 -> many evictions -------- */
    parser_cache_set_capacity(8);
    for (int i = 0; i < 100; i++) {
        char *src = make_src(i);
        ParseResult r = parser_parse_cached(src, "<gen>");
        parser_free_result(&r);
        free(src);
    }
    ParseCacheStats s3 = parser_cache_stats();
    printf("Test 3: 100 distinct with cap=8: hits=%llu misses=%llu evictions=%llu\n",
           (unsigned long long)s3.hits, (unsigned long long)s3.misses,
           (unsigned long long)s3.evictions);
    parser_cache_clear();

    /* -------- Test 4: capacity=64 -------- */
    parser_cache_set_capacity(64);
    for (int i = 0; i < 100; i++) {
        char *src = make_src(i);
        ParseResult r = parser_parse_cached(src, "<gen>");
        parser_free_result(&r);
        free(src);
    }
    ParseCacheStats s4 = parser_cache_stats();
    printf("Test 4: 100 distinct with cap=64: hits=%llu misses=%llu evictions=%llu entries=%d\n",
           (unsigned long long)s4.hits, (unsigned long long)s4.misses,
           (unsigned long long)s4.evictions, s4.entries);
    parser_cache_clear();

    return 0;
}
