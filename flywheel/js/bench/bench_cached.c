#include <stdio.h>
#include <time.h>
#include "../include/parser.h"
#include "../include/cache.h"

static const char *SRC =
"function fib(n){if(n<2)return n;return fib(n-1)+fib(n-2);}"
"const x=[1,2,3].map(a=>a*2).filter(a=>a>2).reduce((a,b)=>a+b,0);"
"class A{constructor(x){this.x=x}get y(){return this.x*2}}"
"for(let i=0;i<10;i++){sum+=i}"
"try{f()}catch(e){g(e)}finally{h()}"
"const t=`hello ${name} ${x+y}`;"
"a?b:c;x=y=z=0;a+=1;b-=2;"
"async function main(){await fetch(url)}"
"let {a=1,b:{c}}=obj;"
"switch(x){case 1:a();break;default:b()}";

int main(void) {
    int N = 10000;
    parser_cache_set_capacity(64);

    for (int i = 0; i < 100; i++) {
        ParseResult r = parser_parse_cached(SRC, "<bench>");
        parser_free_result(&r);
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        ParseResult r = parser_parse_cached(SRC, "<bench>");
        parser_free_result(&r);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("  cached: %d parses of same source\n", N);
    printf("  per parse: %.1f microseconds\n", sec * 1e6 / N);
    printf("  throughput: %.0f parses/sec\n", N / sec);

    ParseCacheStats s = parser_cache_stats();
    printf("  cache: hits=%d misses=%d evictions=%d entries=%d/%d\n",
           s.hits, s.misses, s.evictions, s.entries, s.capacity);
    return 0;
}
