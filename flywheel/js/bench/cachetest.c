#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/cache.h"
#include "../include/ast.h"

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
    struct timespec t0, t1;
    int N = 100000;
    double sec;

    /* warm up: first parse populates the cache */
    { ParseResult r = parser_parse_cached(SRC, "<x>"); parser_free_result(&r); }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        ParseResult r = parser_parse_cached(SRC, "<x>");
        parser_free_result(&r);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sec = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    printf("cached:  %.2f us/parse  (%d pars/sec)\n", sec*1e6/N, (int)(N/sec));

    ParseCacheStats s = parser_cache_stats();
    printf("stats:   hits=%llu misses=%llu evictions=%llu entries=%d/%d\n",
           (unsigned long long)s.hits, (unsigned long long)s.misses,
           (unsigned long long)s.evictions, s.entries, s.capacity);

    parser_cache_clear();
    return 0;
}
