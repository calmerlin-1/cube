/** bench_baseline.c — portable baseline benchmark.
 * Reports: cold parse, cached parse, Interp setup, eval cost.
 * Writes results to bench/baseline.txt. */

#include "parser.h"
#include "cache.h"
#include "interp.h"
#include "platform.h"
#include "os_sensors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const int REFERENCE_MHZ = 2000;

static void report(const char *name, uint64_t ns, int iters,
                   int freq_start_mhz, int freq_end_mhz, int temp_start_c10) {
    double ns_per_op = (double)ns / iters;
    double ops_per_sec = (double)iters * 1e9 / ns;

    int freq_mid = (freq_start_mhz > 0 && freq_end_mhz > 0)
                     ? (freq_start_mhz + freq_end_mhz) / 2
                     : 0;

    uint64_t norm_ns = os_sensor_normalize_ns(ns, freq_mid, REFERENCE_MHZ);
    double norm_ns_per_op = (double)norm_ns / iters;
    double norm_ops = (double)iters * 1e9 / (double)norm_ns;

    printf("  %-28s %8.1f ns/op", name, ns_per_op);
    if (freq_mid) {
        printf("  @%4d MHz  norm %6.1f ns/op  (%6.0f vs %6.0f ops/s)",
               freq_mid, norm_ns_per_op, ops_per_sec, norm_ops);
    } else {
        printf("  %6.0f ops/s", ops_per_sec);
    }
    if (temp_start_c10 >= 0) {
        printf("  %d.%d°C", temp_start_c10 / 10, temp_start_c10 % 10);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    int N = 10000;
    for (int i = 1; i < argc; i++)
        if (!strncmp(argv[i], "--n=", 4)) N = atoi(argv[i] + 4);

    printf("=== flywheel baseline benchmark ===\n");
    printf("  platform:  %s  arch:  %s\n", plat_name(), plat_arch());
    printf("  iterations: %d\n\n", N);

    /* --- cold parse --- */
    uint64_t t0 = plat_now_ns();
    for (int i = 0; i < N; i++) {
        ParseResult r = parser_parse(SRC, "<bench>");
        parser_free_result(&r);
    }
    uint64_t dt = plat_now_ns() - t0;
    os_sensor_reading_t sA, sB; os_sensor_read(&sA); report("cold parse", dt, N, sA.freq_mhz, sA.freq_mhz, sA.temp_c10);

    /* --- cached parse --- */
    /* Note: do NOT free the result. The cache owns the arena. */
    parser_cache_set_capacity(64);
    parser_parse_cached(SRC, "<bench>");  /* warm */
    t0 = plat_now_ns();
    for (int i = 0; i < N; i++) {
        ParseResult r = parser_parse_cached(SRC, "<bench>");
        (void)r;
    }
    dt = plat_now_ns() - t0;
    os_sensor_reading_t sc1, sc2; os_sensor_read(&sc1); report("cached parse", dt, N, sc1.freq_mhz, sc1.freq_mhz, sc1.temp_c10);
    {
        ParseCacheStats cs = parser_cache_stats();
        printf("  cache: hits=%llu misses=%llu entries=%d/%d evictions=%llu\n",
               (unsigned long long)cs.hits, (unsigned long long)cs.misses,
               cs.entries, cs.capacity,
               (unsigned long long)cs.evictions);
    }

    /* --- fresh Interp + natives + eval --- */
    t0 = plat_now_ns();
    for (int i = 0; i < N / 10; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, "1+2*3-4/2", "<b>");
        (void)r;
        flywheel_free(I);
    }
    dt = plat_now_ns() - t0;
    os_sensor_reading_t sf1, sf2; os_sensor_read(&sf1); report("fresh Interp + eval expr", dt, N / 10, sf1.freq_mhz, sf1.freq_mhz, sf1.temp_c10);

    /* --- reuse Interp --- */
    Interp *I = flywheel_new();
    flywheel_load_natives(I);
    t0 = plat_now_ns();
    for (int i = 0; i < N; i++) {
        FlyResult r = flywheel_eval(I, "1+2*3-4/2", "<b>");
        (void)r;
    }
    dt = plat_now_ns() - t0;
    os_sensor_reading_t sr1, sr2; os_sensor_read(&sr1); report("reuse Interp, eval expr", dt, N, sr1.freq_mhz, sr1.freq_mhz, sr1.temp_c10);
    flywheel_free(I);

    /* --- long-running workloads --- */
    struct { const char *label; const char *src; int iters; } cases[] = {
        {"loop 100",          "let s=0; for(let i=0;i<100;i=i+1) s+=i; s",              1000},
        {"loop 1k",           "let s=0; for(let i=0;i<1000;i=i+1) s+=i; s",              100},
        {"fib(15)",           "function f(n){if(n<2)return n;return f(n-1)+f(n-2);} f(15)", 100},
        {"array push 100",    "let a=[]; for(let i=0;i<100;i=i+1) a.push(i); a.length",   100},
        {"string concat 100", "let s=''; for(let i=0;i<100;i=i+1) s=s+'x'; s.length",     100},
    };
    printf("\n  workloads:\n");
    for (size_t c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
        Interp *Ii = flywheel_new();
        flywheel_load_natives(Ii);
        /* warmup */
        for (int w = 0; w < 3; w++) flywheel_eval(Ii, cases[c].src, "<w>");
        t0 = plat_now_ns();
        for (int i = 0; i < cases[c].iters; i++) {
            FlyResult r = flywheel_eval(Ii, cases[c].src, "<w>");
            (void)r;
        }
        dt = plat_now_ns() - t0;
        os_sensor_reading_t sw; os_sensor_read(&sw); report(cases[c].label, dt, cases[c].iters, sw.freq_mhz, sw.freq_mhz, sw.temp_c10);
        flywheel_free(Ii);
    }

    long rss = plat_rss_bytes();
    printf("\n  rss: %ld bytes\n", rss);
    return 0;
}
