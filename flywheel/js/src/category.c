/** category.c — side table for per-node classification.
 * Hash by pointer, linear probe, bounded. */

#include "category.h"
#include "../include/ast.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int g_cat_enabled = 0;

#define CAT_TABLE_SIZE 4096
#define CAT_EMPTY ((const void *)0)

typedef struct {
    const void *key;
    cat_state_t state;
} cat_slot_t;

static cat_slot_t g_table[CAT_TABLE_SIZE];
static uint32_t   g_used = 0;

/* FNV-1a over the pointer's bytes. */
static uint32_t hash_ptr(const void *p) {
    uintptr_t v = (uintptr_t)p;
    uint32_t h = 2166136261u;
    for (int i = 0; i < (int)sizeof(v); i++) {
        h ^= (uint8_t)(v >> (i * 8));
        h *= 16777619u;
    }
    return h;
}

cat_state_t *cat_get(const void *node) {
    if (!node) return NULL;

    uint32_t idx = hash_ptr(node) & (CAT_TABLE_SIZE - 1);
    uint32_t start = idx;
    for (;;) {
        if (g_table[idx].key == CAT_EMPTY) {
            g_table[idx].key = node;
            memset(&g_table[idx].state, 0, sizeof(cat_state_t));
            g_used++;
            return &g_table[idx].state;
        }
        if (g_table[idx].key == node) {
            return &g_table[idx].state;
        }
        idx = (idx + 1) & (CAT_TABLE_SIZE - 1);
        if (idx == start) {
            /* full — ignore new entries */
            return NULL;
        }
    }
}

void cat_classify(cat_state_t *s) {
    if (!s) return;
    if (s->count < 3) { s->category = CAT_COLD_ONESHOT; return; }
    /* Fast path: same kind seen many times consecutively = monomorphic */
    if (s->count > 100 && s->same_type_run > 50) {
        s->category = CAT_HOT_NUMERIC;   /* placeholder; refine per-kind later */
        return;
    }
    if (s->same_type_run == s->count && s->count > 20) {
        s->category = CAT_MONO_CALL;
        return;
    }
    /* Otherwise leave unclassified for now */
    s->category = CAT_UNCLASSIFIED;
}

const char *cat_name(category_t c) {
    switch (c) {
        case CAT_UNCLASSIFIED: return "UNCLASSIFIED";
        case CAT_COLD_ONESHOT: return "COLD_ONESHOT";
        case CAT_HOT_NUMERIC:  return "HOT_NUMERIC";
        case CAT_HOT_LOOP:     return "HOT_LOOP";
        case CAT_MONO_CALL:    return "MONO_CALL";
        case CAT_LOOKUP_BOUND: return "LOOKUP_BOUND";
        case CAT_POLY:         return "POLY";
        case CAT_DYNAMIC:      return "DYNAMIC";
        default:               return "?";
    }
}

void cat_reset(void) {
    memset(g_table, 0, sizeof(g_table));
    g_used = 0;
}

void cat_dump(void) {
    uint64_t counts[CAT__MAX] = {0};
    uint64_t times[CAT__MAX] = {0};
    uint64_t totals[CAT__MAX] = {0};
    uint32_t nodes[CAT__MAX] = {0};

    for (uint32_t i = 0; i < CAT_TABLE_SIZE; i++) {
        if (g_table[i].key == CAT_EMPTY) continue;
        cat_state_t *s = &g_table[i].state;
        cat_classify(s);
        counts[s->category] += s->count;
        times[s->category]  += s->total_time_ns;
        totals[s->category] += s->self_time_ns;
        nodes[s->category]++;
    }

    printf("%-18s  %6s  %10s  %14s  %8s\n",
           "Category", "Nodes", "Runs", "Total ns", "% of time");
    printf("------------------  ------  ----------  --------------  --------\n");

    uint64_t grand_total = 0;
    for (int i = 0; i < CAT__MAX; i++) grand_total += times[i];
    if (grand_total == 0) grand_total = 1;

    for (int i = 0; i < CAT__MAX; i++) {
        if (nodes[i] == 0) continue;
        printf("%-18s  %6u  %10llu  %14llu  %7.1f%%\n",
               cat_name((category_t)i),
               nodes[i],
               (unsigned long long)counts[i],
               (unsigned long long)times[i],
               (double)times[i] * 100.0 / (double)grand_total);
    }
    printf("\n  total observed: %u nodes, %llu runs, %llu ns\n",
           g_used,
           (unsigned long long)counts[0] +
           (unsigned long long)counts[1] +
           (unsigned long long)counts[2] +
           (unsigned long long)counts[3] +
           (unsigned long long)counts[4] +
           (unsigned long long)counts[5] +
           (unsigned long long)counts[6] +
           (unsigned long long)counts[7],
           (unsigned long long)grand_total);
}
