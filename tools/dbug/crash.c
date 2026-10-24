/** crash.c — Pass 3: parse text crash logs (tombstone, dmesg, gdb). */

#define _GNU_SOURCE
#include "dbug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct sig_info { int num; const char *name; const char *what; const char *why; };

static const struct sig_info SIGS[] = {
    {4,  "SIGILL",  "illegal instruction",
         "the CPU hit an instruction it cannot execute. Binary built for a different CPU, or corrupted code."},
    {6,  "SIGABRT", "aborted",
         "abort() called, or a runtime check failed: double free, malloc heap corruption, assertion, C++ throw with no handler."},
    {7,  "SIGBUS",  "bus error",
         "misaligned memory access, or mmap region used past its end. Different from SIGSEGV: the address was valid but the access was wrong."},
    {8,  "SIGFPE",  "floating point exception",
         "integer division by zero, or an invalid arithmetic op. Note: fires on integer math, not floating."},
    {9,  "SIGKILL", "killed",
         "process killed externally. Usually the OOM killer, or `kill -9` from another process."},
    {11, "SIGSEGV", "segmentation fault",
         "invalid memory access. Common causes: NULL pointer dereference, buffer overflow, use after free, stack overflow."},
    {13, "SIGPIPE", "broken pipe",
         "wrote to a pipe or socket whose reader is gone. Common when piping through `head`."},
    {0, NULL, NULL, NULL}
};

static const struct sig_info *sig_by_num(int n) {
    for (int i = 0; SIGS[i].name; i++) if (SIGS[i].num == n) return &SIGS[i];
    return NULL;
}

static void explain_addr(unsigned long a) {
    if (a == 0)
        printf("    %sWHY%s  NULL pointer dereference. The code used a pointer that was never set.\n",
               COL.yellow, COL.reset);
    else if (a < 0x1000)
        printf("    %sWHY%s  near-NULL dereference at 0x%lx. A pointer that should have been set is off by a small offset.\n",
               COL.yellow, COL.reset, a);
    else if (a < 0x10000)
        printf("    %sWHY%s  low-address dereference at 0x%lx. Likely an uninitialized pointer used as a base.\n",
               COL.yellow, COL.reset, a);
    else if (a >= 0xf000000000000000UL)
        printf("    %sWHY%s  high-address dereference. Corrupted pointer or a stack smash.\n",
               COL.yellow, COL.reset);
    else
        printf("    %sWHY%s  wild address 0x%lx. Not NULL, so the pointer held garbage.\n",
               COL.yellow, COL.reset, a);
}

static void print_frame(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;

    /* function name in parens, if any */
    const char *open = strchr(p, '(');
    const char *close = open ? strchr(open, ')') : NULL;

    printf("    ");
    if (open) {
        printf("%s%.*s%s", COL.cyan, (int)(open - p), p, COL.reset);
        printf("%s%.*s%s",
               COL.bold,
               (int)(close ? (close - open + 1) : (int)strlen(open)),
               open, COL.reset);
    } else {
        printf("%s%s%s", COL.cyan, p, COL.reset);
    }

    /* source file:line reference */
    const char *colon = strstr(line, ".c:");
    if (!colon) colon = strstr(line, ".h:");
    if (!colon) colon = strstr(line, ".cpp:");
    if (colon) {
        const char *s = colon;
        while (s > line && s[-1] != ' ' && s[-1] != '\t') s--;
        printf("  %s-> %s%s", COL.dim, s, COL.reset);
    }
    putchar('\n');
}

int dbug_crash(const dbug_opts_t *o) {
    if (!o->file) { sear_err("usage: dbug crash <logfile>"); return 2; }
    FILE *fp = fopen(o->file, "r");
    if (!fp) { sear_err("cannot open %s", o->file); return 2; }

    printf("  %sCRASH%s  %s\n", COL.bold, COL.reset, o->file);

    char line[4096];
    int sig_num = 0;
    unsigned long fault = 0;
    int have_fault = 0;
    int frames = 0;
    int in_bt = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len && (line[len-1]=='\n' || line[len-1]=='\r')) line[--len] = 0;

        /* Android tombstone: signal N (SIGXXX), ... fault addr 0xNNN */
        const char *sp = strstr(line, "signal ");
        if (sp && (sp == line || sp[-1] == ' ')) {
            int n = 0;
            if (sscanf(sp, "signal %d", &n) == 1) {
                sig_num = n;
                const struct sig_info *si = sig_by_num(n);
                printf("\n  %sSIGNAL%s  %d", COL.red, COL.reset, n);
                if (si) printf("  %s%s%s  %s%s%s", COL.bold, si->name, COL.reset,
                                COL.dim, si->what, COL.reset);
                putchar('\n');
                if (si) printf("\n    %sWHAT%s  %s\n", COL.cyan, COL.reset, si->why);
                const char *fa = strstr(sp, "fault addr 0x");
                if (fa) { fault = strtoul(fa + 13, NULL, 16); have_fault = 1; }
                continue;
            }
        }

        /* dmesg: prog[pid]: segfault at ADDR ip IP sp SP error E in ... */
        const char *sg = strstr(line, "segfault at ");
        if (sg) {
            unsigned long a = strtoul(sg + 12, NULL, 16);
            sig_num = 11; fault = a; have_fault = 1;
            printf("\n  %sSIGNAL%s  11  %sSIGSEGV%s  %ssegmentation fault%s\n",
                   COL.red, COL.reset, COL.bold, COL.reset, COL.dim, COL.reset);
            printf("\n    %sWHAT%s  invalid memory access. NULL deref, buffer overflow, use-after-free, or stack overflow.\n",
                   COL.cyan, COL.reset);
            continue;
        }

        /* gdb: "Program received signal SIGSEGV, Segmentation fault." */
        const char *gdb = strstr(line, "Program received signal ");
        if (gdb) {
            if      (strstr(gdb, "SIGSEGV")) sig_num = 11;
            else if (strstr(gdb, "SIGABRT")) sig_num = 6;
            else if (strstr(gdb, "SIGFPE"))  sig_num = 8;
            else if (strstr(gdb, "SIGILL"))  sig_num = 4;
            else if (strstr(gdb, "SIGBUS"))  sig_num = 7;
            else if (strstr(gdb, "SIGPIPE")) sig_num = 13;
            const struct sig_info *si = sig_by_num(sig_num);
            printf("\n  %sSIGNAL%s  %d  %s%s%s",
                   COL.red, COL.reset, sig_num,
                   COL.bold, si ? si->name : "unknown", COL.reset);
            if (si) printf("  %s%s%s", COL.dim, si->what, COL.reset);
            putchar('\n');
            if (si) printf("\n    %sWHAT%s  %s\n", COL.cyan, COL.reset, si->why);
            continue;
        }

        if (strstr(line, "backtrace") || strstr(line, "Backtrace")) {
            in_bt = 1;
            printf("\n  %sBACKTRACE%s\n", COL.cyan, COL.reset);
            continue;
        }

        const char *t = line;
        while (*t==' ' || *t=='\t') t++;
        if (*t == '#') {
            if (!in_bt) { printf("\n  %sBACKTRACE%s\n", COL.cyan, COL.reset); in_bt = 1; }
            print_frame(line);
            frames++;
        }
    }
    fclose(fp);

    if (have_fault) {
        printf("\n    %sFAULT%s   0x%lx\n", COL.cyan, COL.reset, fault);
        explain_addr(fault);
    }

    printf("\n  %sVERDICT%s  ", COL.bold, COL.reset);
    if (sig_num) {
        const struct sig_info *si = sig_by_num(sig_num);
        printf("%s%s%s", COL.red, si ? si->name : "unknown signal", COL.reset);
        if (have_fault) printf(" at 0x%lx", fault);
    } else {
        printf("%sno signal found in log%s", COL.dim, COL.reset);
    }
    if (frames) printf("  ·  %d frames", frames);
    putchar('\n');
    return sig_num ? 1 : 0;
}
