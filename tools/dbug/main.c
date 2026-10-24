/** main.c — arg parse + dispatch for dbug. */

#include "dbug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void dbug_usage(void) {
    fputs(
"usage:\n"
"  dbug <file.c>                 static analysis\n"
"  dbug run <binary> [args...]   run under shim, log calls\n"
"  dbug crash <logfile>          parse crash log, colorize\n"
"\n"
"flags:\n"
"  --no-color      disable color\n"
"  --verbose       more detail\n"
"  --help          this message\n"
        , stderr);
}

int main(int argc, char **argv) {
    dbug_opts_t o;
    memset(&o, 0, sizeof(o));
    o.color = 1;

    if (argc < 2) { dbug_usage(); return 2; }

    /* Skip our own argv[0], scan the rest. */
    int i = 1;
    const char *first = argv[i];

    if (!strcmp(first, "--help") || !strcmp(first, "-h")) {
        dbug_usage(); return 0;
    }
    if (!strcmp(first, "--no-color")) {
        o.color = 0; i++;
        if (i >= argc) { dbug_usage(); return 2; }
        first = argv[i];
    }

    if (!strcmp(first, "build")) {
        /* everything after "build" is the shell command, joined by spaces */
        i++;
        if (i >= argc) { dbug_usage(); return 2; }
        static char cmd[4096];
        size_t w = 0;
        for (int k = i; k < argc && w + 2 < sizeof(cmd); k++) {
            if (k > i) cmd[w++] = ' ';
            size_t al = strlen(argv[k]);
            if (w + al >= sizeof(cmd)) break;
            memcpy(cmd + w, argv[k], al);
            w += al;
        }
        cmd[w] = 0;
        o.mode = DBUG_MODE_TRACE;   /* reuse; we dispatch by presence of prog below */
        o.prog = cmd;
        sear_colors_set(o.color, isatty(1));
        return dbug_build(&o);
    }
    if (!strcmp(first, "run")) {
        o.mode = DBUG_MODE_TRACE;
        i++;
        if (i >= argc) { dbug_usage(); return 2; }
        o.prog   = argv[i++];
        o.args   = (const char **)&argv[i];
        o.n_args = argc - i;
        /* allow --no-color / --verbose anywhere after "run" */
        const char *filtered[256];
        int fn = 0;
        for (int k = 0; k < o.n_args; k++) {
            if (!strcmp(o.args[k], "--no-color")) { o.color = 0; continue; }
            if (!strcmp(o.args[k], "--verbose"))  { o.verbose = 1; continue; }
            if (fn < 256) filtered[fn++] = o.args[k];
        }
        o.args   = filtered;
        o.n_args = fn;
    }
    else if (!strcmp(first, "crash")) {
        o.mode = DBUG_MODE_CRASH;
        i++;
        if (i >= argc) { dbug_usage(); return 2; }
        o.file = argv[i];
    }
    else {
        o.mode = DBUG_MODE_STATIC;
        o.file = first;
        i++;
        for (; i < argc; i++) {
            if (!strcmp(argv[i], "--no-color")) o.color = 0;
            else if (!strcmp(argv[i], "--verbose")) o.verbose = 1;
            else { fprintf(stderr, "dbug: unknown arg %s\n", argv[i]); return 2; }
        }
    }

    int force = 0;
    for (int k = 0; k < argc; k++)
        if (!strcmp(argv[k], "--force-color")) { force = 1; break; }
    if (force) sear_colors_set(1, 1);
    else       sear_colors_set(o.color, isatty(1));

    switch (o.mode) {
    case DBUG_MODE_STATIC: return dbug_static(&o);
    case DBUG_MODE_TRACE:  return dbug_trace(&o);
    case DBUG_MODE_CRASH:  return dbug_crash(&o);
    }
    return 2;
}
