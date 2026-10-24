/** trace.c — Pass 2: LD_PRELOAD trace.  Not supported on Termux/bionic.
 *
 * bionic's dynamic linker recurses into malloc() the moment our hook tries
 * dlsym(RTLD_NEXT, ...), which crashes the child before the shim can log
 * anything.  No workaround without root.  We refuse with a clear message
 * and point at the passes that DO work here.
 */
#include "dbug.h"
#include <stdio.h>
#include <unistd.h>

int dbug_trace(const dbug_opts_t *o) {
    printf("  %strace%s  %s\n\n", COL.cyan, COL.reset, o->prog ? o->prog : "(none)");

    fprintf(stderr,
        "  %snot supported on this platform%s\n\n"
        "  Reason: Termux runs on bionic, whose linker recurses into\n"
        "  malloc() from dlsym() before an LD_PRELOAD shim can bootstrap.\n"
        "  The child crashes with SIGSEGV before any event is logged.\n\n"
        "  Try instead:\n"
        "    %sdbug <file.c>%s                static walk of the source\n"
        "    %sdbug build \"cc ...\"%s        compile and explain errors\n"
        "    %sdbug crash <logfile>%s         parse a crash log\n\n"
        "  Live tracing works on Linux with glibc or musl.\n",
        COL.yellow, COL.reset,
        COL.bold, COL.reset,
        COL.bold, COL.reset,
        COL.bold, COL.reset);

    return 2;
}
