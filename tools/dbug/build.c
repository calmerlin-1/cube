/** build.c — run a build command, parse compiler errors, explain them.
 *  Also: crash-log parser for text dumps (signal traces, panic logs). */

#define _GNU_SOURCE
#include "dbug.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define BUILD_LOG ".dbug.build.log"

/* ---------- clang message -> explanation ---------- */
static const char *explain(const char *msg) {
    struct { const char *pat; const char *why; } T[] = {
      {"expected expression",
       "an expression is missing. Something like `= ;` or `, )` — the compiler "
       "found `;` where it wanted a value."},
      {"expected ';' after",
       "missing semicolon at the end of the previous statement."},
      {"expected ';'",
       "missing semicolon."},
      {"expected identifier",
       "the compiler wanted a name here (variable, function, or type)."},
      {"expected ')'",
       "unclosed parenthesis. Look up for an earlier `(` that never closes."},
      {"expected '}'",
       "unclosed brace. A `{` earlier in the file has no matching `}`."},
      {"expected ']'",
       "unclosed bracket. A `[` earlier in the expression has no matching `]`."},
      {"use of undeclared identifier",
       "this name is used but never declared. Either a typo, or a missing #include."},
      {"implicit declaration of function",
       "function used without a prototype. Usually a missing #include."},
      {"incompatible pointer",
       "pointer types differ. Usually a missing cast or a wrong parameter type."},
      {"too few arguments",
       "not enough arguments for this call."},
      {"too many arguments",
       "too many arguments for this call."},
      {"no member named",
       "this struct has no field with that name. Check the struct definition."},
      {"unterminated comment",
       "a `/*` was opened but never closed with `*/`."},
      {"unterminated string",
       "a `\"` was opened but never closed on the same line."},
      {"unknown type name",
       "the compiler doesn't know this type. Missing #include or typo."},
      {"redefinition of",
       "this name is defined more than once in the same scope."},
      {"conflicting types",
        "two declarations of the same name disagree. Check the header."},
      {"incompatible integer to pointer",
       "you're storing an integer where a pointer is expected. To convert, cast: `(int *)value`."},
      {"incompatible pointer to integer",
       "you're storing a pointer where an integer is expected. Cast with `(long)` or `(intptr_t)`."},
      {"call to undeclared library function",
       "the function isn't declared before use. Add the right header: printf -> <stdio.h>, malloc -> <stdlib.h>, strlen -> <string.h>."},
      {"unterminated /* comment",
       "a block comment opened with `/*` was never closed. Add `*/` where it should end."},
      {"missing terminating",
       "a string or character literal was opened but never closed on the same line."},
      {NULL, NULL}
    };
    for (int i = 0; T[i].pat; i++)
        if (strstr(msg, T[i].pat)) return T[i].why;
    return NULL;
}

/* ---------- byte dump at column ---------- */
static void dump_bytes_at(const sear_line_t *l, int col) {
    if (col < 1 || (size_t)col > l->len) return;
    size_t start = (size_t)(col - 1);
    if (start >= 6) start -= 6; else start = 0;
    size_t end = (size_t)(col - 1) + 6;
    if (end > l->len) end = l->len;

    printf("    %sbytes at col %d:%s\n", COL.dim, col, COL.reset);
    printf("       ");
    printf("%s", COL.dim);
    for (size_t i = start; i < end; i++)
        printf("%02x ", (unsigned char)l->p[i]);
    printf("%s\n", COL.reset);

    printf("       ");
    printf("%s", COL.dim);
    for (size_t i = start; i < end; i++) {
        unsigned char c = (unsigned char)l->p[i];
        putchar((c >= 32 && c < 127) ? c : '.');
        putchar(' ');
    }
    printf("%s\n", COL.reset);
    /* caret under the target byte */
    printf("       ");
    for (size_t i = start; i < end; i++) {
        if ((size_t)(col - 1) == i) printf("%s^%s", COL.red, COL.reset);
        else putchar(' ');
        putchar(' ');
    }
    printf("\n");
}

/* ---------- context window ---------- */
static void show_context(const char *file, int line, int col, const char *msg) {
    sear_file_t f;
    if (sear_file_load(file, &f) != 0) return;

    int target = line - 1;
    if (target < 0 || (size_t)target >= f.n_lines) { sear_file_free(&f); return; }

    int lo = target - 3; if (lo < 0) lo = 0;
    int hi = target + 3; if ((size_t)hi >= f.n_lines) hi = (int)f.n_lines - 1;

    printf("    %scontext:%s\n", COL.dim, COL.reset);
    for (int i = lo; i <= hi; i++) {
        const sear_line_t *l = &f.lines[i];
        if (i == target) {
            printf("      %s%3d%s %s%s", COL.red, i + 1, COL.reset, COL.bold, COL.reset);
            /* print with a caret under col */
            printf("  %s", COL.reset);
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
            printf("          ");
            for (int k = 1; k < col && (size_t)k <= l->len; k++) putchar(' ');
            printf("%s^%s\n", COL.red, COL.reset);
        } else {
            printf("      %s%3d%s   ", COL.dim, i + 1, COL.reset);
            fwrite(l->p, 1, l->len, stdout);
            putchar('\n');
        }
    }

    const char *why = explain(msg);
    if (why) {
        printf("\n    %sWHY%s  %s\n", COL.yellow, COL.reset, why);
    }
    if (col > 0) dump_bytes_at(&f.lines[target], col);

    sear_file_free(&f);
}

/* ---------- parse one diagnostic line ---------- */
/* format: file:line:col: severity: message
   or:     file:line: severity: message */
static int parse_diag(const char *line, char *file, size_t fsz,
                      int *ln, int *col, char *sev, size_t ssz,
                      char *msg, size_t msz)
{
    const char *p = line;
    const char *colon = strchr(p, ':');
    if (!colon) return 0;

    size_t fn = (size_t)(colon - p);
    if (fn == 0 || fn >= fsz) return 0;
    memcpy(file, p, fn); file[fn] = 0;

    /* line number */
    char *end;
    long L = strtol(colon + 1, &end, 10);
    if (*end != ':' || L < 1) return 0;
    *ln = (int)L;

    /* optional column */
    *col = 0;
    const char *after = end + 1;
    if (*after >= '0' && *after <= '9') {
        long C = strtol(after, &end, 10);
        if (*end == ':') { *col = (int)C; after = end + 1; }
    }
    if (*after == ' ') after++;

    /* severity */
    const char *ssev = after;
    const char *smsg = strstr(ssev, ": ");
    if (!smsg) return 0;
    size_t sn = (size_t)(smsg - ssev);
    if (sn == 0 || sn >= ssz) return 0;
    memcpy(sev, ssev, sn); sev[sn] = 0;
    smsg += 2;

    /* strip trailing " [-Wflag]" noise that clang appends */
    size_t mlen = strlen(smsg);
    const char *wflag = strstr(smsg, " [-W");
    const char *iso   = strstr(smsg, "; ISO ");
    if (wflag) mlen = (size_t)(wflag - smsg);
    if (iso   && (size_t)(iso - smsg) < mlen) mlen = (size_t)(iso - smsg);
    if (mlen >= msz) mlen = msz - 1;
    memcpy(msg, smsg, mlen); msg[mlen] = 0;

    return 1;
}

/* ---------- parse the whole build log ---------- */
static void report_log(const char *logpath) {
    FILE *fp = fopen(logpath, "r");
    if (!fp) return;
    char line[2048];
    int n_err = 0, n_warn = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (!len) { putchar('\n'); continue; }
        /* skip clang's own continuation lines — we render better */
        { const char *t0 = line; while (*t0 == ' ' || *t0 == '\t') t0++; if (*t0 == '|' || *t0 == '^') continue; }

        {
            const char *q = line;
            while (*q == ' ' || *q == '\t') q++;
            if (*q >= '0' && *q <= '9') {
                const char *e = q;
                while (*e >= '0' && *e <= '9') e++;
                while (*e == ' ') e++;
                if (!strncmp(e, "error", 5) || !strncmp(e, "warning", 7)) continue;
                if (strstr(e, "generated.")) continue;
            }
            /* clang source echo: "   3 |  code" */
            {
                const char *t = line;
                while (*t == ' ' || *t == '\t') t++;
                if (*t >= '0' && *t <= '9') {
                    const char *e2 = t;
                    while (*e2 >= '0' && *e2 <= '9') e2++;
                    while (*e2 == ' ' || *e2 == '\t') e2++;
                    if (*e2 == '|') continue;
                }
            }
        }

        char file[512], sev[32], msg[1024];
        int ln = 0, col = 0;
        if (parse_diag(line, file, sizeof(file), &ln, &col,
                       sev, sizeof(sev), msg, sizeof(msg)))
        {
            int is_err  = !strcmp(sev, "error") || !strcmp(sev, "fatal error");
            int is_warn = !strcmp(sev, "warning");
            const char *c = is_err ? COL.red : is_warn ? COL.yellow : COL.cyan;
            const char *sym = is_err ? "✗" : is_warn ? "!" : "·";

            printf("\n  %s%s%s  %s%s:%d", c, sym, COL.reset,
                   COL.bold, file, ln);
            if (col > 0) printf(":%d", col);
            printf("%s\n", COL.reset);
            printf("    %s%s%s  %s\n", c, sev, COL.reset, msg);
            /* re-anchor: file:line:col under the error, so it is the last
             * thing the eye lands on before WHY */
            if (col > 0)
                printf("    %s→ %s:%d:%d%s\n",
                       COL.dim, file, ln, col, COL.reset);

            show_context(file, ln, col, msg);

            if (is_err) n_err++;
            else if (is_warn) n_warn++;
        } else {
            printf("  %s%s%s\n", COL.dim, line, COL.reset);
        }
    }
    fclose(fp);
    printf("\n\n  %sVERDICT%s  %s%d errors%s · %s%d warnings%s\n",
           COL.bold, COL.reset,
           n_err ? COL.red : COL.green, n_err, COL.reset,
           n_warn ? COL.yellow : COL.dim, n_warn, COL.reset);
}

/* ---------- run command, capture output ---------- */
int dbug_build(const dbug_opts_t *o) {
    if (!o->prog) { sear_err("usage: dbug build <command...>"); return 2; }

    printf("  %sBUILD%s  %s\n\n", COL.cyan, COL.reset, o->prog);

    pid_t pid = fork();
    if (pid < 0) { sear_err("fork failed: %s", strerror(errno)); return 2; }
    if (pid == 0) {
        /* redirect stdout+stderr to log */
        int fd = open(BUILD_LOG, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd < 0) _exit(127);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        execl("/bin/sh", "sh", "-c", o->prog, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    report_log(BUILD_LOG);
    unlink(BUILD_LOG);
    return rc;
}
