/** output.c — every formatted print + color handling. */

#include "sear.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

sear_colors_t COL;

void sear_colors_set(int enable, int is_tty) {
    int on = enable && is_tty;
    COL.reset    = on ? "\033[0m"    : "";
    COL.bold     = on ? "\033[1m"    : "";
    COL.dim      = on ? "\033[2m"    : "";
    COL.cyan     = on ? "\033[36m"   : "";
    COL.dim_cyan = on ? "\033[2;36m" : "";
    COL.yellow   = on ? "\033[33m"   : "";
    COL.red      = on ? "\033[31m"   : "";
    COL.green    = on ? "\033[32m"   : "";
}

/* Write `color + text + reset` to fp. Handles empty color strings. */
static void puts_c(FILE *fp, const char *color, const char *text) {
    if (color && *color) fputs(color, fp);
    fputs(text, fp);
    if (color && *color) fputs(COL.reset, fp);
}

void sear_err(const char *fmt, ...) {
    va_list ap;
    if (*COL.red) fputs(COL.red, stderr);
    fputs("sear: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*COL.reset) fputs(COL.reset, stderr);
    fputc('\n', stderr);
}

void sear_warn(const char *fmt, ...) {
    va_list ap;
    if (*COL.yellow) fputs(COL.yellow, stderr);
    fputs("sear: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*COL.reset) fputs(COL.reset, stderr);
    fputc('\n', stderr);
}

/* 1-based character column of a byte offset. */
size_t sear_col_of_match(const char *line, size_t len, size_t off) {
    (void)len;
    size_t col = 1;
    for (size_t i = 0; i < off; i++) {
        unsigned char c = (unsigned char)line[i];
        if ((c & 0xC0) != 0x80) col++;
    }
    return col;
}

void sear_ws_annot(char *out, size_t cap, const sear_line_t *l) {
    if (l->lead_sp == 0 && l->lead_tab == 0) {
        snprintf(out, cap, "[     0 ]");
    } else if (l->lead_tab == 0) {
        snprintf(out, cap, "[ %2dsp ]", l->lead_sp);
    } else if (l->lead_sp == 0) {
        snprintf(out, cap, "[ %2dtab]", l->lead_tab);
    } else {
        snprintf(out, cap, "[%2dsp+tab]", l->lead_sp);
    }
}

/* Print a byte range with visible markers on whitespace. */
static void emit_visible(FILE *fp, const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (c == ' ')      fputs("·", fp);
        else if (c == '\t') fputs("→", fp);
        else                fputc(c, fp);
    }
}

void sear_print_line_detail(FILE *fp, const sear_line_t *l, size_t match_off,
                            int show_match_col)
{
    char ws[32];
    sear_ws_annot(ws, sizeof(ws), l);

    fprintf(fp, "  %sL%-5zu%s", COL.cyan, l->line_no, COL.reset);
    if (show_match_col && match_off != SIZE_MAX) {
        fprintf(fp, " %sC%-4zu%s", COL.dim_cyan,
                sear_col_of_match(l->p, l->len, match_off), COL.reset);
    } else {
        fputs("       ", fp);
    }

    int warn = (l->lead_sp > 0 && l->lead_tab > 0);
    fprintf(fp, " %s%s%s ", warn ? COL.yellow : COL.dim, ws, COL.reset);

    size_t n = l->len;
    size_t trail_start = n;
    while (trail_start > 0 &&
           (l->p[trail_start-1] == ' ' || l->p[trail_start-1] == '\t'))
        trail_start--;

    if (trail_start > 0)
        fwrite(l->p, 1, trail_start, fp);
    if (trail_start < n) {
        puts_c(fp, COL.red, "");
        emit_visible(fp, l->p + trail_start, n - trail_start);
        if (*COL.reset) fputs(COL.reset, fp);
    }
    if (l->cr) puts_c(fp, COL.red, "\u240D");

    if (trail_start < n) puts_c(fp, COL.red, "  \u27F5 TW");
    if (l->cr)           puts_c(fp, COL.red, "  \u27F5 CR");
    if (warn)            puts_c(fp, COL.yellow, "  \u27F5 MIXED");
    fputc('\n', fp);
}

void sear_print_line_plain(FILE *fp, const sear_line_t *l) {
    char ws[32];
    sear_ws_annot(ws, sizeof(ws), l);
    fprintf(fp, "  %sL%-5zu%s %s%s%s ",
            COL.cyan, l->line_no, COL.reset,
            COL.dim, ws, COL.reset);
    if (l->len == 0) {
        puts_c(fp, COL.dim, "(blank)");
    } else {
        fwrite(l->p, 1, l->len, fp);
    }
    if (l->cr) puts_c(fp, COL.red, "\u240D");
    fputc('\n', fp);
}
