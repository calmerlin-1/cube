/** color.c — full ANSI color and style control. */

#include "color.h"
#include <string.h>
#include <stdlib.h>

static int g_enabled = 0;
static int g_forced  = -1;

#define S(x) x

static const char *FG_BLACK   = S("\x1b[30m");
static const char *FG_RED     = S("\x1b[31m");
static const char *FG_GREEN   = S("\x1b[32m");
static const char *FG_YELLOW  = S("\x1b[33m");
static const char *FG_BLUE    = S("\x1b[34m");
static const char *FG_MAGENTA = S("\x1b[35m");
static const char *FG_CYAN    = S("\x1b[36m");
static const char *FG_WHITE   = S("\x1b[37m");
static const char *FG_BBLACK  = S("\x1b[90m");
static const char *FG_BRED    = S("\x1b[91m");
static const char *FG_BGREEN  = S("\x1b[92m");
static const char *FG_BYELLOW = S("\x1b[93m");
static const char *FG_BBLUE   = S("\x1b[94m");
static const char *FG_BMAGENTA= S("\x1b[95m");
static const char *FG_BCYAN   = S("\x1b[96m");
static const char *FG_BWHITE  = S("\x1b[97m");

static const char *BG_BLACK   = S("\x1b[40m");
static const char *BG_RED     = S("\x1b[41m");
static const char *BG_GREEN   = S("\x1b[42m");
static const char *BG_YELLOW  = S("\x1b[43m");
static const char *BG_BLUE    = S("\x1b[44m");
static const char *BG_MAGENTA = S("\x1b[45m");
static const char *BG_CYAN    = S("\x1b[46m");
static const char *BG_WHITE   = S("\x1b[47m");

static const char *ST_BOLD      = S("\x1b[1m");
static const char *ST_DIM       = S("\x1b[2m");
static const char *ST_ITALIC    = S("\x1b[3m");
static const char *ST_UNDERLINE = S("\x1b[4m");
static const char *ST_BLINK     = S("\x1b[5m");
static const char *ST_REVERSE   = S("\x1b[7m");
static const char *ST_HIDDEN    = S("\x1b[8m");
static const char *ST_STRIKE    = S("\x1b[9m");

static const char *RS_ALL       = S("\x1b[0m");
static const char *RS_BOLD      = S("\x1b[22m");
static const char *RS_DIM       = S("\x1b[22m");
static const char *RS_ITALIC    = S("\x1b[23m");
static const char *RS_UNDERLINE = S("\x1b[24m");
static const char *RS_BLINK     = S("\x1b[25m");
static const char *RS_REVERSE   = S("\x1b[27m");
static const char *RS_HIDDEN    = S("\x1b[28m");
static const char *RS_STRIKE    = S("\x1b[29m");

static const char *EMPTY = "";

static inline const char *cc(const char *s) {
    return g_enabled ? s : EMPTY;
}

const char *col_black(void)         { return cc(FG_BLACK); }
const char *col_red(void)           { return cc(FG_RED); }
const char *col_green(void)         { return cc(FG_GREEN); }
const char *col_yellow(void)        { return cc(FG_YELLOW); }
const char *col_blue(void)          { return cc(FG_BLUE); }
const char *col_magenta(void)       { return cc(FG_MAGENTA); }
const char *col_cyan(void)          { return cc(FG_CYAN); }
const char *col_white(void)         { return cc(FG_WHITE); }

const char *col_bright_black(void)  { return cc(FG_BBLACK); }
const char *col_bright_red(void)    { return cc(FG_BRED); }
const char *col_bright_green(void)  { return cc(FG_BGREEN); }
const char *col_bright_yellow(void) { return cc(FG_BYELLOW); }
const char *col_bright_blue(void)   { return cc(FG_BBLUE); }
const char *col_bright_magenta(void){ return cc(FG_BMAGENTA); }
const char *col_bright_cyan(void)   { return cc(FG_BCYAN); }
const char *col_bright_white(void)  { return cc(FG_BWHITE); }

const char *col_bg_black(void)   { return cc(BG_BLACK); }
const char *col_bg_red(void)     { return cc(BG_RED); }
const char *col_bg_green(void)   { return cc(BG_GREEN); }
const char *col_bg_yellow(void)  { return cc(BG_YELLOW); }
const char *col_bg_blue(void)    { return cc(BG_BLUE); }
const char *col_bg_magenta(void) { return cc(BG_MAGENTA); }
const char *col_bg_cyan(void)    { return cc(BG_CYAN); }
const char *col_bg_white(void)   { return cc(BG_WHITE); }

const char *col_bold(void)      { return cc(ST_BOLD); }
const char *col_dim(void)       { return cc(ST_DIM); }
const char *col_italic(void)    { return cc(ST_ITALIC); }
const char *col_underline(void) { return cc(ST_UNDERLINE); }
const char *col_blink(void)     { return cc(ST_BLINK); }
const char *col_reverse(void)   { return cc(ST_REVERSE); }
const char *col_hidden(void)    { return cc(ST_HIDDEN); }
const char *col_strike(void)    { return cc(ST_STRIKE); }

const char *col_reset(void)          { return cc(RS_ALL); }
const char *col_reset_bold(void)     { return cc(RS_BOLD); }
const char *col_reset_dim(void)      { return cc(RS_DIM); }
const char *col_reset_italic(void)   { return cc(RS_ITALIC); }
const char *col_reset_underline(void){ return cc(RS_UNDERLINE); }
const char *col_reset_blink(void)    { return cc(RS_BLINK); }
const char *col_reset_reverse(void)  { return cc(RS_REVERSE); }
const char *col_reset_hidden(void)   { return cc(RS_HIDDEN); }
const char *col_reset_strike(void)   { return cc(RS_STRIKE); }

/* ---- 256-color ---- */
static char g_fg256_buf[16];
static char g_bg256_buf[16];

static void build_256(char *buf, int idx, int bg) {
    if (idx < 0) idx = 0;
    if (idx > 255) idx = 255;
    char tmp[4];
    int w = 0;
    int v = idx;
    if (v == 0) tmp[w++] = '0';
    while (v > 0) { tmp[w++] = (char)('0' + v % 10); v /= 10; }
    int o = 0;
    buf[o++] = '\x1b'; buf[o++] = '[';
    buf[o++] = bg ? '4' : '3';
    buf[o++] = '8';    buf[o++] = ';';
    buf[o++] = '5';    buf[o++] = ';';
    while (w > 0) buf[o++] = tmp[--w];
    buf[o++] = 'm';
    buf[o] = 0;
}

const char *col_fg256(int idx) {
    if (!g_enabled) return EMPTY;
    build_256(g_fg256_buf, idx, 0);
    return g_fg256_buf;
}

const char *col_bg256(int idx) {
    if (!g_enabled) return EMPTY;
    build_256(g_bg256_buf, idx, 1);
    return g_bg256_buf;
}

/* ---- truecolor ---- */
static char g_fg_rgb_buf[32];
static char g_bg_rgb_buf[32];

static void write_int(char *buf, int v) {
    if (v < 0) v = 0;
    if (v > 255) v = 255;
    char tmp[4];
    int w = 0;
    if (v == 0) tmp[w++] = '0';
    while (v > 0) { tmp[w++] = (char)('0' + v % 10); v /= 10; }
    while (w > 0) *buf++ = tmp[--w];
    *buf = 0;
}

static void build_rgb(char *buf, int r, int g, int b, int bg) {
    char *p = buf;
    *p++ = '\x1b'; *p++ = '[';
    *p++ = bg ? '4' : '3';
    *p++ = '8';    *p++ = ';';
    *p++ = '2';    *p++ = ';';
    write_int(p, r); p += strlen(p);
    *p++ = ';';
    write_int(p, g); p += strlen(p);
    *p++ = ';';
    write_int(p, b); p += strlen(p);
    *p++ = 'm';
    *p = 0;
}

const char *col_rgb(int r, int g, int b) {
    if (!g_enabled) return EMPTY;
    build_rgb(g_fg_rgb_buf, r, g, b, 0);
    return g_fg_rgb_buf;
}

const char *col_bg_rgb(int r, int g, int b) {
    if (!g_enabled) return EMPTY;
    build_rgb(g_bg_rgb_buf, r, g, b, 1);
    return g_bg_rgb_buf;
}

/* ---- control ---- */
void col_enable(void)     { g_enabled = 1; g_forced = 1; }
void col_disable(void)    { g_enabled = 0; g_forced = 0; }
int  col_is_enabled(void) { return g_enabled; }

#if defined(_WIN32)
  #include <io.h>
  #define FW_ISATTY(fd) _isatty(fd)
  #define FW_FILENO(fp) _fileno(fp)
#else
  #include <unistd.h>
  #define FW_ISATTY(fd) isatty(fd)
  #define FW_FILENO(fp) fileno(fp)
#endif

int col_supported(FILE *fp) {
    if (!fp) return 0;
    if (g_forced == 1) { g_enabled = 1; return 1; }
    if (g_forced == 0) { g_enabled = 0; return 0; }
    { const char *nc = getenv("NO_COLOR");
      if (nc && *nc) { g_enabled = 0; return 0; } }
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb") == 0) { g_enabled = 0; return 0; }
    int ok = FW_ISATTY(FW_FILENO(fp));
    g_enabled = ok;
    return ok;
}

void col_force(int on) {
    g_forced = on ? 1 : 0;
    g_enabled = on ? 1 : 0;
}

void col_set_enabled_for(FILE *fp, int on) {
    (void)fp;
    if (on) col_enable();
    else    col_disable();
}

const char *col_state_description(void) {
    if (g_forced == 1) return "forced-on";
    if (g_forced == 0) return "forced-off";
    return g_enabled ? "auto-on" : "auto-off";
}

/* ---- demo ---- */
void col_demo(FILE *fp) {
    if (!fp) fp = stdout;
    int was = g_enabled;
    g_enabled = 1;
    fprintf(fp, "%sBold%s  %sDim%s  %sItalic%s  %sUnderline%s  %sBlink%s  %sReverse%s  %sStrike%s\n",
            ST_BOLD, RS_ALL, ST_DIM, RS_ALL, ST_ITALIC, RS_ALL,
            ST_UNDERLINE, RS_ALL, ST_BLINK, RS_ALL,
            ST_REVERSE, RS_ALL, ST_STRIKE, RS_ALL);
    fprintf(fp, "%sRed%s %sGreen%s %sYellow%s %sBlue%s %sMagenta%s %sCyan%s %sWhite%s\n",
            FG_RED, RS_ALL, FG_GREEN, RS_ALL, FG_YELLOW, RS_ALL, FG_BLUE, RS_ALL,
            FG_MAGENTA, RS_ALL, FG_CYAN, RS_ALL, FG_WHITE, RS_ALL);
    fprintf(fp, "%sBright red%s %sBright blue%s\n",
            FG_BRED, RS_ALL, FG_BBLUE, RS_ALL);
    fprintf(fp, "%sBg red%s %sBg blue white text%s\n",
            BG_RED, RS_ALL, BG_BLUE, RS_ALL);
    for (int i = 0; i < 16; i++) {
        fprintf(fp, "%s  %d  %s", col_bg256(196 + i), i, col_reset());
    }
    fprintf(fp, "\n");
    for (int i = 0; i < 16; i++) {
        fprintf(fp, "%s  %s", col_rgb(255, i * 16, 0), col_reset());
    }
    fprintf(fp, "\n");
    g_enabled = was;
}
