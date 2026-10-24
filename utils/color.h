/** color.h — full ANSI color and style control.
 *  Returns empty strings when disabled. */

#ifndef FLY_UTILS_COLOR_H
#define FLY_UTILS_COLOR_H

#include <stdio.h>
#include <stdint.h>

/* ---- foreground ---- */
const char *col_black(void);
const char *col_red(void);
const char *col_green(void);
const char *col_yellow(void);
const char *col_blue(void);
const char *col_magenta(void);
const char *col_cyan(void);
const char *col_white(void);

/* ---- bright foreground ---- */
const char *col_bright_black(void);
const char *col_bright_red(void);
const char *col_bright_green(void);
const char *col_bright_yellow(void);
const char *col_bright_blue(void);
const char *col_bright_magenta(void);
const char *col_bright_cyan(void);
const char *col_bright_white(void);

/* ---- background ---- */
const char *col_bg_black(void);
const char *col_bg_red(void);
const char *col_bg_green(void);
const char *col_bg_yellow(void);
const char *col_bg_blue(void);
const char *col_bg_magenta(void);
const char *col_bg_cyan(void);
const char *col_bg_white(void);

/* ---- style ---- */
const char *col_bold(void);
const char *col_dim(void);
const char *col_italic(void);
const char *col_underline(void);
const char *col_blink(void);
const char *col_reverse(void);
const char *col_hidden(void);
const char *col_strike(void);

/* ---- reset ---- */
const char *col_reset(void);
const char *col_reset_bold(void);
const char *col_reset_dim(void);
const char *col_reset_italic(void);
const char *col_reset_underline(void);
const char *col_reset_blink(void);
const char *col_reset_reverse(void);
const char *col_reset_hidden(void);
const char *col_reset_strike(void);

/* ---- 256-color palette ---- */
const char *col_fg256(int idx);
const char *col_bg256(int idx);

/* ---- truecolor RGB ---- */
const char *col_rgb(int r, int g, int b);
const char *col_bg_rgb(int r, int g, int b);

/* ---- control ---- */
void col_enable(void);
void col_disable(void);
int  col_is_enabled(void);
int  col_supported(FILE *fp);
void col_force(int on);
void col_set_enabled_for(FILE *fp, int on);
const char *col_state_description(void);

/* ---- debug ---- */
void col_demo(FILE *fp);

#endif
