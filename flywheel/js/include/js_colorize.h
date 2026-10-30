/** js_colorize.h — ANSI syntax highlighting for JavaScript source. */
#ifndef FLYWHEEL_JS_COLORIZE_H
#define FLYWHEEL_JS_COLORIZE_H

#include <stdio.h>
#include <stddef.h>

int js_colorize(const char *src, size_t len, FILE *out);

#endif
