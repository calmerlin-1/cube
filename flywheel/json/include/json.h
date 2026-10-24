/** json.h — minimal JSON syntax colorizer. */
#ifndef FLYWHEEL_JSON_H
#define FLYWHEEL_JSON_H

#include <stdio.h>
#include <stddef.h>

/** Colorize JSON source with ANSI escapes. Writes to `out`.
 *  Byte-level state machine; safe on any input, no allocation.
 *  Returns 0 on success. */
int json_colorize(const char *src, size_t len, FILE *out);

#endif
