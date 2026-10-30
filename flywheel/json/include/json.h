/** json.h — JSON colorizer and strict JSON/JSONC validator. */
#ifndef FLYWHEEL_JSON_H
#define FLYWHEEL_JSON_H

#include <stdio.h>
#include <stddef.h>

/** Colorize JSON source with ANSI escapes. Writes to `out`.
 *  Byte-level state machine; safe on any input, no allocation.
 *  Returns 0 on success. */
int json_colorize(const char *src, size_t len, FILE *out);

/** Validation error location and message. */
typedef struct {
    size_t offset;          /* byte offset in source */
    int    line;            /* 1-based */
    int    column;          /* 1-based */
    char   message[160];
} json_error_t;

/** Validate a JSON document.
 *  allow_comments != 0 enables JSONC: // and block comments plus trailing
 *  commas in arrays/objects. Returns 0 if valid, -1 otherwise and fills
 *  err (if non-NULL). */
int json_validate(const char *src, size_t len, int allow_comments,
                  json_error_t *err);

#endif
