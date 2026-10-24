/** css.h — CSS parser public API. */

#ifndef FLYWHEEL_CSS_H
#define FLYWHEEL_CSS_H

#include <stdio.h>

#include "css_types.h"

/** Parse a CSS stylesheet. Returns NULL on catastrophic error.
 *  Recoverable errors leave partial output; check `css_has_error`.
 *  Caller must free with css_free(). */
css_stylesheet_t *css_parse(const char *source, size_t len);

/** Free a stylesheet and its arena. */
void css_free(css_stylesheet_t *s);

/* ---- Caches (opt-in, off by default for isolation) ---- */

/** Enable/disable the stylesheet cache. Default: off. */
void css_cache_enable(int enable);

/** Parse a stylesheet with caching. Cached result is shared — caller
 *  must NOT free it. Use css_parse() for owned results. */
const css_stylesheet_t *css_parse_cached(const char *source, size_t len);

/** Clear all caches. */
void css_cache_clear(void);

/** Cache stats. */
typedef struct {
    uint64_t tok_hits, tok_misses;
    uint64_t sheet_hits, sheet_misses;
    uint64_t intern_hits, intern_misses;
    size_t   tok_entries, sheet_entries, intern_entries;
} css_cache_stats_t;
void css_cache_stats(css_cache_stats_t *out);

/** Debug: print the rules to stdout. */
int css_colorize(const char *src, size_t len, FILE *out);
void css_dump(const css_stylesheet_t *s);

/* ---- selectors ---- */

/** Parse a single selector (for querySelector). Returns 0 on success. */
int css_parse_selector(const char *text, size_t len, css_selector_t *out);

/** Compute specificity of a selector. Returns (a<<20)|(b<<10)|c. */
uint32_t css_selector_specificity(const css_selector_t *sel);

/** Human-readable: writes "(0,0,0)" style to buffer. */
void css_selector_specificity_str(const css_selector_t *sel,
                                  char *out, size_t cap);

/** Debug: print a selector to stdout. */
void css_selector_dump(const css_selector_t *sel);

/* ---- Values (lazy) ---- */

/** Get the structured value of a declaration. Parses on first call,
 *  caches the result in the decl. Returns NULL on OOM. */
struct css_value_t;   /* forward decl from css_types.h */
const css_value_t *css_decl_value(const css_decl_t *decl);

/* ---- errors ---- */
int css_error_count(void);
const char *css_error_at(int i);
void css_error_clear(void);

#endif
