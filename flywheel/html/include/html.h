/** html.h — HTML parser public API. */

#ifndef FLYWHEEL_HTML_H
#define FLYWHEEL_HTML_H

#include "html_types.h"
#include <stdio.h>

/** Parse an HTML document. Returns NULL on catastrophic failure.
 *  Recoverable errors are tolerated — parse continues where possible.
 *  Caller must free with html_free(). */
html_document_t *html_parse(const char *source, size_t len);

/** Free a document and its arena. */
void html_free(html_document_t *doc);

/** Debug: print the tree to stdout. */
void html_dump(const html_document_t *doc);

/* ---- DOM traversal ---- */

/** Find first element with the given tag (case-insensitive). */
const html_node_t *html_find_tag(const html_node_t *root, const char *tag);

/** Find first element with an attribute matching (name, value). */
const html_node_t *html_find_attr(const html_node_t *root,
                                  const char *name, const char *value);

/** Get an attribute value by name. Returns NULL if absent. */
const char *html_get_attr(const html_node_t *node, const char *name);

/** Get text content of a node and all descendants, appended into `out`.
 *  Returns bytes written. */
int html_text_content(const html_node_t *node, char *out, size_t cap);

/** Like html_text_content, but does NOT suppress hidden tags
 *  (script/style/head/title/...). Use this to extract script or style
 *  bodies. Returns bytes written. */
int html_raw_text(const html_node_t *node, char *out, size_t cap);

#endif

/* ---- Syntax highlighting ---- */

/** Colorize HTML source with ANSI escapes. Writes to `out`.
 *  Byte-level state machine; safe on any input, no allocation.
 *  Returns 0 on success. */

/** Pretty-print HTML source with 2-space indentation. Parses to AST,
 *  emits normalized output. Raw-text elements (pre/script/style/textarea)
 *  preserved verbatim. Returns 0 on success, -1 on parse failure. */
int html_format(const char *src, size_t len, FILE *out);
int html_colorize(const char *src, size_t len, FILE *out);
