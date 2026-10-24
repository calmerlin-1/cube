/** dom.h — public DOM API: mutation, query, JS bridge, style. */
#ifndef FLYWHEEL_DOM_H
#define FLYWHEEL_DOM_H

#include "html_types.h"
#include "css_types.h"
#include "dom_style.h"
#include <stdio.h>

/* Forward declaration — actual definition is in interp.h (included by
 * any TU that uses the JS bridge). Declaring here lets prototypes use
 * `struct Interp *` without pulling interp.h into every consumer. */
struct Interp;

/* ============================================================
 * DOM mutation
 * ============================================================ */

html_node_t *dom_create_element(html_document_t *doc, const char *tag);
html_node_t *dom_create_text(html_document_t *doc, const char *text);

void dom_append_child(html_node_t *parent, html_node_t *child);
void dom_insert_before(html_node_t *parent, html_node_t *node,
                       html_node_t *ref);
void dom_remove_child(html_node_t *child);

void dom_set_attribute(html_document_t *doc, html_node_t *node,
                       const char *name, const char *value);
void dom_remove_attribute(html_node_t *node, const char *name);
const char *dom_get_attribute(const html_node_t *node, const char *name);

void dom_set_text(html_document_t *doc, html_node_t *node, const char *text);
void dom_set_id(html_document_t *doc, html_node_t *node, const char *id);
const char *dom_get_id(const html_node_t *node);

/* ============================================================
 * DOM query
 * ============================================================ */

html_node_t *dom_get_element_by_id(html_node_t *root, const char *id);
html_node_t *dom_get_element_by_tag(html_node_t *root, const char *tag);

int dom_get_elements_by_class(html_node_t *root, const char *cls,
                              html_node_t **out, int cap);
int dom_get_elements_by_tag(html_node_t *root, const char *tag,
                            html_node_t **out, int cap);

html_node_t *dom_query_selector(html_node_t *root, const char *selector);
int dom_query_selector_all(html_node_t *root, const char *selector,
                           html_node_t **out, int cap);

int dom_matches(html_node_t *node, const char *selector);
int dom_match_parsed(html_node_t *node, const css_selector_t *sel);

/* ============================================================
 * JS bridge
 * ============================================================ */

void dom_js_install(struct Interp *I, html_document_t *doc);
void dom_js_set_stylesheet(struct Interp *I, const css_stylesheet_t *ss);

#endif /* FLYWHEEL_DOM_H */
