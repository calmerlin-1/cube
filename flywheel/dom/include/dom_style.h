/* dom_style.h — computed style public API.
 * Pairs with dom_style.c. Additive: existing code doesn't include this yet. */
#ifndef DOM_STYLE_H
#define DOM_STYLE_H

#include "html_types.h"
#include "css_types.h"

#define DOM_STYLE_MAX_DECLS 64

typedef struct {
    char        prop[32];
    char        value[96];
    int         important;
    uint32_t    spec_a, spec_b, spec_c;
    int         order;
    int         layer;
} dom_style_decl_t;

typedef struct computed_style_s {
    uint32_t    color_rgb;
    uint32_t    bg_rgb;
    int         has_color;
    int         has_bg;
    char        display[16];
    char        font_size[16];
    char        font_weight[16];
    char        font_family[64];
    char        line_height[16];

    dom_style_decl_t decls[DOM_STYLE_MAX_DECLS];
    int              n_decls;

    struct computed_style_s *parent;
} computed_style_t;

/* Compute the winning value for each property on `node`, using `ss` as
 * the author stylesheet (may be NULL). Walks UA sheet + author + inline. */
int dom_compute_style(const css_stylesheet_t *ss, html_node_t *node,
                      computed_style_t *out);

/* Same, but resolves inherited properties against the parent chain.
 * parent_out is workspace owned by the caller. */
int dom_compute_style_inherited(const css_stylesheet_t *ss, html_node_t *node,
                                computed_style_t *out,
                                computed_style_t *parent_out);

/* Iterate the doc, computing for each element. Returns the count. */
int dom_apply_stylesheet(html_document_t *doc, const css_stylesheet_t *ss);

/* Free internal caches (UA stylesheet). Safe to call any time. */
void dom_style_shutdown(void);

#endif
