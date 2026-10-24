/* dom_style.c — CSS style computation over an html_document_t.
 * Public types in dom_style.h. Layers, lowest to highest:
 *   1. UA stylesheet (built in).  2. author ss.  3. inline style="".
 * Inherited props fall back to parent. No @media, :hover, :nth-child(n).
 */

#include "dom.h"
#include "html.h"
#include "css.h"
#include "css_types.h"
#include "dom_style.h"
#include <string.h>
#include <stdio.h>

extern int dom_match_parsed(html_node_t *node, const css_selector_t *sel);

static const char *UA_SHEET =
    "html, body, div, p, h1, h2, h3, h4, h5, h6, ul, ol, li,"
    " header, footer, section, article, nav, aside, blockquote,"
    " pre, table, form, fieldset { display: block }"
    " head, script, style, meta, link, title { display: none }"
    " span, a, em, strong, b, i, code, small { display: inline }"
    " h1 { font-size: 2em; font-weight: bold }"
    " h2 { font-size: 1.5em; font-weight: bold }"
    " h3 { font-size: 1.17em; font-weight: bold }"
    " b, strong { font-weight: bold }"
    " i, em { font-style: italic }"
    " a { text-decoration: underline }";

static css_stylesheet_t *g_ua = NULL;
static const css_stylesheet_t *ua_sheet(void) {
    if (!g_ua) g_ua = css_parse(UA_SHEET, strlen(UA_SHEET));
    return g_ua;
}

static int cmp_style_decl(const dom_style_decl_t *a, const dom_style_decl_t *b) {
    if (a->layer != b->layer)         return a->layer - b->layer;
    if (a->important != b->important) return a->important - b->important;
    if (a->spec_a != b->spec_a)       return (int)(a->spec_a - b->spec_a);
    if (a->spec_b != b->spec_b)       return (int)(a->spec_b - b->spec_b);
    if (a->spec_c != b->spec_c)       return (int)(a->spec_c - b->spec_c);
    return a->order - b->order;
}

static int prop_eq(const char *p, int plen, const char *lit) {
    int ll = (int)strlen(lit);
    return plen == ll && strncmp(p, lit, (size_t)plen) == 0;
}

static void copy_trim(const char *src, int len, char *dst, int cap) {
    if (!src || cap <= 0) return;
    if (len < 0) len = 0;
    if (len > cap - 1) len = cap - 1;
    memcpy(dst, src, (size_t)len);
    dst[len] = '\0';
}

/* Parse a CSS color value into a 24-bit RGB number, honoring whatever
 * form the parser stored: "#RRGGBB", "RRGGBB" (parser strips '#'),
 * "RRGGBB !important" (parser keeps '!important' suffix), "rgb(r,g,b)".
 * Returns 1 on success, 0 if unparseable. */
static int parse_color_rgb(const char *v, int len, uint32_t *out) {
    if (!v || len <= 0) return 0;
    /* trim trailing whitespace */
    while (len > 0 && (v[len-1] == ' ' || v[len-1] == '\t')) len--;
    /* strip trailing "!important" (with preceding space) */
    if (len >= 11 && memcmp(v + len - 11, " !important", 11) == 0) {
        len -= 11;
        while (len > 0 && (v[len-1] == ' ' || v[len-1] == '\t')) len--;
    } else if (len >= 10 && memcmp(v + len - 10, "!important", 10) == 0) {
        len -= 10;
        while (len > 0 && (v[len-1] == ' ' || v[len-1] == '\t')) len--;
    }
    if (len <= 0) return 0;

    /* copy into a bounded buffer for sscanf */
    char tmp[64];
    int cp = len < 63 ? len : 63;
    memcpy(tmp, v, (size_t)cp);
    tmp[cp] = '\0';

    unsigned int r = 0, g = 0, b = 0;
    if (tmp[0] == '#') {
        if (sscanf(tmp, "#%02x%02x%02x", &r, &g, &b) == 3) {
            *out = (r << 16) | (g << 8) | b; return 1;
        }
        return 0;
    }
    if (strncmp(tmp, "rgb(", 4) == 0 || strncmp(tmp, "RGB(", 4) == 0) {
        if (sscanf(tmp, "rgb(%u,%u,%u)", &r, &g, &b) == 3 ||
            sscanf(tmp, "rgb( %u , %u , %u )", &r, &g, &b) == 3) {
            *out = (r << 16) | (g << 8) | b; return 1;
        }
        return 0;
    }
    /* bare hex — parser strips '#' from hex colors */
    if (cp == 6 || cp == 3) {
        int all_hex = 1;
        for (int i = 0; i < cp; i++) {
            char c = tmp[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                all_hex = 0; break;
            }
        }
        if (all_hex) {
            if (cp == 6 && sscanf(tmp, "%02x%02x%02x", &r, &g, &b) == 3) {
                *out = (r << 16) | (g << 8) | b; return 1;
            }
            if (cp == 3 && sscanf(tmp, "%1x%1x%1x", &r, &g, &b) == 3) {
                *out = (r << 16) | (g << 8) | b; return 1;
            }
        }
    }
    return 0;
}

/* Expand CSS 'font' shorthand into longhand declarations.
 * Syntax: [style] [variant] [weight] <size>[/<line-height>] <family>
 * Handles the common case; skips values we can't parse confidently. */
/* Expand CSS 'font' shorthand into longhand declarations.
 * Syntax: [style] [variant] [weight] <size>[/<line-height>] <family>
 * Expanded strings are copied into caller-owned `arena` and live there
 * past this call, so return values are safe to record afterwards.
 * Returns number of longhand declarations emitted (0 if not expandable). */
static int expand_font_shorthand(const char *value, int vlen,
                                 css_decl_t *out, int cap,
                                 char *arena, size_t arena_cap, size_t *arena_used) {
    if (!value || vlen <= 0 || cap < 1 || !arena || !arena_used) return 0;

    char buf[256];
    int cp = vlen < 255 ? vlen : 255;
    memcpy(buf, value, (size_t)cp);
    buf[cp] = 0;

    int important = 0;
    if (cp >= 11 && memcmp(buf + cp - 11, " !important", 11) == 0) { cp -= 11; important = 1; }
    else if (cp >= 10 && memcmp(buf + cp - 10, "!important", 10) == 0) { cp -= 10; important = 1; }
    buf[cp] = 0;

    char *tok[16];
    int nt = 0;
    char *p = buf;
    while (*p && nt < 16) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = 0; p++; }
    }

    int size_idx = -1;
    for (int i = 0; i < nt; i++) {
        char *s = tok[i];
        int j = 0;
        while (s[j] >= '0' && s[j] <= '9') j++;
        if (j == 0) continue;
        if (s[j] == '.') { j++; while (s[j] >= '0' && s[j] <= '9') j++; }
        if ((s[j] == 'p' && s[j+1] == 'x') ||
            (s[j] == 'e' && s[j+1] == 'm') ||
            (s[j] == 'p' && s[j+1] == 't') ||
            (s[j] == '%')) { size_idx = i; break; }
    }
    if (size_idx < 0) return 0;

    int emitted = 0;

    for (int i = 0; i < size_idx && emitted < cap; i++) {
        const char *t = tok[i];
        int is_style = (!strcmp(t, "italic") || !strcmp(t, "oblique"));
        int is_weight = (!strcmp(t, "bold") || !strcmp(t, "bolder") ||
                         !strcmp(t, "lighter") ||
                         (t[0] >= '1' && t[0] <= '9' && !t[1]));
        if (!is_style && !is_weight) continue;
        size_t tl = strlen(t);
        if (*arena_used + tl + 1 > arena_cap) break;
        char *v = arena + *arena_used;
        memcpy(v, t, tl); v[tl] = 0;
        *arena_used += tl + 1;
        css_decl_t d; memset(&d, 0, sizeof(d));
        if (is_style) { d.prop = "font-style"; d.prop_len = 10; }
        else          { d.prop = "font-weight"; d.prop_len = 11; }
        d.value = v; d.value_len = (int)tl;
        d.important = important;
        out[emitted++] = d;
    }

    {
        char *s = tok[size_idx];
        char *slash = strchr(s, '/');
        if (slash) {
            *slash = 0;
            size_t sl = strlen(s);
            if (*arena_used + sl + 1 <= arena_cap) {
                char *vsize = arena + *arena_used;
                memcpy(vsize, s, sl); vsize[sl] = 0;
                *arena_used += sl + 1;
                if (emitted < cap) {
                    css_decl_t ds; memset(&ds, 0, sizeof(ds));
                    ds.prop = "font-size"; ds.prop_len = 9;
                    ds.value = vsize; ds.value_len = (int)sl;
                    ds.important = important;
                    out[emitted++] = ds;
                }
            }
            char *lh = slash + 1;
            size_t ll = strlen(lh);
            if (*arena_used + ll + 1 <= arena_cap) {
                char *vlh = arena + *arena_used;
                memcpy(vlh, lh, ll); vlh[ll] = 0;
                *arena_used += ll + 1;
                if (emitted < cap) {
                    css_decl_t dl; memset(&dl, 0, sizeof(dl));
                    dl.prop = "line-height"; dl.prop_len = 11;
                    dl.value = vlh; dl.value_len = (int)ll;
                    dl.important = important;
                    out[emitted++] = dl;
                }
            }
        } else {
            size_t sl = strlen(s);
            if (*arena_used + sl + 1 <= arena_cap) {
                char *vsize = arena + *arena_used;
                memcpy(vsize, s, sl); vsize[sl] = 0;
                *arena_used += sl + 1;
                if (emitted < cap) {
                    css_decl_t ds; memset(&ds, 0, sizeof(ds));
                    ds.prop = "font-size"; ds.prop_len = 9;
                    ds.value = vsize; ds.value_len = (int)sl;
                    ds.important = important;
                    out[emitted++] = ds;
                }
            }
        }
    }

    if (size_idx + 1 < nt && emitted < cap) {
        char fam[128]; int fl = 0;
        for (int i = size_idx + 1; i < nt && fl < 127; i++) {
            int tl = (int)strlen(tok[i]);
            if (i > size_idx + 1 && fl < 126) fam[fl++] = ' ';
            if (fl + tl > 126) tl = 126 - fl;
            memcpy(fam + fl, tok[i], (size_t)tl);
            fl += tl;
        }
        fam[fl] = 0;
        if (*arena_used + (size_t)fl + 1 <= arena_cap) {
            char *vfam = arena + *arena_used;
            memcpy(vfam, fam, (size_t)fl); vfam[fl] = 0;
            *arena_used += (size_t)fl + 1;
            css_decl_t df; memset(&df, 0, sizeof(df));
            df.prop = "font-family"; df.prop_len = 11;
            df.value = vfam; df.value_len = fl;
            df.important = important;
            out[emitted++] = df;
        }
    }

    return emitted;
}

/* Expand CSS box shorthand (margin, padding) into longhand sides.
 * Forms: A | A B | A B C | A B C D  (TRBL clockwise).
 * Writes expanded values into caller-owned arena; pointers valid past return. */
static int expand_box_shorthand(const char *prop, int prop_len,
                                const char *value, int vlen,
                                css_decl_t *out, int cap,
                                char *arena, size_t arena_cap, size_t *arena_used) {
    if (!prop || prop_len <= 0 || !value || vlen <= 0 || cap < 4) return 0;
    if (!arena || !arena_used) return 0;

    /* Build longhand names: e.g. "margin" -> "margin-top", etc. */
    static const char *MARGIN_NAMES[4] = {
        "margin-top", "margin-right", "margin-bottom", "margin-left"
    };
    static const char *PADDING_NAMES[4] = {
        "padding-top", "padding-right", "padding-bottom", "padding-left"
    };
    int is_margin = (prop_len == 6 && memcmp(prop, "margin", 6) == 0);
    int is_padding = (prop_len == 7 && memcmp(prop, "padding", 7) == 0);
    if (!is_margin && !is_padding) return 0;
    const char **names = is_margin ? MARGIN_NAMES : PADDING_NAMES;
    /* Tokenize value on whitespace. */
    char buf[256];
    int cp = vlen < 255 ? vlen : 255;
    memcpy(buf, value, (size_t)cp);
    buf[cp] = '\0';

    int important = 0;
    if (cp >= 11 && memcmp(buf + cp - 11, " !important", 11) == 0) { cp -= 11; important = 1; }
    else if (cp >= 10 && memcmp(buf + cp - 10, "!important", 10) == 0) { cp -= 10; important = 1; }
    buf[cp] = '\0';

    char *tok[4];
    int nt = 0;
    char *p = buf;
    while (*p && nt < 4) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = '\0'; p++; }
    }
    if (nt == 0) return 0;

    /* Expand to 4 sides: TRBL */
    const char *sides[4];
    if (nt == 1) {
        sides[0] = sides[1] = sides[2] = sides[3] = tok[0];
    } else if (nt == 2) {
        sides[0] = sides[2] = tok[0];
        sides[1] = sides[3] = tok[1];
    } else if (nt == 3) {
        sides[0] = tok[0];         /* top */
        sides[1] = sides[3] = tok[1]; /* left, right */
        sides[2] = tok[2];         /* bottom */
    } else {
        sides[0] = tok[0]; sides[1] = tok[1]; sides[2] = tok[2]; sides[3] = tok[3];
    }

    int emitted = 0;
    for (int i = 0; i < 4 && emitted < cap; i++) {
        size_t sl = strlen(sides[i]);
        if (*arena_used + sl + 1 > arena_cap) break;
        char *v = arena + *arena_used;
        memcpy(v, sides[i], sl); v[sl] = '\0';
        *arena_used += sl + 1;
        css_decl_t d; memset(&d, 0, sizeof(d));
        d.prop = names[i]; d.prop_len = (int)strlen(names[i]);
        d.value = v; d.value_len = (int)sl;
        d.important = important;
        out[emitted++] = d;
    }
    return emitted;
}

/* Expand CSS border shorthand (border, border-top, border-right, border-bottom, border-left)
 * into longhand width/style/color props. Any order of tokens allowed.
 * Skips cleanly if any token is var(...) or light-dark(...) — those need var resolution. */
static int expand_border_shorthand(const char *prop, int prop_len,
                                   const char *value, int vlen,
                                   css_decl_t *out, int cap,
                                   char *arena, size_t arena_cap, size_t *arena_used) {
    if (!prop || !value || vlen <= 0 || cap < 3 || !arena || !arena_used) return 0;

    /* Per-side prop names — 4 sides, 3 props each = 12. */
    static const char *SIDE_NAMES[4][3] = {
        { "border-top-width", "border-top-style", "border-top-color" },
        { "border-right-width", "border-right-style", "border-right-color" },
        { "border-bottom-width", "border-bottom-style", "border-bottom-color" },
        { "border-left-width", "border-left-style", "border-left-color" }
    };
    /* If prop is border-<side>, restrict to one side. Else all 4. */
    int side_start = 0, side_end = 4;
    if (prop_len > 7 && memcmp(prop, "border-", 7) == 0) {
        if      (prop_len == 12 && memcmp(prop+7, "top",    3) == 0) { side_start = 0; side_end = 1; }
        else if (prop_len == 14 && memcmp(prop+7, "right",  5) == 0) { side_start = 1; side_end = 2; }
        else if (prop_len == 15 && memcmp(prop+7, "bottom", 6) == 0) { side_start = 2; side_end = 3; }
        else if (prop_len == 13 && memcmp(prop+7, "left",   4) == 0) { side_start = 3; side_end = 4; }
        else return 0; /* border-color, border-width, border-style are not this helper's job */
    }

    /* Copy value, strip !important. */
    char buf[256];
    int cp = vlen < 255 ? vlen : 255;
    memcpy(buf, value, (size_t)cp); buf[cp] = 0;
    int important = 0;
    if (cp >= 11 && memcmp(buf+cp-11, " !important", 11) == 0) { cp -= 11; important = 1; }
    else if (cp >= 10 && memcmp(buf+cp-10, "!important", 10) == 0) { cp -= 10; important = 1; }
    buf[cp] = 0;

    /* Bail on var()/light-dark() — can't classify those. */
    if (strstr(buf, "var(") || strstr(buf, "light-dark(")) return 0;

    /* Tokenize. */
    char *tok[8];
    int nt = 0;
    char *p = buf;
    while (*p && nt < 8) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = 0; p++; }
    }
    if (nt == 0) return 0;

    /* Classify each token. */
    const char *width_tok = NULL, *style_tok = NULL, *color_tok = NULL;
    static const char *STYLES[] = { "none","solid","dashed","dotted","double",
                                    "groove","ridge","inset","outset","hidden", NULL };
    static const char *WIDTHS[] = { "thin","medium","thick", NULL };
    static const char *COLORS[] = { "black","white","red","green","blue","gray","grey",
                                    "silver","maroon","navy","olive","purple","teal",
                                    "yellow","aqua","fuchsia","lime","currentcolor", NULL };
    for (int i = 0; i < nt; i++) {
        const char *t = tok[i];
        int classified = 0;

        /* Style keyword. */
        for (int k = 0; STYLES[k]; k++)
            if (strcmp(t, STYLES[k]) == 0) { style_tok = t; classified = 1; break; }
        if (classified) continue;

        /* Width keyword. */
        for (int k = 0; WIDTHS[k]; k++)
            if (strcmp(t, WIDTHS[k]) == 0) { width_tok = t; classified = 1; break; }
        if (classified) continue;

        /* Color keyword. */
        for (int k = 0; COLORS[k]; k++)
            if (strcmp(t, COLORS[k]) == 0) { color_tok = t; classified = 1; break; }
        if (classified) continue;

        /* Hex color (#RRGGBB or bare hex, parser strips #). */
        if (t[0] == '#' || (strlen(t) == 6 &&
            strspn(t, "0123456789abcdefABCDEF") == 6)) { color_tok = t; continue; }

        /* rgb(...) — tokenizer split on whitespace inside parens, unlikely but handle. */
        if (strncmp(t, "rgb(", 4) == 0) { color_tok = t; continue; }

        /* Width: number + unit, or just 0. */
        int j = 0;
        while (t[j] >= '0' && t[j] <= '9') j++;
        if (j > 0) {
            if (t[j] == 0) { width_tok = t; continue; }  /* "0" */
            if (t[j] == '.') { j++; while (t[j] >= '0' && t[j] <= '9') j++; }
            if ((t[j]=='p' && t[j+1]=='x') || (t[j]=='e' && t[j+1]=='m') ||
                (t[j]=='r' && t[j+1]=='e' && t[j+2]=='m') ||
                (t[j]=='v' && t[j+1]=='h') || (t[j]=='v' && t[j+1]=='w') ||
                (t[j]=='p' && t[j+1]=='t') || t[j]=='%') { width_tok = t; continue; }
        }
        /* Unknown token — bail cleanly rather than emit wrong values. */
        return 0;
    }

    /* CSS defaults for unset components: medium/none/currentcolor. */
    const char *w = width_tok ? width_tok : "medium";
    const char *s = style_tok ? style_tok : "none";
    const char *c = color_tok ? color_tok : "currentcolor";

    int emitted = 0;
    for (int side = side_start; side < side_end; side++) {
        const char *vals[3] = { w, s, c };
        for (int k = 0; k < 3; k++) {
            if (emitted >= cap) return emitted;
            size_t vl = strlen(vals[k]);
            if (*arena_used + vl + 1 > arena_cap) return emitted;
            char *v = arena + *arena_used;
            memcpy(v, vals[k], vl); v[vl] = 0;
            *arena_used += vl + 1;
            css_decl_t d; memset(&d, 0, sizeof(d));
            d.prop = SIDE_NAMES[side][k]; d.prop_len = (int)strlen(d.prop);
            d.value = v; d.value_len = (int)vl;
            d.important = important;
            out[emitted++] = d;
        }
    }
    return emitted;
}

/* Expand CSS background shorthand when the value is a pure color.
 * Emits background-color: <color>. Bails on url(), gradients, var(),
 * light-dark(), or anything that isn't a recognized color. */
static int expand_background_shorthand(const char *value, int vlen,
                                       css_decl_t *out, int cap,
                                       char *arena, size_t arena_cap, size_t *arena_used) {
    if (!value || vlen <= 0 || cap < 1 || !arena || !arena_used) return 0;

    char buf[256];
    int cp = vlen < 255 ? vlen : 255;
    memcpy(buf, value, (size_t)cp); buf[cp] = 0;
    int important = 0;
    if (cp >= 11 && memcmp(buf+cp-11, " !important", 11) == 0) { cp -= 11; important = 1; }
    else if (cp >= 10 && memcmp(buf+cp-10, "!important", 10) == 0) { cp -= 10; important = 1; }
    buf[cp] = 0;

    /* Bail on anything requiring further resolution. */
    if (strstr(buf, "url(") || strstr(buf, "gradient(") ||
        strstr(buf, "var(") || strstr(buf, "light-dark(")) return 0;

    /* Strip whitespace. */
    char *s = buf;
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
    *e = 0;

    /* Single token only — anything with internal space is a multi-value
     * shorthand (position/size/repeat) that we don't expand. */
    if (strchr(s, ' ') || strchr(s, '\t')) return 0;

    /* Must be a color: hex (#RRGGBB), bare hex (RRGGBB), rgb(), or a keyword. */
    int is_color = 0;
    if (s[0] == '#') is_color = 1;
    else if (strlen(s) == 6 && strspn(s, "0123456789abcdefABCDEF") == 6) is_color = 1;
    else if (strncmp(s, "rgb(", 4) == 0) is_color = 1;
    else {
        static const char *COLORS[] = { "black","white","red","green","blue","gray","grey",
                                        "silver","maroon","navy","olive","purple","teal",
                                        "yellow","aqua","fuchsia","lime",
                                        "currentcolor","inherit","transparent", NULL };
        for (int k = 0; COLORS[k]; k++)
            if (strcmp(s, COLORS[k]) == 0) { is_color = 1; break; }
    }
    if (!is_color) return 0;

    size_t vl = strlen(s);
    if (*arena_used + vl + 1 > arena_cap) return 0;
    char *v = arena + *arena_used;
    memcpy(v, s, vl); v[vl] = 0;
    *arena_used += vl + 1;

    css_decl_t d; memset(&d, 0, sizeof(d));
    d.prop = "background-color"; d.prop_len = 16;
    d.value = v; d.value_len = (int)vl;
    d.important = important;
    out[0] = d;
    return 1;
}

/* Expand CSS border-radius shorthand into 4 corner longhands.
 * Forms: A (all four corners = A) | A B (tl/br = A, tr/bl = B). */
static int expand_border_radius_shorthand(const char *value, int vlen,
                                          css_decl_t *out, int cap,
                                          char *arena, size_t arena_cap, size_t *arena_used) {
    if (!value || vlen <= 0 || cap < 4 || !arena || !arena_used) return 0;

    static const char *NAMES[4] = {
        "border-top-left-radius", "border-top-right-radius",
        "border-bottom-right-radius", "border-bottom-left-radius"
    };

    char buf[256];
    int cp = vlen < 255 ? vlen : 255;
    memcpy(buf, value, (size_t)cp); buf[cp] = 0;
    int important = 0;
    if (cp >= 11 && memcmp(buf+cp-11, " !important", 11) == 0) { cp -= 11; important = 1; }
    else if (cp >= 10 && memcmp(buf+cp-10, "!important", 10) == 0) { cp -= 10; important = 1; }
    buf[cp] = 0;

    /* Tokenize (at most 2 tokens for our supported forms). */
    char *tok[2] = {0};
    int nt = 0;
    char *p = buf;
    while (*p && nt < 2) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = 0; p++; }
    }
    if (nt < 1 || nt > 2) return 0; /* 3-4 value forms deferred */

    const char *sides[4];
    if (nt == 1) {
        sides[0] = sides[1] = sides[2] = sides[3] = tok[0];
    } else {
        sides[0] = sides[2] = tok[0];
        sides[1] = sides[3] = tok[1];
    }

    int emitted = 0;
    for (int i = 0; i < 4; i++) {
        size_t sl = strlen(sides[i]);
        if (*arena_used + sl + 1 > arena_cap) return emitted;
        char *v = arena + *arena_used;
        memcpy(v, sides[i], sl); v[sl] = 0;
        *arena_used += sl + 1;
        css_decl_t d; memset(&d, 0, sizeof(d));
        d.prop = NAMES[i]; d.prop_len = (int)strlen(d.prop);
        d.value = v; d.value_len = (int)sl;
        d.important = important;
        out[emitted++] = d;
    }
    return emitted;
}

static void record_decl(computed_style_t *out, const css_decl_t *d,
                        uint32_t a, uint32_t b, uint32_t c,
                        int order, int layer) {
    if (!d || !d->prop) return;
    dom_style_decl_t nd;
    memset(&nd, 0, sizeof(nd));
    copy_trim(d->prop,  d->prop_len,  nd.prop,  sizeof(nd.prop));
    copy_trim(d->value, d->value_len, nd.value, sizeof(nd.value));
    nd.important = d->important;
    nd.spec_a = a; nd.spec_b = b; nd.spec_c = c;
    nd.order = order; nd.layer = layer;

    for (int i = 0; i < out->n_decls; i++) {
        if (strcmp(out->decls[i].prop, nd.prop) == 0) {
            if (cmp_style_decl(&nd, &out->decls[i]) >= 0)
                out->decls[i] = nd;
            return;
        }
    }
    if (out->n_decls < DOM_STYLE_MAX_DECLS)
        out->decls[out->n_decls++] = nd;
}

static void collect_sheet(const css_stylesheet_t *ss, html_node_t *node,
                          computed_style_t *out, int layer, int *order_io) {
    if (!ss) return;
    int order = *order_io;
    for (int r = 0; r < ss->n_rules; r++) {
        const css_rule_t *rule = &ss->rules[r];
        if (rule->kind != RULE_STYLE) continue;
        for (int s = 0; s < rule->selectors.n; s++) {
            const css_selector_t *sel = &rule->selectors.items[s];
            if (!dom_match_parsed(node, sel)) continue;
            for (int i = 0; i < rule->n_decls; i++) {
                const css_decl_t *d = &rule->decls[i];
                if (d->prop && d->value && d->prop_len > 0) {
                    int is_border = (d->prop_len == 6 && memcmp(d->prop, "border", 6) == 0);
                    int is_bside  = (d->prop_len > 7 && memcmp(d->prop, "border-", 7) == 0);
                    if (is_border || is_bside) {
                        char brd_arena[1024]; size_t brd_used = 0;
                        css_decl_t brd_exp[12];
                        int bn = expand_border_shorthand(d->prop, d->prop_len,
                                                         d->value, d->value_len,
                                                         brd_exp, 12,
                                                         brd_arena, sizeof(brd_arena),
                                                         &brd_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &brd_exp[k],
                                            sel->spec_a, sel->spec_b, sel->spec_c,
                                            order, layer);
                            order++;
                            continue;
                        }
                    }
                }
                if (d->prop && d->value && d->prop_len > 0) {
                    int is_margin = (d->prop_len == 6 && memcmp(d->prop, "margin", 6) == 0);
                    int is_padding = (d->prop_len == 7 && memcmp(d->prop, "padding", 7) == 0);
                    if (is_margin || is_padding) {
                        char box_arena[1024]; size_t box_used = 0;
                        css_decl_t box_exp[4];
                        int bn = expand_box_shorthand(d->prop, d->prop_len,
                                                      d->value, d->value_len,
                                                      box_exp, 4,
                                                      box_arena, sizeof(box_arena),
                                                      &box_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &box_exp[k],
                                            sel->spec_a, sel->spec_b, sel->spec_c,
                                            order, layer);
                            order++;
                            continue;
                        }
                    }
                }
                if (d->prop && d->value && d->prop_len > 0) {
                    int is_bg = (d->prop_len == 10 && memcmp(d->prop, "background", 10) == 0);
                    if (is_bg) {
                        char bg_arena[1024]; size_t bg_used = 0;
                        css_decl_t bg_exp[1];
                        int bn = expand_background_shorthand(d->value, d->value_len,
                                                             bg_exp, 1,
                                                             bg_arena, sizeof(bg_arena),
                                                             &bg_used);
                        if (bn > 0) {
                            record_decl(out, &bg_exp[0],
                                        sel->spec_a, sel->spec_b, sel->spec_c,
                                        order, layer);
                            order++;
                            continue;
                        }
                    }
                    int is_br = (d->prop_len == 13 && memcmp(d->prop, "border-radius", 13) == 0);
                    if (is_br) {
                        char br_arena[1024]; size_t br_used = 0;
                        css_decl_t br_exp[4];
                        int bn = expand_border_radius_shorthand(d->value, d->value_len,
                                                                br_exp, 4,
                                                                br_arena, sizeof(br_arena),
                                                                &br_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &br_exp[k],
                                            sel->spec_a, sel->spec_b, sel->spec_c,
                                            order, layer);
                            order++;
                            continue;
                        }
                    }
                }
                if (d->prop && d->prop_len == 4 &&
                    memcmp(d->prop, "font", 4) == 0 && d->value) {
                    char font_arena[1024]; size_t font_used = 0;
                    css_decl_t exp[8];
                    int n = expand_font_shorthand(d->value, d->value_len,
                                                  exp, 8,
                                                  font_arena, sizeof(font_arena),
                                                  &font_used);
                    if (n > 0) {
                        for (int k = 0; k < n; k++)
                            record_decl(out, &exp[k],
                                        sel->spec_a, sel->spec_b, sel->spec_c,
                                        order, layer);
                        order++;
                        continue;
                    }
                }
                record_decl(out, d,
                            sel->spec_a, sel->spec_b, sel->spec_c,
                            order, layer);
            }
            order++;
        }
    }
    *order_io = order;
}

static void collect_inline(html_node_t *node, computed_style_t *out, int *order_io) {
    const char *style = html_get_attr(node, "style");
    if (!style || !*style) return;
    int order = *order_io;
    const char *p = style;
    while (*p) {
        while (*p == ';' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ';') end++;
        const char *colon = p;
        while (colon < end && *colon != ':') colon++;
        if (colon < end) {
            const char *pstart = p;
            const char *pend = colon;
            while (pend > pstart && (pend[-1] == ' ' || pend[-1] == '\t')) pend--;
            const char *vstart = colon + 1;
            while (vstart < end && (*vstart == ' ' || *vstart == '\t')) vstart++;
            const char *vend = end;
            while (vend > vstart && (vend[-1] == ' ' || vend[-1] == '\t')) vend--;
            if (pend > pstart && vend > vstart) {
                css_decl_t d;
                memset(&d, 0, sizeof(d));
                d.prop = pstart; d.prop_len = (int)(pend - pstart);
                d.value = vstart; d.value_len = (int)(vend - vstart);
                if (d.value_len > 10 &&
                    memcmp(d.value + d.value_len - 10, "!important", 10) == 0) {
                    d.important = 1;
                    d.value_len -= 10;
                    while (d.value_len > 0 &&
                           (d.value[d.value_len-1] == ' ' || d.value[d.value_len-1] == '\t'))
                        d.value_len--;
                }
                if (d.prop_len > 0) {
                    int is_border = (d.prop_len == 6 && memcmp(d.prop, "border", 6) == 0);
                    int is_bside  = (d.prop_len > 7 && memcmp(d.prop, "border-", 7) == 0);
                    if (is_border || is_bside) {
                        char brd_arena[1024]; size_t brd_used = 0;
                        css_decl_t brd_exp[12];
                        int bn = expand_border_shorthand(d.prop, d.prop_len,
                                                         d.value, d.value_len,
                                                         brd_exp, 12,
                                                         brd_arena, sizeof(brd_arena),
                                                         &brd_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &brd_exp[k], 1, 0, 0, order++, 2);
                            p = end;
                            continue;
                        }
                    }
                }
                if (d.prop_len > 0) {
                    if (d.prop_len == 10 && memcmp(d.prop, "background", 10) == 0) {
                        char bg_arena[1024]; size_t bg_used = 0;
                        css_decl_t bg_exp[1];
                        int bn = expand_background_shorthand(d.value, d.value_len,
                                                             bg_exp, 1,
                                                             bg_arena, sizeof(bg_arena),
                                                             &bg_used);
                        if (bn > 0) {
                            record_decl(out, &bg_exp[0], 1, 0, 0, order++, 2);
                            p = end;
                            continue;
                        }
                    }
                    if (d.prop_len == 13 && memcmp(d.prop, "border-radius", 13) == 0) {
                        char br_arena[1024]; size_t br_used = 0;
                        css_decl_t br_exp[4];
                        int bn = expand_border_radius_shorthand(d.value, d.value_len,
                                                                br_exp, 4,
                                                                br_arena, sizeof(br_arena),
                                                                &br_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &br_exp[k], 1, 0, 0, order++, 2);
                            p = end;
                            continue;
                        }
                    }
                    int is_margin = (d.prop_len == 6 && memcmp(d.prop, "margin", 6) == 0);
                    int is_padding = (d.prop_len == 7 && memcmp(d.prop, "padding", 7) == 0);
                    if (is_margin || is_padding) {
                        char box_arena[1024]; size_t box_used = 0;
                        css_decl_t box_exp[4];
                        int bn = expand_box_shorthand(d.prop, d.prop_len,
                                                      d.value, d.value_len,
                                                      box_exp, 4,
                                                      box_arena, sizeof(box_arena),
                                                      &box_used);
                        if (bn > 0) {
                            for (int k = 0; k < bn; k++)
                                record_decl(out, &box_exp[k], 1, 0, 0, order++, 2);
                            p = end;
                            continue;
                        }
                    }
                }
                if (d.prop_len == 4 && memcmp(d.prop, "font", 4) == 0) {
                    char font_arena[1024]; size_t font_used = 0;
                    css_decl_t exp[8];
                    int n = expand_font_shorthand(d.value, d.value_len,
                                                  exp, 8,
                                                  font_arena, sizeof(font_arena),
                                                  &font_used);
                    if (n > 0) {
                        for (int k = 0; k < n; k++)
                            record_decl(out, &exp[k], 1, 0, 0, order++, 2);
                    } else {
                        record_decl(out, &d, 1, 0, 0, order++, 2);
                    }
                } else {
                    record_decl(out, &d, 1, 0, 0, order++, 2);
                }
            }
        }
        p = end;
    }
    *order_io = order;
}

static void finalize_named(computed_style_t *out) {
    for (int i = 0; i < out->n_decls; i++) {
        const dom_style_decl_t *d = &out->decls[i];
        int plen = (int)strlen(d->prop);
        if (prop_eq(d->prop, plen, "color")) {
            uint32_t rgb;
            if (parse_color_rgb(d->value, (int)strlen(d->value), &rgb)) {
                out->color_rgb = rgb; out->has_color = 1;
            }
        } else if (prop_eq(d->prop, plen, "background-color")) {
            uint32_t rgb;
            if (parse_color_rgb(d->value, (int)strlen(d->value), &rgb)) {
                out->bg_rgb = rgb; out->has_bg = 1;
            }
        } else if (prop_eq(d->prop, plen, "display")) {
            copy_trim(d->value, (int)strlen(d->value), out->display, sizeof(out->display));
        } else if (prop_eq(d->prop, plen, "font-size")) {
            copy_trim(d->value, (int)strlen(d->value), out->font_size, sizeof(out->font_size));
        } else if (prop_eq(d->prop, plen, "font-weight")) {
            copy_trim(d->value, (int)strlen(d->value), out->font_weight, sizeof(out->font_weight));
        } else if (prop_eq(d->prop, plen, "font-family")) {
            copy_trim(d->value, (int)strlen(d->value), out->font_family, sizeof(out->font_family));
        } else if (prop_eq(d->prop, plen, "line-height")) {
            copy_trim(d->value, (int)strlen(d->value), out->line_height, sizeof(out->line_height));
        }
    }
    if (out->parent) {
        if (!out->has_color && out->parent->has_color) {
            out->color_rgb = out->parent->color_rgb; out->has_color = 1;
        }
        if (out->font_size[0] == '\0' && out->parent->font_size[0] != '\0')
            copy_trim(out->parent->font_size, (int)strlen(out->parent->font_size),
                      out->font_size, sizeof(out->font_size));
        if (out->font_weight[0] == '\0' && out->parent->font_weight[0] != '\0')
            copy_trim(out->parent->font_weight, (int)strlen(out->parent->font_weight),
                      out->font_weight, sizeof(out->font_weight));
        if (out->font_family[0] == '\0' && out->parent->font_family[0] != '\0')
            copy_trim(out->parent->font_family, (int)strlen(out->parent->font_family),
                      out->font_family, sizeof(out->font_family));
        if (out->line_height[0] == '\0' && out->parent->line_height[0] != '\0')
            copy_trim(out->parent->line_height, (int)strlen(out->parent->line_height),
                      out->line_height, sizeof(out->line_height));
    }
}

int dom_compute_style(const css_stylesheet_t *ss, html_node_t *node,
                      computed_style_t *out) {
    if (!node || !out || node->kind != HTML_NODE_ELEMENT) return -1;
    memset(out, 0, sizeof(*out));
    out->parent = NULL;
    int order = 0;
    collect_sheet(ua_sheet(), node, out, 0, &order);
    collect_sheet(ss,        node, out, 1, &order);
    collect_inline(node, out, &order);
    finalize_named(out);
    return 0;
}

int dom_compute_style_inherited(const css_stylesheet_t *ss, html_node_t *node,
                                computed_style_t *out,
                                computed_style_t *parent_out) {
    if (!node || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->parent = NULL;
    html_node_t *p = node->parent;
    while (p && p->kind != HTML_NODE_ELEMENT) p = p->parent;
    if (p && parent_out) {
        if (dom_compute_style_inherited(ss, p, parent_out, NULL) == 0)
            out->parent = parent_out;
    }
    int order = 0;
    collect_sheet(ua_sheet(), node, out, 0, &order);
    collect_sheet(ss,        node, out, 1, &order);
    collect_inline(node, out, &order);
    finalize_named(out);
    return 0;
}

int dom_apply_stylesheet(html_document_t *doc, const css_stylesheet_t *ss) {
    if (!doc || !doc->root) return -1;
    html_node_t *stack[4096];
    int top = 0;
    stack[top++] = doc->root;
    int count = 0;
    while (top > 0) {
        html_node_t *n = stack[--top];
        if (n->kind == HTML_NODE_ELEMENT) {
            computed_style_t cs, parent;
            if (dom_compute_style_inherited(ss, n, &cs, &parent) == 0) count++;
        }
        html_node_t *kids[256];
        int nk = 0;
        for (html_node_t *c = n->first_child; c && nk < 256; c = c->next_sibling)
            kids[nk++] = c;
        for (int i = nk - 1; i >= 0; i--)
            if (top < 4096) stack[top++] = kids[i];
    }
    return count;
}

void dom_style_shutdown(void) {
    if (g_ua) { css_free(g_ua); g_ua = NULL; }
}
