#include "html.h"
#include "css.h"
#include "dom.h"
#include "dom_style.h"
#include "interp.h"
#include "value.h"
#include <stdio.h>
#include <string.h>

void dom_js_set_stylesheet(struct Interp *I, const css_stylesheet_t *ss);

static int fails = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); fails++; } \
} while (0)

static FlyResult ev(Interp *I, const char *src) {
    return flywheel_eval(I, src, "<test>");
}

static int ok(FlyResult r) { return r.status == FLY_OK; }

static const char *as_str(FlyResult r) {
    if (r.status != FLY_OK || r.value.kind != VAL_STRING) return NULL;
    return r.value.as.string;
}

int main(void) {
    const char *html_src =
        "<div id=\"wrap\" class=\"outer\">"
        "  <span id=\"x\" class=\"hi\">hello</span>"
        "</div>";
    const char *css_src =
        "#wrap { color: #ff0000; }"
        ".hi   { color: #00ff00; font-size: 14px; }";

    html_document_t *doc = html_parse(html_src, strlen(html_src));
    css_stylesheet_t *ss = css_parse(css_src, strlen(css_src));
    if (!doc || !ss) { printf("parse failed\n"); return 1; }

    Interp *I = flywheel_new();
    if (!I) { printf("interp failed\n"); return 1; }
    flywheel_load_natives(I);
    dom_js_install(I, doc);
    dom_js_set_stylesheet(I, ss);

    FlyResult r;

    r = ev(I, "var el = document.querySelector('#x');");
    if (!ok(r)) { printf("eval failed: %s\n", r.error_msg); return 1; }
    CHECK("eval querySelector works", 1);

    r = ev(I, "var cs = document.getComputedStyle(el); cs.color;");
    CHECK("getComputedStyle color = #00ff00",
          ok(r) && as_str(r) && strcmp(as_str(r), "#00ff00") == 0);

    r = ev(I, "document.getComputedStyle(el).fontSize;");
    CHECK("getComputedStyle fontSize = 14px",
          ok(r) && as_str(r) && strcmp(as_str(r), "14px") == 0);

    r = ev(I, "el.classAdd('extra'); el.classContains('extra');");
    CHECK("classAdd + contains",
          ok(r) && r.value.kind == VAL_BOOL && r.value.as.boolean == 1);

    r = ev(I, "el.classRemove('extra'); el.classContains('extra');");
    CHECK("classRemove",
          ok(r) && r.value.kind == VAL_BOOL && r.value.as.boolean == 0);

    r = ev(I, "el.styleSet('color', '#0000ff'); document.getComputedStyle(el).color;");
    CHECK("inline styleSet overrides author rule (#0000ff)",
          ok(r) && as_str(r) && strcmp(as_str(r), "#0000ff") == 0);

    r = ev(I, "el.styleGet('color');");
    CHECK("styleGet returns #0000ff",
          ok(r) && as_str(r) && strcmp(as_str(r), "#0000ff") == 0);

    r = ev(I, "el.styleSet('color', ''); document.getComputedStyle(el).color;");
    CHECK("styleSet('') reverts to author rule (#00ff00)",
          ok(r) && as_str(r) && strcmp(as_str(r), "#00ff00") == 0);

    flywheel_free(I);
    css_free(ss);
    html_free(doc);

    printf("\n%s\n", fails ? "FAILED" : "ALL PASS");
    return fails ? 1 : 0;
}
