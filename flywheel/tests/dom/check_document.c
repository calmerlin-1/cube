/** check_document.c — verify that `document` is visible from JS. */
#include "html.h"
#include "interp.h"
#include "dom.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    Interp *I = flywheel_new();
    if (!I) return 1;
    flywheel_load_natives(I);

    /* Before install: is document defined? */
    FlyResult r1 = flywheel_eval(I, "typeof document", "<test>");
    printf("before install: status=%d value_kind=%d str='%s'\n",
           r1.status, r1.value.kind,
           r1.value.kind == VAL_STRING && r1.value.as.string ? r1.value.as.string : "(non-string)");

    /* Parse a tiny HTML and install the DOM */
    const char *html = "<html><body><div id=\"x\">hi</div></body></html>";
    html_document_t *doc = html_parse(html, strlen(html));
    if (!doc) { printf("html parse failed\n"); return 1; }

    dom_js_install(I, doc);

    /* After install: is document defined? */
    FlyResult r2 = flywheel_eval(I, "typeof document", "<test>");
    printf("after install:  status=%d value_kind=%d str='%s'\n",
           r2.status, r2.value.kind,
           r2.value.kind == VAL_STRING && r2.value.as.string ? r2.value.as.string : "(non-string)");

    /* Can we call getElementById? */
    FlyResult r3 = flywheel_eval(I, "document.getElementById('x').getTagName()", "<test>");
    printf("getElementById: status=%d kind=%d\n", r3.status, r3.value.kind);
    if (r3.status == FLY_OK && r3.value.kind == VAL_STRING)
        printf("  tagName='%s'\n", r3.value.as.string);
    else if (r3.status != FLY_OK)
        printf("  error at line %d: %s\n", r3.error_line, r3.error_msg);


    {
        const char *ps[] = {
            "typeof document.getElementById",
            "typeof document.getElementById('x')",
            "document.getElementById('x') === null",
            "document.getElementById('nope') === null",
            "typeof document.documentElement",
            "typeof document.documentElement.getTagName",
            "document.documentElement.getTagName()",
            "var e = document.getElementById('x'); typeof e",
            "var e2 = document.getElementById('x'); e2.getTagName()",
            "typeof neverDeclared",
            "document.getElementById('x') === null",
            "document.getElementById('x').getAttribute('id')",
            "document.getElementById('x').getId()",
            "document.getElementById('x').getTextContent()",
            "document.getElementById('x').tagName",
            "document.querySelector('#x') === null",
            "document.querySelector('div').getTagName()",
            "document.getElementsByTagName('div').length",
            "var d = document.createElement('p'); d.setAttribute('class','k'); d.getAttribute('class')",
            "var d2 = document.createElement('span'); d2.setTextContent('yo'); document.getElementById('x').appendChild(d2); document.getElementById('x').getTextContent()",
            "document.getElementById('x').getAttribute('nope') === null",
            "typeof document.getElementsByTagName('div')[0]",
            "document.getElementsByTagName('div')[0].getTagName()",
            "document.getElementsByTagName('nope').length",
            "document.querySelectorAll('div').length",
            "document.querySelectorAll('div')[0].getTagName()",
            "document.getElementsByClassName('k').length",
            "var a = [1,2,3]; a.length",
            "var a2 = []; a2.push(5); a2.length",
            "[1,2,3][0]",
            "[1,2,3][2]",
            "var q = [7,8]; q[1]",
            "var q2 = [7,8]; q2.length",
            "typeof [].push",
            "[1,2,3].length",
            "Array.isArray([1])",
            "Array.isArray({})",
            "JSON.stringify([1,2,3])",
            "JSON.stringify({a:[1,2],b:'x'})",
            "var z=[1,2,3]; z.pop(); z.length",
            "[1,2,3].join('-')",
            "[5,6,7].indexOf(7)",
            "document.getElementsByTagName('div').length",
            "document.getElementsByClassName('k').length",
            0 };
        for (int i = 0; ps[i]; i++) {
            FlyResult r = flywheel_eval(I, ps[i], "<probe>");
            printf("PROBE %-55s st=%d kind=%d %s%s\n", ps[i], r.status, r.value.kind,
                   r.status ? "" : val_to_cstr(r.value),
                   r.status ? r.error_msg : "");
        }
    }
    html_free(doc);
    flywheel_free(I);
    return 0;
}
