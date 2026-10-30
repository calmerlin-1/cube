/** browser_native.h — cube's own headless page renderer.
 *
 * Takes fetched HTML, builds the native DOM, runs inline scripts against
 * the DOM JS bindings, and serializes the result. No subprocesses and no
 * external browser. Rendering is textual (outerHTML), matching cube's
 * "no painting" design.
 */
#ifndef FLYWHEEL_BROWSER_NATIVE_H
#define FLYWHEEL_BROWSER_NATIVE_H

#include <stddef.h>

typedef struct {
    const char *query;   /* optional CSS selector: return its text content */
    const char *eval;    /* optional JS expression: return its string value */
} browser_native_opts_t;

/* Returns 0 on success. `err` receives the first script error, if any,
 * but does not prevent serialization of the resulting DOM. */
int browser_native_run(const char *html, size_t len,
                       const browser_native_opts_t *opts,
                       char **out, size_t *out_len,
                       char *err, size_t err_cap);

#endif
