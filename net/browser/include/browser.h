/** browser.h — headless browser automation.
 *
 * Chromium is driven over the DevTools protocol (CDP); Firefox over
 * WebDriver BiDi. Both transports are plain WebSocket to a locally
 * launched browser, so no extra dependencies are required.
 */
#ifndef CUBE_NET_BROWSER_H
#define CUBE_NET_BROWSER_H

#include <stddef.h>

/* engine: "chromium" (default) or "firefox". */
int browser_fetch(const char *url, const char *engine,
                  char **html, size_t *html_len,
                  char *err, size_t err_cap);

/* 1 if the given engine binary is on PATH. */
int browser_available(const char *engine);

#endif
