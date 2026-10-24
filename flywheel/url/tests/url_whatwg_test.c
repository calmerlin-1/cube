#include <stdio.h>
#include <string.h>
#include "url_parser.h"

static void show(const char *u) {
    url_view v1, v2;
    url_err e1 = url_parse(u, strlen(u), &v1);
    url_err e2 = url_parse_whatwg(u, strlen(u), &v2);
    char c2[512] = {0}; size_t n2 = 0;
    if (e2 == URL_OK) url_canonicalize(&v2, c2, sizeof c2, &n2);
    printf("--- %s ---\n", u);
    printf("  strict: %s\n", e1 == URL_OK ? "OK" : url_err_name(e1));
    printf("  whatwg: %s%s%s\n",
           e2 == URL_OK ? "OK -> " : url_err_name(e2),
           e2 == URL_OK ? c2 : "",
           "");
    printf("\n");
}

int main(void) {
    const char *urls[] = {
        "http://exa mple.com/",           // space in host
        "http://exa\tmple.com/",          // tab (browsers strip)
        "http://exa\nmple.com/",          // newline (browsers strip)
        "http:example.com",                // missing //
        "http:/example.com",               // single slash
        "http:///example.com",             // triple slash
        "http:\\\\example.com\\path",      // backslashes
        "http://1234/",                    // integer IPv4
        "http://1.2.3/",                   // 3-part IP
        "http://example.com:/",            // empty port
        "http://example.com:443",          // no path
        "http://[::1]/",                   // IPv6
        "http://[::ffff:192.0.2.1]/",      // IPv4-mapped IPv6
        "http://example.com/a/../b",       // dot segments
        "http://example.com/./a",          // dot prefix
        "HTTP://EXAMPLE.COM",              // case
        "  http://example.com  ",          // leading/trailing spaces
        "http://example.com/path with space",  // space in path
        "http://example.com/%zz",          // bad percent
        NULL
    };
    for (int i = 0; urls[i]; i++) show(urls[i]);
    return 0;
}
