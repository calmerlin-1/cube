#include <stdio.h>
#include <string.h>
#include "url_parser.h"

typedef struct {
    const char *in;
    const char *want_scheme;
    const char *want_host;
    unsigned    want_port;
    const char *want_path;
    const char *want_query;    /* NULL means expected NULL */
    const char *want_fragment; /* NULL means expected NULL */
} tc_t;

static int field_ok(const char *got, size_t got_len, const char *want) {
    if (!want) return got_len == 0 || got == NULL;
    if (!got) return 0;
    return got_len == strlen(want) && memcmp(got, want, got_len) == 0;
}

int main(void) {
    /* RFC 3986 §6.2.2 + WHATWG canonicalization cases */
    tc_t cases[] = {
        { "https://example.com/",                    "https", "example.com", 443, "/",     NULL,   NULL },
        { "HTTPS://example.com/",                    "https", "example.com", 443, "/",     NULL,   NULL },
        { "HtTpS://ExAmPlE.CoM/PaTh",                "https", "example.com", 443, "/PaTh", NULL,   NULL },
        { "https://example.com:443/",                "https", "example.com", 443, "/",     NULL,   NULL },
        { "http://example.com:80/",                  "http",  "example.com", 80,  "/",     NULL,   NULL },
        { "http://example.com:8080/",                "http",  "example.com", 8080,"/",     NULL,   NULL },
        { "https://example.com./path",               "https", "example.com", 443, "/path", NULL,   NULL },
        { "https://example.com../path",              "https", "example.com", 443, "/path", NULL,   NULL },
        { "https://example.com/?",                   "https", "example.com", 443, "/",     NULL,   NULL },
        { "https://example.com/#",                   "https", "example.com", 443, "/",     NULL,   NULL },
        { "https://example.com/?#",                  "https", "example.com", 443, "/",     NULL,   NULL },
        { "https://example.com/?a=1",                "https", "example.com", 443, "/",     "a=1",  NULL },
        { "https://example.com/#frag",               "https", "example.com", 443, "/",     NULL,   "frag" },
        { "https://[::1]/",                          "https", "::1",         443, "/",     NULL,   NULL },
        { "https://[2001:DB8::1]/",                  "https", "2001:db8::1", 443, "/",     NULL,   NULL },
        { "http:example.com",                        "http",  "example.com", 80,  "/",     NULL,   NULL },
        { "http:/example.com",                       "http",  "example.com", 80,  "/",     NULL,   NULL },
        { "http:///example.com",                     "http",  "example.com", 80,  "/",     NULL,   NULL },
        { "  https://example.com/  ",                "https", "example.com", 443, "/",     NULL,   NULL },
        { "https://example.com/pa\nth",              "https", "example.com", 443, "/path", NULL,   NULL },
        { NULL, NULL, NULL, 0, NULL, NULL, NULL }
    };

    int pass = 0, fail = 0;
    for (int i = 0; cases[i].in; i++) {
        char buf[8192]; size_t n = 0; url_view v;
        url_err e = url_parse_whatwg_stable(cases[i].in, strlen(cases[i].in),
                                             buf, sizeof buf, &n, &v);
        if (e != URL_OK) {
            printf("FAIL [%02d] %-38s  err=%s\n", i, cases[i].in, url_err_name(e));
            fail++; continue;
        }
        int ok = 1;
        if (!field_ok(v.scheme, v.scheme_len, cases[i].want_scheme)) ok = 0;
        if (!field_ok(v.host,   v.host_len,   cases[i].want_host))   ok = 0;
        if (cases[i].want_port && v.port != cases[i].want_port)      ok = 0;
        if (!field_ok(v.path,   v.path_len,   cases[i].want_path))   ok = 0;
        if (!field_ok(v.query,  v.query_len,  cases[i].want_query))  ok = 0;
        if (!field_ok(v.fragment, v.fragment_len, cases[i].want_fragment)) ok = 0;
        if (ok) {
            pass++;
        } else {
            printf("FAIL [%02d] %-38s\n", i, cases[i].in);
            printf("   scheme='%.*s'  want='%s'\n", (int)v.scheme_len, v.scheme ? v.scheme : "", cases[i].want_scheme ? cases[i].want_scheme : "(null)");
            printf("   host  ='%.*s'  want='%s'\n", (int)v.host_len,   v.host   ? v.host   : "", cases[i].want_host   ? cases[i].want_host   : "(null)");
            printf("   port  =%u  want=%u\n", v.port, cases[i].want_port);
            printf("   path  ='%.*s'  want='%s'\n", (int)v.path_len,   v.path   ? v.path   : "", cases[i].want_path   ? cases[i].want_path   : "(null)");
            printf("   query =%s  want=%s\n", v.query ? "non-NULL" : "NULL", cases[i].want_query ? "non-NULL" : "NULL");
            printf("   frag  =%s  want=%s\n", v.fragment ? "non-NULL" : "NULL", cases[i].want_fragment ? "non-NULL" : "NULL");
            fail++;
        }
    }
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
