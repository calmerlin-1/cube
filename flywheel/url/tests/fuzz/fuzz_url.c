/* fuzz_url.c — libFuzzer harness for the URL library.
 *
 * Goal: exercise every public entry point with hostile input. The fuzzer
 * dictionary (tests/fuzz/url.dict) guides mutations toward URL grammar so
 * coverage isn't wasted on random bytes that die at has_bad_char.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "url_parser.h"
#include "url_percent.h"
#include "url_idna.h"
#include "url_cache.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = 0;

    /* 1. strict parse, all flag combinations */
    url_view v;
    url_err e = url_parse(buf, size, &v);
    url_view tmp;
    url_parse_ex(buf, size, URL_F_STRICT_HTTP, &tmp);
    url_parse_ex(buf, size, URL_F_ALLOW_CTRL, &tmp);
    url_parse_ex(buf, size, URL_F_ALLOW_SPACE, &tmp);
    url_parse_ex(buf, size, URL_F_NO_DEFAULT, &tmp);
    url_parse_ex(buf, size, URL_F_ALLOW_CTRL|URL_F_ALLOW_SPACE, &tmp);

    /* 2. validate — regardless of parse result (uses whatever fields
     *    are set; caller might misuse this in real code) */
    url_validate(&v);

    /* 3. canonicalize — on success only */
    if (e == URL_OK) {
        char out[65536];
        size_t n = 0;
        url_canonicalize(&v, out, sizeof out, &n);
    }

    /* 4. build variants — on success */
    if (e == URL_OK) {
        char out[65536];
        size_t n = 0;
        url_build_origin(&v, out, sizeof out, &n);
        url_build_href(&v, out, sizeof out, &n);
        url_build_href_encoded(&v, out, sizeof out, &n);
        url_build_full(&v, out, sizeof out, &n);
    }

    /* 5. WHATWG stable parse */
    {
        char norm[65536];
        size_t n = 0;
        url_view w;
        if (url_parse_whatwg_stable(buf, size, norm, sizeof norm, &n, &w) == URL_OK) {
            url_validate(&w);
        }
    }

    /* 6. auto */
    {
        char norm[65536];
        size_t n = 0;
        url_view a;
        url_parse_auto(buf, size, norm, sizeof norm, &n, &a);
    }

    /* 7. cache: miss + hit + hit + hit again after evict pressure */
    {
        url_cache_t *c = url_cache_new(8);
        if (c) {
            url_view cv;
            url_cache_parse(c, buf, size, &cv);
            url_cache_parse(c, buf, size, &cv);
            /* insert 20 other entries to force eviction, then re-hit */
            for (int k = 0; k < 20; k++) {
                char other[64];
                int m = snprintf(other, sizeof other, "http://x%d/", k);
                url_view ov;
                url_cache_parse(c, other, (size_t)m, &ov);
            }
            url_cache_parse(c, buf, size, &cv);
            url_cache_free(c);
        }
    }

    /* 8. same-origin — on success only */
    if (e == URL_OK) {
        url_same_host(&v, &v);
        url_same_origin(&v, &v);
    }

    /* 9. join with hostile relative refs */
    if (e == URL_OK) {
        char out[65536];
        size_t n = 0;
        const char *rels[] = {
            "", "/", "//", "/x", "?q", "#f", "..", "../..",
            "../../../..", "?a=b&c=d", "#" "\x00",
        };
        for (size_t r = 0; r < sizeof(rels)/sizeof(*rels); r++) {
            url_join(&v, rels[r], strlen(rels[r]), out, sizeof out, &n);
        }
    }

    /* 10. direct percent / IDN entry points */
    {
        char out[65536];
        size_t n = 0;
        url_percent_decode(buf, size, out, sizeof out, &n, 0);
        url_percent_decode(buf, size, out, sizeof out, &n, 1);
        url_percent_encode_path(buf, size, out, sizeof out, &n);
        url_percent_encode_query(buf, size, out, sizeof out, &n);
        url_percent_encode_strict(buf, size, out, sizeof out, &n);
        url_utf8_valid(buf, size);

        char ascii[512];
        size_t alen = 0;
        url_idna_to_ascii(buf, size, ascii, sizeof ascii, &alen);
        url_idna_to_unicode(buf, size, ascii, sizeof ascii, &alen);
    }

    free(buf);
    return 0;
}
