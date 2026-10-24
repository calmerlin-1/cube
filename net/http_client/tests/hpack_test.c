/* Huffman decoder tests — verified against Python hpack library. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int h2_huff_decode(const uint8_t *in, size_t in_len, char **out);

static void test(const char *name, const char *hex, const char *expected) {
    size_t n = strlen(hex) / 2;
    uint8_t *buf = malloc(n);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i*2, "%02x", &v);
        buf[i] = (uint8_t)v;
    }
    char *out = NULL;
    int rc = h2_huff_decode(buf, n, &out);
    int ok = (rc == 0) && out && strcmp(out, expected) == 0;
    printf("  %-26s rc=%d  got='%s'  want='%s'  %s\n",
           name, rc,
           out ? out : "(null)",
           expected,
           ok ? "PASS" : "FAIL");
    free(out);
    free(buf);
}

int main(void) {
    printf("=== Huffman decoder tests (against Python hpack) ===\n");

    /* RFC 7541 §C.4.2 published value */
    test("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff", "www.example.com");

    /* Correct huffman for custom-key: custom-value (from Python hpack) */
    test("custom-key: custom-value",
         "25a849e95ba97d5c5096a127a56ee3a2d2ff",
         "custom-key: custom-value");

    /* Short strings */
    test("gzip",   "9bd9ab",       "gzip");
    test("no-cache", "a8eb10649cbf", "no-cache");
    test("/",      "63",           "/");
    test("302",    "6402",         "302");
    test("private", "aec3771a4b",   "private");
    test("Mon, 21 Oct 2013 20:13:21 GMT",
         "d07abe941054d444a8200595040b8166e082a62d1bff",
         "Mon, 21 Oct 2013 20:13:21 GMT");
    test("https://www.example.com",
         "9d29ad171863c78f0b97c8e9ae82ae43d3",
         "https://www.example.com");

    return 0;
}
