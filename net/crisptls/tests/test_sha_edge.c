/* test_sha_edge.c — SHA edge cases: block-boundary lengths, random-ish bytes. */
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); fails++; } \
} while (0)

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = H[b[i] >> 4];
        out[i*2+1] = H[b[i] & 0xF];
    }
    out[n*2] = 0;
}

/* Compare native vs openssl (via command line, captured outside) —
 * here just print hex so external diff can compare. */
static void test_len(const char *desc, size_t len, uint8_t fill) {
    uint8_t *buf = malloc(len ? len : 1);
    memset(buf, fill, len);
    uint8_t out[32]; char h[65];
    ct_sha256(buf, len, out);
    hex(out, 32, h);
    printf("  %s len=%zu fill=0x%02x  sha256=%s\n", desc, len, fill, h);
    free(buf);
}

int main(void) {
    printf("=== SHA-256 edge cases (block boundaries) ===\n");
    /* Lengths around the 55/56/57 and 63/64/65 block-padding boundaries */
    test_len("len", 55, 0xAA);
    test_len("len", 56, 0xAA);
    test_len("len", 57, 0xAA);
    test_len("len", 63, 0xAA);
    test_len("len", 64, 0xAA);
    test_len("len", 65, 0xAA);
    test_len("len", 119, 0xAA);
    test_len("len", 120, 0xAA);
    test_len("len", 128, 0xAA);
    test_len("len", 32, 0xAA);   /* typical TLS transcript hash */
    test_len("len", 32, 0x00);   /* all zeros */
    test_len("len", 32, 0xFF);   /* all ones */
    return 0;
}
