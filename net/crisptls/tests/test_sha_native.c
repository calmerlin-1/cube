/* test_sha_native.c — NIST FIPS 180-4 test vectors for native SHA. */
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

int main(void) {
    printf("=== native SHA test (NIST vectors) ===\n");

    /* ---- SHA-256 ---- */
    /* Input "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    {
        uint8_t out[32]; char h[65];
        ct_sha256((const uint8_t *)"abc", 3, out);
        hex(out, 32, h);
        CHECK("SHA-256(\"abc\")", strcmp(h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
        if (strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
            printf("        got:  %s\n", h);
    }
    /* Input "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    {
        uint8_t out[32]; char h[65];
        ct_sha256((const uint8_t *)"", 0, out);
        hex(out, 32, h);
        CHECK("SHA-256(\"\")", strcmp(h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
        if (strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            printf("        got:  %s\n", h);
    }
    /* Input 1,000,000 'a' */
    {
        uint8_t *buf = malloc(1000000);
        memset(buf, 'a', 1000000);
        uint8_t out[32]; char h[65];
        ct_sha256(buf, 1000000, out);
        hex(out, 32, h);
        CHECK("SHA-256(1M 'a')", strcmp(h,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
        free(buf);
    }

    /* ---- SHA-512 ---- */
    /* Input "abc" -> ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
     *                2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f */
    {
        uint8_t out[64]; char h[129];
        ct_sha512((const uint8_t *)"abc", 3, out);
        hex(out, 64, h);
        CHECK("SHA-512(\"abc\")", strcmp(h,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") == 0);
        if (strcmp(h, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))
            printf("        got:  %s\n", h);
    }
    /* Input "" -> cf83e1357eefb8bd... */
    {
        uint8_t out[64]; char h[129];
        ct_sha512((const uint8_t *)"", 0, out);
        hex(out, 64, h);
        CHECK("SHA-512(\"\")", strcmp(h,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") == 0);
        if (strcmp(h, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                       "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))
            printf("        got:  %s\n", h);
    }

    /* ---- SHA-384 ---- */
    /* Input "abc" -> cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed
     *                8086072ba1e7cc2358baeca134c825a7 */
    {
        uint8_t out[48]; char h[97];
        ct_sha384((const uint8_t *)"abc", 3, out);
        hex(out, 48, h);
        CHECK("SHA-384(\"abc\")", strcmp(h,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7") == 0);
        if (strcmp(h, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                       "8086072ba1e7cc2358baeca134c825a7"))
            printf("        got:  %s\n", h);
    }

    printf("\n=== summary ===\n  fails: %d\n", fails);
    return fails ? 1 : 0;
}
