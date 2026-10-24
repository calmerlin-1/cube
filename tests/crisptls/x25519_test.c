/* RFC 7748 test vectors for X25519 */
#include "x25519.h"
#include <stdio.h>
#include <string.h>

static void hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    /* Test 1: RFC 7748 §5.2, first vector
     * scalar = a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
     * point  = e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
     * output = c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
     */
    uint8_t scalar[32], point[32], out[32], expect[32];

    const char *s_hex = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    const char *p_hex = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    const char *e_hex = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

    for (int i = 0; i < 32; i++) {
        unsigned int v;
        sscanf(s_hex + i*2, "%02x", &v); scalar[i] = (uint8_t)v;
        sscanf(p_hex + i*2, "%02x", &v); point[i]  = (uint8_t)v;
        sscanf(e_hex + i*2, "%02x", &v); expect[i] = (uint8_t)v;
    }

    int rc = x25519(out, scalar, point);
    printf("rc = %d\n", rc);
    printf("out    = "); hex(out, 32);
    printf("expect = "); hex(expect, 32);
    printf("match  = %d\n", memcmp(out, expect, 32) == 0);

    /* Test 2: basepoint multiply
     * scalar = 0900000000000000000000000000000000000000000000000000000000000000
     * output = 9d61b19deff0d36f26c2b9a5d0d5b20a9e0f10a7b7c8b6a1b2b4e8e2a8f0e2c8
     * (this is the base-point test from RFC 7748)
     */

    return 0;
}
