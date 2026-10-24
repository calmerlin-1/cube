/** quic_test.c — RFC 9001 Appendix A test vectors. */

#include "crisptls_quic.h"
#include <stdio.h>
#include <string.h>

static void dump(const char *label, const uint8_t *b, size_t n) {
    printf("%-22s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int cmp(const char *label, const uint8_t *got,
               const char *expect_hex, size_t n) {
    uint8_t want[64];
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(expect_hex + i*2, "%02x", &v);
        want[i] = (uint8_t)v;
    }
    int ok = memcmp(got, want, n) == 0;
    dump(label, got, n);
    if (!ok) {
        printf("%-22s EXPECTED ", "");
        for (size_t i = 0; i < n; i++) printf("%02x", want[i]);
        printf("\n");
        printf("  -> MISMATCH\n");
    }
    return ok;
}

int main(void) {
    /* Test vector from RFC 9001 §A.1 */
    uint8_t dcid[8] = { 0x83, 0x94, 0xc8, 0xf0,
                        0x3e, 0x51, 0x57, 0x08 };

    crisptls_quic_keys_t keys;
    memset(&keys, 0, sizeof(keys));

    if (crisptls_quic_derive_initial(dcid, 8, CRISPTLS_QUIC_V1, &keys) != 0) {
        printf("derive_initial FAILED\n");
        return 1;
    }

    printf("RFC 9001 Appendix A.1 test vector\n");
    printf("DCID = 8394c8f03e515708\n\n");

    int ok = 1;

    /* Client initial */
    ok &= cmp("client packet_key", keys.client.packet_key,
              "1f369613dd76d5467730efcbe3b1a22d", 16);
    ok &= cmp("client packet_iv",  keys.client.packet_iv,
              "fa044b2f42a3fd3b46fb255c", 12);
    ok &= cmp("client hp_key",     keys.client.hp_key,
              "9f50449e04a0e810283a1e9933adedd2", 16);

    /* Server initial */
    ok &= cmp("server packet_key", keys.server.packet_key,
              "cf3a5331653c364c88f0f379b6067e37", 16);
    ok &= cmp("server packet_iv",  keys.server.packet_iv,
              "0ac1493ca1905853b0bba03e", 12);
    ok &= cmp("server hp_key",     keys.server.hp_key,
              "c206b8d9b9f0f37644430b490eeaa314", 16);

    printf("\n");
    if (ok) printf("ALL TESTS PASSED\n");
    else    printf("SOME TESTS FAILED\n");
    return ok ? 0 : 1;
}
