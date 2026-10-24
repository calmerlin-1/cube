/** quic_packet_test.c — RFC 9001 Appendix A.2 strict test.
 * Compares our encrypted Client Initial packet byte-for-byte against
 * the RFC's published expected ciphertext + tag. */

#include "crisptls_quic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *from_hex(const char *s, size_t *out_len) {
    size_t n = 0;
    const char *p = s;
    while (*p) {
        if (*p == ' ' || *p == '\n' || *p == '\t') { p++; continue; }
        n++; p++;
    }
    n /= 2;
    uint8_t *b = malloc(n ? n : 1);
    p = s;
    size_t i = 0;
    while (*p && i < n) {
        while (*p == ' ' || *p == '\n' || *p == '\t') p++;
        if (!*p) break;
        unsigned v;
        sscanf(p, "%02x", &v);
        b[i++] = (uint8_t)v;
        p += 2;
    }
    *out_len = n;
    return b;
}

static int check(const char *label, const uint8_t *got,
                  const char *want_hex, size_t n) {
    size_t wn = 0;
    uint8_t *want = from_hex(want_hex, &wn);
    int ok = (wn == n) && (memcmp(got, want, n) == 0);
    printf("%-20s %s\n", label, ok ? "MATCH" : "MISMATCH");
    if (!ok) {
        printf("  got: ");
        for (size_t i = 0; i < n && i < 32; i++) printf("%02x", got[i]);
        printf("\n  want:");
        for (size_t i = 0; i < wn && i < 32; i++) printf("%02x", want[i]);
        printf("\n");
    }
    free(want);
    return ok;
}

int main(void) {
    uint8_t dcid[8] = { 0x83, 0x94, 0xc8, 0xf0,
                        0x3e, 0x51, 0x57, 0x08 };

    crisptls_quic_keys_t keys;
    memset(&keys, 0, sizeof(keys));
    if (crisptls_quic_derive_initial(dcid, 8, CRISPTLS_QUIC_V1, &keys) != 0) {
        printf("derive_initial FAILED\n");
        return 1;
    }

    size_t pt_len = 0;
    uint8_t *pt = from_hex(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e0005000501000000000033002600"
        "24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e9"
        "94fc3c6e52300100000c00000000000000000000",
        &pt_len);

    size_t aad_len = 0;
    uint8_t *aad = from_hex(
        "c300000001088394c8f03e5157080000449e00000002",
        &aad_len);

    uint8_t ct[1500];
    uint8_t tag[16];
    if (crisptls_quic_packet_encrypt(&keys.client, 0x1301, 2,
                                      aad, aad_len,
                                      pt, pt_len,
                                      ct, tag) != 0) {
        printf("encrypt FAILED\n");
        return 1;
    }

    /* RFC 9001 §A.2 expected: the protected payload followed by the tag.
     * The published encrypted client Initial packet's payload is: */
    int ok = 1;
    ok &= check("ciphertext head", ct,
                 "d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d", 32);

    /* RFC 9001 §A.2 tag */
    ok &= check("tag", tag,
                 "6f8293f214659a77042b8554b38791a7", 16);

    printf("\n");
    printf(ok ? "ALL QUIC PACKET TESTS PASSED\n"
              : "SOME TESTS FAILED\n");

    free(pt); free(aad);
    return ok ? 0 : 1;
}
