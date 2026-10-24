/** quic_varint_test.c — RFC 9000 §A.1 test vectors. */

#include "quic_varint.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int test_decode(const char *label,
                        const uint8_t *in, size_t in_len,
                        uint64_t want) {
    uint64_t got = 0;
    int n = quic_varint_decode(in, in_len, &got);
    int ok = (n > 0) && (got == want);
    printf("  %-28s decode: got=%llu (%d bytes) want=%llu  %s\n",
           label, (unsigned long long)got, n,
           (unsigned long long)want, ok ? "OK" : "FAIL");
    return ok;
}

static int test_encode(const char *label, uint64_t v,
                        const uint8_t *want, size_t want_len) {
    uint8_t buf[8];
    int n = quic_varint_encode(v, buf, sizeof(buf));
    int ok = (n == (int)want_len) && (memcmp(buf, want, want_len) == 0);
    printf("  %-28s encode: ", label);
    for (int i = 0; i < n; i++) printf("%02x", buf[i]);
    printf(" (%d bytes)  %s\n", n, ok ? "OK" : "FAIL");
    return ok;
}

int main(void) {
    int ok = 1;

    printf("RFC 9000 §A.1 test vectors\n\n");

    /* Decode */
    {
        uint8_t a[] = { 0x25 };
        ok &= test_decode("0x25 -> 37", a, 1, 37);
    }
    {
        uint8_t a[] = { 0x7b, 0xbd };
        ok &= test_decode("0x7bbd -> 15293", a, 2, 15293);
    }
    {
        uint8_t a[] = { 0x9d, 0x7f, 0x3e, 0x7d };
        ok &= test_decode("0x9d7f3e7d -> 494878333", a, 4, 494878333ULL);
    }
    {
        uint8_t a[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
        ok &= test_decode("0xc2197c5eff14e88c -> ...",
                            a, 8, 151288809941952652ULL);
    }

    /* Non-minimal encodings — same value, longer form */
    {
        uint8_t a[] = { 0x40, 0x25 };
        ok &= test_decode("0x4025 -> 37 (2-byte form)", a, 2, 37);
    }
    {
        uint8_t a[] = { 0x80, 0x00, 0x00, 0x25 };
        ok &= test_decode("0x80000025 -> 37 (4-byte form)", a, 4, 37);
    }
    {
        uint8_t a[] = { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 };
        ok &= test_decode("0xc000000000000025 -> 37 (8-byte)",
                            a, 8, 37);
    }

    printf("\nEncode round-trip\n\n");

    /* Encode (minimal) */
    { uint8_t w[] = { 0x25 }; ok &= test_encode("37", 37, w, 1); }
    { uint8_t w[] = { 0x7b, 0xbd }; ok &= test_encode("15293", 15293, w, 2); }
    { uint8_t w[] = { 0x9d, 0x7f, 0x3e, 0x7d };
      ok &= test_encode("494878333", 494878333ULL, w, 4); }
    { uint8_t w[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
      ok &= test_encode("151288809941952652", 151288809941952652ULL, w, 8); }

    /* Boundaries */
    printf("\nBoundaries\n\n");
    {
        uint8_t buf[8];
        uint64_t vals[] = { 0, 63, 64, 16383, 16384,
                            (1ULL<<30) - 1, 1ULL<<30,
                            (1ULL<<62) - 1 };
        for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
            int n = quic_varint_encode(vals[i], buf, 8);
            uint64_t back = 0;
            int m = quic_varint_decode(buf, 8, &back);
            int rok = (n == m) && (back == vals[i]);
            printf("  %-22llu enc=%d dec=%d back=%llu  %s\n",
                   (unsigned long long)vals[i], n, m,
                   (unsigned long long)back, rok ? "OK" : "FAIL");
            ok &= rok;
        }
    }

    printf("\n");
    printf(ok ? "ALL VARINT TESTS PASSED\n" : "SOME TESTS FAILED\n");
    return ok ? 0 : 1;
}
