#include "crypto.h"
#include <stdio.h>
#include <string.h>

static void hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t zeros[48] = {0};

    /* HKDF-Extract-SHA384(0^48, 0^48) */
    uint8_t prk[48];
    ct_hkdf_extract_sha384(zeros, 48, zeros, 48, prk);
    printf("E-SHA384(0^48,0^48) = "); hex(prk, 48);

    /* HMAC-SHA384(0^48, 0^48) — same thing */
    uint8_t direct[48];
    ct_hmac_sha384(zeros, 48, zeros, 48, direct);
    printf("HMAC-SHA384(0^48,0^48) = "); hex(direct, 48);
    printf("match: %d\n", memcmp(prk, direct, 48) == 0);

    /* HKDF-Expand-Label-SHA384 with empty context */
    uint8_t out48[48];
    ct_hkdf_expand_label_sha384(prk, "test", (const uint8_t *)"", 0, out48, 48);
    printf("Expand-Label(prk,\"test\",\"\",48) = "); hex(out48, 48);

    /* SHA-384 of empty string */
    uint8_t eh[48];
    ct_sha384((const uint8_t *)"", 0, eh);
    printf("SHA-384(\"\") = "); hex(eh, 48);

    return 0;
}
