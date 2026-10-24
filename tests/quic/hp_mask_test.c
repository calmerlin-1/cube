/** hp_mask_test.c — verify AES-ECB single-block primitive. */

#include "crypto.h"
#include <stdio.h>
#include <string.h>

static int hex2b(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v; sscanf(h + i*2, "%02x", &v);
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(void) {
    uint8_t key[16], sample[16], block[16];

    hex2b("9f50449e04a0e810283a1e9933adedd2", key, 16);
    hex2b("d1b1c98dd7689fb8ec11d242b123dc9b", sample, 16);

    printf("key:    "); for (int i=0;i<16;i++) printf("%02x",key[i]); printf("\n");
    printf("sample: "); for (int i=0;i<16;i++) printf("%02x",sample[i]); printf("\n");

    int rc = ct_aes128_ecb_encrypt_block(key, sample, block);
    printf("rc=%d\n", rc);
    printf("mask:   "); for (int i=0;i<16;i++) printf("%02x",block[i]); printf("\n");
    printf("RFC wants mask[0..4] = 437b9aec34\n");

    /* Check the first block against known OpenSSL output */
    printf("\nIf mask[0..4] != 437b9aec34, then ct_aes128_ecb_encrypt_block is wrong.\n");
    return 0;
}
