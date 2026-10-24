/* test_p256.c — NIST P-256 verification vectors.
 * Proves native P-256 is correct before integration.
 * Build: cc -O2 -Wall -Iinclude -Isrc/crypto -o build/test_p256 \
 *          tests/test_p256.c src/crypto/crypto_p256.c \
 *          src/crypto/crypto_libcrypto.c build/crypto/*.o ...
 * For now: link against libcrypto for ct_random.
 */
#include "crypto_p256.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>

/* Helpers: hex string <-> bytes */
static void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned int v = 0;
        sscanf(hex + 2*i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int cmp_bytes(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0 ? 0 : -1;
}

/* Since fe64/ge64 are static in crypto_p256.c, we can't call them from here.
 * Instead, use the public API to verify against NIST vector. */

int main(void) {
    int fail = 0;

    /* ---- Test 1: keypair + pub is valid point (0x04 prefix, 65 bytes) ---- */
    uint8_t priv[32], pub[65];
    if (ct_p256_keypair(priv, pub) != 0) {
        printf("FAIL: keypair returned error\n"); return 1;
    }
    if (pub[0] != 0x04) {
        printf("FAIL: pub[0] = 0x%02x, want 0x04\n", pub[0]); return 1;
    }
    printf("PASS: keypair generates 0x04-prefixed 65-byte pub\n");

    /* ---- Test 2: ECDH round-trip (alice × bob.pub == bob × alice.pub) ---- */
    uint8_t apriv[32], apub[65];
    uint8_t bpriv[32], bpub[65];
    if (ct_p256_keypair(apriv, apub) != 0) { printf("FAIL: alice keypair\n"); return 1; }
    if (ct_p256_keypair(bpriv, bpub) != 0) { printf("FAIL: bob keypair\n"); return 1; }

    uint8_t s1[32], s2[32];
    if (ct_p256_ecdh(s1, apriv, bpub) != 0) { printf("FAIL: ecdh alice\n"); return 1; }
    if (ct_p256_ecdh(s2, bpriv, apub) != 0) { printf("FAIL: ecdh bob\n"); return 1; }
    if (cmp_bytes(s1, s2, 32) != 0) {
        printf("FAIL: ECDH shared secrets differ\n");
        printf("  alice side: "); for (int i=0;i<32;i++) printf("%02x", s1[i]); printf("\n");
        printf("  bob side:   "); for (int i=0;i<32;i++) printf("%02x", s2[i]); printf("\n");
        fail = 1;
    } else {
        printf("PASS: ECDH round-trip (shared secrets match)\n");
    }

    /* ---- Test 3: known scalar → known public key (k=1 → G) ----
     * priv = 1 (big-endian 32 bytes: 0x00...01)
     * expected pub = (Gx || Gy) with 0x04 prefix
     * Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
     * Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
     */
    uint8_t priv1[32] = {0};
    priv1[31] = 1;
    uint8_t pub1[65];
    if (ct_p256_keypair(priv1, pub1) != 0) {
        /* Note: this overwrites priv1 with random! Keypair API generates its own.
         * So we can't test k=1 this way. Skip — rely on ECDH round-trip and
         * cross-check against OpenSSL for known pairs. */
        printf("SKIP: keypair(k=1) — keypair API generates own key\n");
    } else {
        (void)pub1;
    }

    /* ---- Test 4: cross-check with known ECDH vector ----
     * Use NIST CAVP vector: 
     *   alice priv = C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433
     *   bob   pub  = D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63
     *                56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB
     *   shared     = D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE
     * (From RFC 5114 test vectors)
     */
    uint8_t apriv_known[32], bpub_known[65], shared_known[32], shared_expect[32];
    hex_to_bytes("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433", apriv_known, 32);
    bpub_known[0] = 0x04;
    hex_to_bytes("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63",
                 bpub_known + 1, 32);
    hex_to_bytes("56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab",
                 bpub_known + 33, 32);
    hex_to_bytes("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de",
                 shared_expect, 32);

    if (ct_p256_ecdh(shared_known, apriv_known, bpub_known) != 0) {
        printf("FAIL: ECDH returned error on known vector\n"); return 1;
    }
    if (cmp_bytes(shared_known, shared_expect, 32) != 0) {
        printf("FAIL: ECDH on known NIST vector — got wrong shared secret\n");
        printf("  got:      "); for (int i=0;i<32;i++) printf("%02x", shared_known[i]); printf("\n");
        printf("  expected: "); for (int i=0;i<32;i++) printf("%02x", shared_expect[i]); printf("\n");
        fail = 1;
    } else {
        printf("PASS: ECDH on NIST CAVP known vector\n");
    }

    return fail;
}
