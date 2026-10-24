/* test_hmac_native.c — HMAC-SHA256 (RFC 4231) and HKDF-SHA256 (RFC 5869). */
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
    for (size_t i = 0; i < n; i++) { out[i*2] = H[b[i]>>4]; out[i*2+1] = H[b[i]&0xF]; }
    out[n*2] = 0;
}

int main(void) {
    printf("=== HMAC-SHA256 (RFC 4231) ===\n");

    /* TC1: key=0x0b*20, data="Hi There" -> b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
    {
        uint8_t k[20]; memset(k, 0x0b, 20);
        uint8_t out[32]; char h[65];
        ct_hmac_sha256(k, 20, (const uint8_t*)"Hi There", 8, out);
        hex(out, 32, h);
        CHECK("TC1", strcmp(h, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")==0);
    }
    /* TC2: key="Jefe", data="what do ya want for nothing?" -> 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 */
    {
        uint8_t out[32]; char h[65];
        ct_hmac_sha256((const uint8_t*)"Jefe", 4,
                       (const uint8_t*)"what do ya want for nothing?", 28, out);
        hex(out, 32, h);
        CHECK("TC2", strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")==0);
    }
    /* TC3: key=0xaa*20, data=0xdd*50 -> 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe */
    {
        uint8_t k[20]; memset(k, 0xaa, 20);
        uint8_t d[50]; memset(d, 0xdd, 50);
        uint8_t out[32]; char h[65];
        ct_hmac_sha256(k, 20, d, 50, out);
        hex(out, 32, h);
        CHECK("TC3", strcmp(h, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")==0);
    }
    /* TC6: key=0xaa*131, data="Test Using Larger Than Block-Size Key - Hash Key First"
     *      -> 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54 */
    {
        uint8_t k[131]; memset(k, 0xaa, 131);
        const char *d = "Test Using Larger Than Block-Size Key - Hash Key First";
        uint8_t out[32]; char h[65];
        ct_hmac_sha256(k, 131, (const uint8_t*)d, strlen(d), out);
        hex(out, 32, h);
        CHECK("TC6 (>64B key)", strcmp(h, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")==0);
    }

    printf("\n=== HKDF-SHA256 (RFC 5869) ===\n");

    /* Test Case 1: IKM=0x0b*22, salt=0x000102...0c, info=0xf0f1...f9, L=42
     * PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
     * OKM = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865 */
    {
        uint8_t ikm[22]; memset(ikm, 0x0b, 22);
        uint8_t salt[13]; for (int i=0;i<13;i++) salt[i]=(uint8_t)i;
        uint8_t info[10]; for (int i=0;i<10;i++) info[i]=(uint8_t)(0xf0+i);
        uint8_t prk[32], okm[42]; char h[65], ho[85];

        ct_hkdf_extract_sha256(salt, 13, ikm, 22, prk);
        hex(prk, 32, h);
        CHECK("HKDF TC1 PRK", strcmp(h,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")==0);

        ct_hkdf_expand_sha256(prk, info, 10, okm, 42);
        hex(okm, 42, ho);
        CHECK("HKDF TC1 OKM", strcmp(ho,
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865")==0);
    }

    printf("\n=== summary ===\n  fails: %d\n", fails);
    return fails ? 1 : 0;
}
