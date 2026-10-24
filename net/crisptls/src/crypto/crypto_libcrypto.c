/** crypto_libcrypto.c — libcrypto bindings. Primitives only. No SSL_*.
 * Alternative backend to crypto_sodium.c; pick one at link time. */

#include "crypto.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int ct_random(uint8_t *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return CT_ERR_CRYPTO;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            close(fd);
            return CT_ERR_CRYPTO;
        }
        got += (size_t)r;
    }
    close(fd);
    return CT_OK;
}






/* ---- SHA-384 variants (for TLS_AES_256_GCM_SHA384) ---- */




/** AEAD via EVP */




int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* ---- Single-block primitives for QUIC header protection ---- */





