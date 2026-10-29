/** crypto_legacy.h — hash/HMAC/CBC primitives for TLS <= 1.2 (MD5, SHA-1,
 *  AES-CBC, 3DES-CBC). Native implementations, zero OpenSSL. Kept out of
 *  crypto.h so the modern path stays untouched. */
#ifndef CRISPTLS_CRYPTO_LEGACY_H
#define CRISPTLS_CRYPTO_LEGACY_H

#include <stddef.h>
#include <stdint.h>

typedef enum { CTL_MD5 = 1, CTL_SHA1 = 2, CTL_SHA256 = 3, CTL_SHA384 = 4 } ctl_hash_t;
typedef enum { CTL_AES128_CBC = 1, CTL_AES256_CBC = 2, CTL_3DES_CBC = 3 } ctl_cbc_t;

typedef struct { const uint8_t *p; size_t n; } ctl_part_t;

size_t ctl_hash_len(ctl_hash_t h);     /* 0 if invalid */
size_t ctl_hash_block(ctl_hash_t h);   /* 64 or 128 */

/** Multi-part hash / HMAC (no concatenation copies). out >= ctl_hash_len(h). */
int ctl_hash_parts(ctl_hash_t h, const ctl_part_t *parts, size_t np, uint8_t *out);
int ctl_hmac_parts(ctl_hash_t h, const uint8_t *key, size_t klen,
                   const ctl_part_t *parts, size_t np, uint8_t *out);
int ctl_hash(ctl_hash_t h, const uint8_t *msg, size_t len, uint8_t *out);
int ctl_hmac(ctl_hash_t h, const uint8_t *key, size_t klen,
             const uint8_t *msg, size_t len, uint8_t *out);

size_t ctl_cbc_block(ctl_cbc_t c);     /* 16 or 8 */
size_t ctl_cbc_keylen(ctl_cbc_t c);    /* 16, 32, 24 */

/** Raw CBC, no padding. len must be a multiple of the block size.
 *  in == out is allowed. Returns 0 / -1. */
int ctl_cbc_crypt(ctl_cbc_t c, int encrypt, const uint8_t *key, const uint8_t *iv,
                  const uint8_t *in, size_t len, uint8_t *out);

int  ctl_random(uint8_t *out, size_t n);
int  ctl_eq(const void *a, const void *b, size_t n);   /* 1 if equal, constant time */
void ctl_wipe(void *p, size_t n);

#endif
