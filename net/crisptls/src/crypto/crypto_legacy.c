/** crypto_legacy.c — TLS ≤1.2 hash/HMAC/CBC primitives. Native only.
 *
 * Hash: SHA-1, SHA-256, SHA-384, MD5 (all via crypto_sha.c/crypto_md5.c
 * streaming API). SHA-1 required for CBC-SHA1 cipher suites.
 *
 * HMAC: RFC 2104 over the above hashes.
 *
 * CBC: AES-128/256 (via crypto_aes.c). 3DES explicitly unsupported —
 * no server in the current cipher policy requires it, and 3DES is
 * deprecated. Returns -1 for CTL_3DES_CBC.
 *
 * No OpenSSL. No libsodium. */

#include "crypto_legacy.h"
#include "crypto.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* ---- Hash dispatch ---- */

size_t ctl_hash_len(ctl_hash_t h) {
    switch (h) {
    case CTL_MD5:    return 16;
    case CTL_SHA1:   return 20;
    case CTL_SHA256: return 32;
    case CTL_SHA384: return 48;
    }
    return 0;
}

size_t ctl_hash_block(ctl_hash_t h) {
    switch (h) {
    case CTL_MD5: case CTL_SHA1: case CTL_SHA256: return 64;
    case CTL_SHA384: return 128;
    }
    return 0;
}

/* Streaming hash context wrapper — matches the shapes we get from
 * crypto_sha.h / crypto_md5.h. One union per type is bigger than the
 * biggest context we might need. */
typedef union {
    ct_md5_ctx_t    md5;
    ct_sha1_ctx_t   sha1;
    ct_sha256_ctx_t sha256;
    ct_sha384_ctx_t sha384;
} ctl_hash_ctx_t;

static void ctl_hash_begin(ctl_hash_t h, ctl_hash_ctx_t *c) {
    switch (h) {
    case CTL_MD5:    ct_md5_init(&c->md5); break;
    case CTL_SHA1:   ct_sha1_init(&c->sha1); break;
    case CTL_SHA256: ct_sha256_init(&c->sha256); break;
    case CTL_SHA384: ct_sha384_init(&c->sha384); break;
    }
}

static void ctl_hash_feed(ctl_hash_t h, ctl_hash_ctx_t *c, const uint8_t *d, size_t n) {
    switch (h) {
    case CTL_MD5:    ct_md5_update(&c->md5, d, n); break;
    case CTL_SHA1:   ct_sha1_update(&c->sha1, d, n); break;
    case CTL_SHA256: ct_sha256_update(&c->sha256, d, n); break;
    case CTL_SHA384: ct_sha384_update(&c->sha384, d, n); break;
    }
}

static void ctl_hash_end(ctl_hash_t h, ctl_hash_ctx_t *c, uint8_t *out) {
    switch (h) {
    case CTL_MD5:    ct_md5_final(&c->md5, out); break;
    case CTL_SHA1:   ct_sha1_final(&c->sha1, out); break;
    case CTL_SHA256: ct_sha256_final(&c->sha256, out); break;
    case CTL_SHA384: ct_sha384_final(&c->sha384, out); break;
    }
}

int ctl_hash_parts(ctl_hash_t h, const ctl_part_t *parts, size_t np, uint8_t *out) {
    if (!out || (np && !parts) || !ctl_hash_len(h)) return -1;
    ctl_hash_ctx_t c;
    ctl_hash_begin(h, &c);
    for (size_t i = 0; i < np; i++)
        if (parts[i].n) ctl_hash_feed(h, &c, parts[i].p, parts[i].n);
    ctl_hash_end(h, &c, out);
    return 0;
}

int ctl_hash(ctl_hash_t h, const uint8_t *msg, size_t len, uint8_t *out) {
    ctl_part_t p = { msg, len };
    return ctl_hash_parts(h, &p, 1, out);
}

/* ---- HMAC (RFC 2104) built on ctl_hash_parts ---- */

int ctl_hmac_parts(ctl_hash_t h, const uint8_t *key, size_t klen,
                   const ctl_part_t *parts, size_t np, uint8_t *out) {
    size_t B = ctl_hash_block(h), hl = ctl_hash_len(h);
    if (!B || np > 8 || (klen && !key)) return -1;
    uint8_t k0[128], pad[128], inner[48];
    memset(k0, 0, sizeof k0);
    if (klen > B) { if (ctl_hash(h, key, klen, k0)) return -1; }
    else if (klen) memcpy(k0, key, klen);

    ctl_part_t pp[9];
    for (size_t i = 0; i < B; i++) pad[i] = k0[i] ^ 0x36;
    pp[0].p = pad; pp[0].n = B;
    for (size_t i = 0; i < np; i++) pp[1 + i] = parts[i];
    int r = ctl_hash_parts(h, pp, np + 1, inner);
    if (!r) {
        for (size_t i = 0; i < B; i++) pad[i] = k0[i] ^ 0x5c;
        ctl_part_t po[2] = { { pad, B }, { inner, hl } };
        r = ctl_hash_parts(h, po, 2, out);
    }
    ctl_wipe(k0, sizeof k0); ctl_wipe(pad, sizeof pad); ctl_wipe(inner, sizeof inner);
    return r;
}

int ctl_hmac(ctl_hash_t h, const uint8_t *key, size_t klen,
             const uint8_t *msg, size_t len, uint8_t *out) {
    ctl_part_t p = { msg, len };
    return ctl_hmac_parts(h, key, klen, &p, 1, out);
}

/* ---- CBC mode ---- */

size_t ctl_cbc_block(ctl_cbc_t c) {
    switch (c) {
    case CTL_AES128_CBC: case CTL_AES256_CBC: return 16;
    case CTL_3DES_CBC: return 0;   /* unsupported natively */
    }
    return 0;
}

size_t ctl_cbc_keylen(ctl_cbc_t c) {
    switch (c) {
    case CTL_AES128_CBC: return 16;
    case CTL_AES256_CBC: return 32;
    case CTL_3DES_CBC: return 0;   /* unsupported */
    }
    return 0;
}

int ctl_cbc_crypt(ctl_cbc_t c, int encrypt, const uint8_t *key, const uint8_t *iv,
                  const uint8_t *in, size_t len, uint8_t *out) {
    if (!key || !iv || !in || !out || (len % 16)) return -1;
    int rc;
    if (c == CTL_AES128_CBC) {
        rc = encrypt ? ct_aes128_cbc_encrypt(key, iv, in, out, len)
                     : ct_aes128_cbc_decrypt(key, iv, in, out, len);
    } else if (c == CTL_AES256_CBC) {
        rc = encrypt ? ct_aes256_cbc_encrypt(key, iv, in, out, len)
                     : ct_aes256_cbc_decrypt(key, iv, in, out, len);
    } else {
        return -1;   /* CTL_3DES_CBC: not supported natively */
    }
    return rc == CT_OK ? 0 : -1;
}

/* ---- Utilities ---- */

int ctl_random(uint8_t *out, size_t n) {
    if (!out && n) return -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

int ctl_eq(const void *a, const void *b, size_t n) {
    const uint8_t *pa = a, *pb = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= pa[i] ^ pb[i];
    return d == 0;
}

void ctl_wipe(void *p, size_t n) {
    if (!p || !n) return;
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}
