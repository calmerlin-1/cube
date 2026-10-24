/* crypto_sha.c — native SHA-256 (FIPS 180-4), SHA-384, SHA-512 (FIPS 180-4).
 * No OpenSSL. No libsodium. No external dependencies.
 * Public API: ct_sha256, ct_sha384, ct_sha512 — matches crypto.h. */

#include "crypto.h"
#include <string.h>

/* ============================================================
 * SHA-256 (FIPS 180-4 §6.2)
 * ============================================================ */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha256_compress(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
               ((uint32_t)blk[i*4+2] << 8) | blk[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i-15], 7) ^ ROTR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR32(w[i-2], 17) ^ ROTR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=st[0], b=st[1], c=st[2], d=st[3], e=st[4], f=st[5], g=st[6], h=st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void sha256_init(sha256_ctx_t *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->buflen = 0;
}

static void sha256_update(sha256_ctx_t *c, const uint8_t *d, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, d, take);
        c->buflen += take;
        d += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_compress(c->h, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) sha256_update(c, &zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(c, len_be, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

int ct_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
    return 0;
}

/* ============================================================
 * SHA-512 (FIPS 180-4 §6.5)
 * ============================================================ */

typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t  buf[128];
    size_t   buflen;
} sha512_ctx_t;

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_compress(uint64_t st[8], const uint8_t blk[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)blk[i*8] << 56) | ((uint64_t)blk[i*8+1] << 48) |
               ((uint64_t)blk[i*8+2] << 40) | ((uint64_t)blk[i*8+3] << 32) |
               ((uint64_t)blk[i*8+4] << 24) | ((uint64_t)blk[i*8+5] << 16) |
               ((uint64_t)blk[i*8+6] << 8) | blk[i*8+7];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROTR64(w[i-15],1) ^ ROTR64(w[i-15],8) ^ (w[i-15] >> 7);
        uint64_t s1 = ROTR64(w[i-2],19) ^ ROTR64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROTR64(e,14) ^ ROTR64(e,18) ^ ROTR64(e,41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ROTR64(a,28) ^ ROTR64(a,34) ^ ROTR64(a,39);
        uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void sha512_init(sha512_ctx_t *c) {
    c->h[0]=0x6a09e667f3bcc908ULL; c->h[1]=0xbb67ae8584caa73bULL;
    c->h[2]=0x3c6ef372fe94f82bULL; c->h[3]=0xa54ff53a5f1d36f1ULL;
    c->h[4]=0x510e527fade682d1ULL; c->h[5]=0x9b05688c2b3e6c1fULL;
    c->h[6]=0x1f83d9abfb41bd6bULL; c->h[7]=0x5be0cd19137e2179ULL;
    c->len = 0; c->buflen = 0;
}

static void sha512_update(sha512_ctx_t *c, const uint8_t *d, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 128 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, d, take);
        c->buflen += take;
        d += take;
        n -= take;
        if (c->buflen == 128) {
            sha512_compress(c->h, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha512_final(sha512_ctx_t *c, uint8_t out[64]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 112) sha512_update(c, &zero, 1);
    uint8_t len_be[16] = {0};
    for (int i = 0; i < 8; i++) len_be[8 + i] = (uint8_t)(bits >> (56 - i*8));
    sha512_update(c, len_be, 16);
    for (int i = 0; i < 8; i++) {
        out[i*8]   = (uint8_t)(c->h[i] >> 56);
        out[i*8+1] = (uint8_t)(c->h[i] >> 48);
        out[i*8+2] = (uint8_t)(c->h[i] >> 40);
        out[i*8+3] = (uint8_t)(c->h[i] >> 32);
        out[i*8+4] = (uint8_t)(c->h[i] >> 24);
        out[i*8+5] = (uint8_t)(c->h[i] >> 16);
        out[i*8+6] = (uint8_t)(c->h[i] >> 8);
        out[i*8+7] = (uint8_t)(c->h[i]);
    }
}

int ct_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    sha512_ctx_t c;
    sha512_init(&c);
    sha512_update(&c, data, len);
    sha512_final(&c, out);
    return 0;
}

/* ============================================================
 * SHA-384 — SHA-512 with different IV, truncate to 48 bytes.
 * ============================================================ */

int ct_sha384(const uint8_t *data, size_t len, uint8_t out[48]) {
    sha512_ctx_t c;
    sha512_init(&c);
    c.h[0]=0xcbbb9d5dc1059ed8ULL; c.h[1]=0x629a292a367cd507ULL;
    c.h[2]=0x9159015a3070dd17ULL; c.h[3]=0x152fecd8f70e5939ULL;
    c.h[4]=0x67332667ffc00b31ULL; c.h[5]=0x8eb44a8768581511ULL;
    c.h[6]=0xdb0c2e0d64f98fa7ULL; c.h[7]=0x47b5481dbefa4fa4ULL;
    sha512_update(&c, data, len);
    uint8_t full[64];
    sha512_final(&c, full);
    memcpy(out, full, 48);
    return 0;
}

/* ============================================================
 * Public streaming API — thin wrappers around the internal helpers.
 * The internal sha256_ctx_t / sha512_ctx_t are layout-compatible
 * with the public ct_sha256_ctx_t / ct_sha512_ctx_t declared in crypto.h.
 * ============================================================ */

/* _Static_assert layout compatibility at build time */
_Static_assert(sizeof(sha256_ctx_t) == sizeof(ct_sha256_ctx_t),
               "sha256_ctx_t layout mismatch");
_Static_assert(sizeof(sha512_ctx_t) == sizeof(ct_sha512_ctx_t),
               "sha512_ctx_t layout mismatch");

void ct_sha256_init(ct_sha256_ctx_t *c) {
    sha256_init((sha256_ctx_t *)c);
}
void ct_sha256_update(ct_sha256_ctx_t *c, const uint8_t *d, size_t n) {
    sha256_update((sha256_ctx_t *)c, d, n);
}
void ct_sha256_final(ct_sha256_ctx_t *c, uint8_t out[32]) {
    sha256_final((sha256_ctx_t *)c, out);
}

void ct_sha512_init(ct_sha512_ctx_t *c) {
    sha512_init((sha512_ctx_t *)c);
}
void ct_sha512_update(ct_sha512_ctx_t *c, const uint8_t *d, size_t n) {
    sha512_update((sha512_ctx_t *)c, d, n);
}
void ct_sha512_final(ct_sha512_ctx_t *c, uint8_t out[64]) {
    sha512_final((sha512_ctx_t *)c, out);
}

/* SHA-384 — dedicated init/update/final with its own IV */
void ct_sha384_init(ct_sha384_ctx_t *c) {
    sha512_init((sha512_ctx_t *)c);
    ((sha512_ctx_t *)c)->h[0] = 0xcbbb9d5dc1059ed8ULL;
    ((sha512_ctx_t *)c)->h[1] = 0x629a292a367cd507ULL;
    ((sha512_ctx_t *)c)->h[2] = 0x9159015a3070dd17ULL;
    ((sha512_ctx_t *)c)->h[3] = 0x152fecd8f70e5939ULL;
    ((sha512_ctx_t *)c)->h[4] = 0x67332667ffc00b31ULL;
    ((sha512_ctx_t *)c)->h[5] = 0x8eb44a8768581511ULL;
    ((sha512_ctx_t *)c)->h[6] = 0xdb0c2e0d64f98fa7ULL;
    ((sha512_ctx_t *)c)->h[7] = 0x47b5481dbefa4fa4ULL;
}
void ct_sha384_update(ct_sha384_ctx_t *c, const uint8_t *d, size_t n) {
    sha512_update((sha512_ctx_t *)c, d, n);
}
void ct_sha384_final(ct_sha384_ctx_t *c, uint8_t out[48]) {
    uint8_t full[64];
    sha512_final((sha512_ctx_t *)c, full);
    memcpy(out, full, 48);
}

/* ============================================================
 * SHA-1 (FIPS 180-4 §6.1) — needed for TLS 1.2 CBC-HMAC-SHA1 suites.
 * ============================================================ */

static void sha1_compress(uint32_t st[5], const uint8_t blk[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
               ((uint32_t)blk[i*4+2] << 8) | blk[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a=st[0], b=st[1], c=st[2], d=st[3], e=st[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;          k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;          k = 0xca62c1d6; }
        uint32_t tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = ((b << 30) | (b >> 2)); b = a; a = tmp;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e;
}

void ct_sha1_init(ct_sha1_ctx_t *c) {
    c->h[0]=0x67452301; c->h[1]=0xefcdab89; c->h[2]=0x98badcfe;
    c->h[3]=0x10325476; c->h[4]=0xc3d2e1f0;
    c->len = 0; c->buflen = 0;
}
void ct_sha1_update(ct_sha1_ctx_t *c, const uint8_t *d, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, d, take);
        c->buflen += take;
        d += take; n -= take;
        if (c->buflen == 64) { sha1_compress(c->h, c->buf); c->buflen = 0; }
    }
}
void ct_sha1_final(ct_sha1_ctx_t *c, uint8_t out[20]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    ct_sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) ct_sha1_update(c, &zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56 - i*8));
    ct_sha1_update(c, len_be, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}
int ct_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    ct_sha1_ctx_t c;
    ct_sha1_init(&c);
    ct_sha1_update(&c, data, len);
    ct_sha1_final(&c, out);
    return 0;
}
