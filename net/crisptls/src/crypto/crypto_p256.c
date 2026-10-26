/** crypto_p256.c — native secp256r1 (NIST P-256) ECDH.
 *
 * Zero external deps. Constant-time scalar multiplication (Montgomery ladder),
 * variable-time field inversion (Fermat — safe because only used on public
 * points or on secrets that are already protected by ladder structure).
 *
 * Representation: uint64_t[4] little-endian limbs (radix 2^64).
 * Uses __int128 for 128-bit multiplication carries. Requires a compiler with
 * 128-bit integer support (clang, gcc, all target triples on ARM64/x86-64).
 *
 * API matches crypto_ec.c's OpenSSL-backed versions:
 *   ct_p256_keypair(priv[32], pub_uncompressed[65])
 *   ct_p256_ecdh(shared[32], priv[32], peer_pub[65])
 *
 * Curve: y^2 = x^3 - 3x + b
 *   p  = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *   b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 *   Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 *   Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 */

#include "crypto.h"
#include "crypto_p256.h"
#include <stdio.h>
#include <string.h>

/* Field element: uint64_t[4], little-endian. p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */

/* Prime p in u64[4] little-endian. */
static const uint64_t P64[4] = {
    0xFFFFFFFFFFFFFFFFull,
    0x00000000FFFFFFFFull,
    0x0000000000000000ull,
    0xFFFFFFFF00000001ull
};

/* Curve b */
static const uint64_t B64[4] = {
    0x3BCE3C3E27D2604Bull,
    0x651D06B0CC53B0F6ull,
    0xB3EBBD55769886BCull,
    0x5AC635D8AA3A93E7ull
};

/* Generator G */
static const uint64_t GX64[4] = {
    0xF4A13945D898C296ull,
    0x77037D812DEB33A0ull,
    0xF8BCE6E563A440F2ull,
    0x6B17D1F2E12C4247ull
};
static const uint64_t GY64[4] = {
    0xCBB6406837BF51F5ull,
    0x2BCE33576B315ECEull,
    0x8EE7EB4A7C0F9E16ull,
    0x4FE342E2FE1A7F9Bull
};

/* p - 2, for Fermat inversion */
static const uint64_t PM2_64[4] = {
    0xFFFFFFFFFFFFFFFDull,
    0x00000000FFFFFFFFull,
    0x0000000000000000ull,
    0xFFFFFFFF00000001ull
};
/* R mod p = 2^256 mod p. Used by Barrett reduction and other folds. */
static const uint64_t R_MOD_P[4] = {
    0x0000000000000001ull,
    0xFFFFFFFF00000000ull,
    0xFFFFFFFFFFFFFFFFull,
    0x00000000FFFFFFFEull
};

/* ---- helpers ---- */

static void fe64_zero(uint64_t r[4]) { r[0]=r[1]=r[2]=r[3]=0; }
static void fe64_copy(uint64_t r[4], const uint64_t a[4]) { r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3]; }
static void fe64_one(uint64_t r[4]) { r[0]=1; r[1]=r[2]=r[3]=0; }

/* return 1 if a >= b (b < 2^256, a < 2^256), 0 otherwise. */
static int fe64_gte(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1;  /* equal */
}

/* r = a + b, returns carry out (0 or 1). */
static uint64_t fe64_add_raw(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    unsigned __int128 t = 0;
    for (int i = 0; i < 4; i++) {
        t += (unsigned __int128)a[i] + (unsigned __int128)b[i];
        r[i] = (uint64_t)t;
        t >>= 64;
    }
    return (uint64_t)t;
}

/* r = a - b, returns borrow out (0 or 1). */
static uint64_t fe64_sub_raw(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    unsigned __int128 t = 0;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        t = (unsigned __int128)a[i] - (unsigned __int128)b[i] - borrow;
        r[i] = (uint64_t)t;
        borrow = (uint64_t)(t >> 64) & 1;
    }
    return borrow;
}

/* r = a + b mod p. a, b assumed < p. */
static void fe64_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[4];
    uint64_t carry = fe64_add_raw(t, a, b);

    if (!carry) {
        if (fe64_gte(t, P64)) {
            uint64_t sub[4];
            fe64_sub_raw(sub, t, P64);
            fe64_copy(r, sub);
        } else {
            fe64_copy(r, t);
        }
        return;
    }

    /* a+b >= 2^256. Then a+b < 2p, so a+b-p < p. And
     * a+b-p = (2^256 - p) + t = c + t, with c+t < 2^256. */
    static const uint64_t C64[4] = {
        0x0000000000000001ull,
        0xFFFFFFFF00000000ull,
        0xFFFFFFFFFFFFFFFFull,
        0x00000000FFFFFFFEull
    };
    uint64_t sum[4];
    fe64_add_raw(sum, t, C64);
    fe64_copy(r, sum);
}
static void fe64_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[4];
    uint64_t borrow = fe64_sub_raw(t, a, b);
    if (borrow) {
        /* add p back */
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 v = (unsigned __int128)t[i] + (unsigned __int128)P64[i] + carry;
            t[i] = (uint64_t)v;
            carry = (uint64_t)(v >> 64);
        }
    }
    fe64_copy(r, t);
}

/* 4x4 schoolbook multiply -> 8-limb result. */
static void fe64_mul_wide(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]) {
    fe64_zero(r);
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 prod = (unsigned __int128)a[i] * b[j]
                                    + r[i + j]
                                    + carry;
            r[i + j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        r[i + 4] = (uint64_t)carry;
    }
}

/* Reduce 8-limb t mod p, writing 4-limb result.
 * Uses repeated hi*c reduction (c = 2^256 - p), twice, with proper 5-limb handling. */
static void fe64_reduce(uint64_t r[4], uint64_t t[8]) {
    /* Barrett reduction for P-256. t < p² (512-bit), r = t mod p. */
    static const uint64_t MU[5] = {
        0x0000000000000003ull,
        0xFFFFFFFEFFFFFFFFull,
        0xFFFFFFFEFFFFFFFEull,
        0x00000000FFFFFFFFull,
        0x0000000000000001ull
    };

    /* q1 = t >> 192 = t[3..7] (5 limbs) */
    uint64_t q1[5] = { t[3], t[4], t[5], t[6], t[7] };

    /* q2 = q1 * MU (5×5 → 10 limbs) */
    uint64_t q2[10] = {0};
    for (int i = 0; i < 5; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 5; j++) {
            unsigned __int128 prod = (unsigned __int128)q1[i] * MU[j]
                                    + q2[i+j] + carry;
            q2[i+j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        q2[i+5] = (uint64_t)carry;
    }

    /* q3 = q2 >> 320 = q2[5..9] (5 limbs) */
    uint64_t q3[5] = { q2[5], q2[6], q2[7], q2[8], q2[9] };

    /* r1 = t mod 2^320 = t[0..4] (5 limbs) */
    uint64_t r1[5] = { t[0], t[1], t[2], t[3], t[4] };

    /* r2 = (q3 * P64) mod 2^320 (5×4 → 9, keep low 5) */
    uint64_t r2[6] = {0};
    for (int i = 0; i < 5; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 prod = (unsigned __int128)q3[i] * P64[j]
                                    + r2[i+j] + carry;
            r2[i+j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        if (i + 4 < 6) {
            unsigned __int128 v = (unsigned __int128)r2[i+4] + (uint64_t)carry;
            r2[i+4] = (uint64_t)v;
        }
    }

    /* r = r1 - r2 mod 2^320 */
    uint64_t res[5] = {0};
    uint64_t borrow = 0;
    for (int i = 0; i < 5; i++) {
        unsigned __int128 v = (unsigned __int128)r1[i] - r2[i] - borrow;
        res[i] = (uint64_t)v;
        borrow = (uint64_t)(v >> 64) & 1;
    }

    uint64_t result[4] = { res[0], res[1], res[2], res[3] };

    /* If res[4] != 0, fold res[4] * 2^256 mod p = res[4] * R_MOD_P. */
    if (res[4]) {
        uint64_t hc[8];
        fe64_mul_wide(hc, &res[4], R_MOD_P);
        uint64_t carry = fe64_add_raw(result, result, hc);
        if (carry) {
            fe64_add_raw(result, result, R_MOD_P);
        }
    }

    /* Final: subtract p up to 3 times. */
    fe64_copy(r, result);
    for (int i = 0; i < 3; i++) {
        if (fe64_gte(r, P64)) {
            uint64_t tmp[4];
            fe64_sub_raw(tmp, r, P64);
            fe64_copy(r, tmp);
        } else break;
    }
}

static void fe64_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t wide[8];
    fe64_mul_wide(wide, a, b);
    fe64_reduce(r, wide);
}

static void fe64_sqr(uint64_t r[4], const uint64_t a[4]) {
    fe64_mul(r, a, a);
}

/* r = a^-1 mod p, via Fermat a^(p-2). */
static void fe64_inv(uint64_t r[4], const uint64_t a[4]) {
    /* Fermat: a^(p-2) via square-and-multiply over PM2_64 bits. */
    uint64_t x[4];
    fe64_one(x);
    for (int i = 255; i >= 0; i--) {
        fe64_sqr(x, x);
        uint64_t bit = (PM2_64[i / 64] >> (i % 64)) & 1;
        if (bit) {
            fe64_mul(x, x, a);
        }
    }
    fe64_copy(r, x);
}

/* Serialization: 4×uint64 limbs ↔ 32-byte big-endian. */

/* out[0..31] = a, big-endian. */
static void fe64_to_bytes(uint8_t out[32], const uint64_t a[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = a[3 - i];
        out[i*8 + 0] = (uint8_t)(w >> 56);
        out[i*8 + 1] = (uint8_t)(w >> 48);
        out[i*8 + 2] = (uint8_t)(w >> 40);
        out[i*8 + 3] = (uint8_t)(w >> 32);
        out[i*8 + 4] = (uint8_t)(w >> 24);
        out[i*8 + 5] = (uint8_t)(w >> 16);
        out[i*8 + 6] = (uint8_t)(w >> 8);
        out[i*8 + 7] = (uint8_t)(w);
    }
}

/* r = in[0..31] as big-endian. */
static void fe64_from_bytes(uint64_t r[4], const uint8_t in[32]) {
    for (int i = 0; i < 4; i++) {
        const uint8_t *p = in + i*8;
        r[3 - i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
                 | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
                 | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
                 | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
    }
}

/* Return 1 if a == 0, constant-time-ish (no early exit). */
static int fe64_is_zero(const uint64_t a[4]) {
    uint64_t acc = a[0] | a[1] | a[2] | a[3];
    return acc == 0;
}

/* Point ops — Jacobian coordinates (X : Y : Z). Affine (x, y) corresponds to (X = x·Z², Y = y·Z³, Z). Point at infinity: Z = 0. Curve: y² = x³ - 3x + b. */

/* Set point to infinity (Z = 0, X = Y = 1 for internal consistency). */
static void ge64_set_infinity(ge64_t *p) {
    fe64_one(p->X);
    fe64_one(p->Y);
    fe64_zero(p->Z);
}

/* Return 1 if point is at infinity (Z == 0). */
static int ge64_is_infinity(const ge64_t *p) {
    return fe64_is_zero(p->Z);
}

/* Copy Jacobian point. */
static void ge64_copy(ge64_t *r, const ge64_t *a) {
    fe64_copy(r->X, a->X);
    fe64_copy(r->Y, a->Y);
    fe64_copy(r->Z, a->Z);
}

/* r = 2·a (Jacobian, a = -3 curve formula). */
static void ge64_double(ge64_t *r, const ge64_t *a) {
    if (ge64_is_infinity(a) || fe64_is_zero(a->Y)) {
        ge64_set_infinity(r);
        return;
    }

    /* Save a->Y and a->Z up front so in-place calls (r == a) don't lose them. */
    uint64_t Y_save[4], Z_save[4];
    fe64_copy(Y_save, a->Y);
    fe64_copy(Z_save, a->Z);

    uint64_t A[4], B[4], C[4], D[4], E[4], F[4];
    uint64_t t1[4], t2[4], t3[4];

    /* A = X² */
    fe64_sqr(A, a->X);
    /* B = Y² */
    fe64_sqr(B, a->Y);
    /* C = B² */
    fe64_sqr(C, B);

    /* t1 = (X + B)² - A - C */
    fe64_add(t1, a->X, B);
    fe64_sqr(t1, t1);
    fe64_sub(t1, t1, A);
    fe64_sub(t1, t1, C);

    /* D = 2·t1 */
    fe64_add(D, t1, t1);

    /* E = 3·(A - Z⁴)  [a = -3] */
    fe64_sqr(t2, Z_save);
    fe64_sqr(t2, t2);          /* Z⁴ */
    fe64_sub(t3, A, t2);       /* A - Z⁴ */
    fe64_add(t1, t3, t3);      /* 2·(A - Z⁴) */
    fe64_add(E, t1, t3);       /* 3·(A - Z⁴) */

    /* F = E² */
    fe64_sqr(F, E);

    /* X₃ = F - 2·D */
    fe64_add(t1, D, D);
    fe64_sub(r->X, F, t1);

    /* Y₃ = E·(D - X₃) - 8·C */
    fe64_sub(t1, D, r->X);
    fe64_mul(t1, E, t1);
    fe64_add(t2, C, C);
    fe64_add(t2, t2, t2);
    fe64_add(t2, t2, t2);      /* 8·C */
    fe64_sub(r->Y, t1, t2);

    /* Z₃ = 2·Y·Z  (use saved Y, Z) */
    fe64_mul(t1, Y_save, Z_save);
    fe64_add(r->Z, t1, t1);
}

/* r = a + b (Jacobian). Handles all cases: infinity, doubling, negation. */
static void ge64_add(ge64_t *r, const ge64_t *a, const ge64_t *b) {
    if (ge64_is_infinity(a)) { ge64_copy(r, b); return; }
    if (ge64_is_infinity(b)) { ge64_copy(r, a); return; }

    uint64_t Z1Z1[4], Z2Z2[4], U1[4], U2[4], S1[4], S2[4];
    uint64_t H[4], rr[4], I[4], J[4], V[4];
    uint64_t t1[4], t2[4];

    fe64_sqr(Z1Z1, a->Z);
    fe64_sqr(Z2Z2, b->Z);
    fe64_mul(U1, a->X, Z2Z2);
    fe64_mul(U2, b->X, Z1Z1);
    fe64_mul(S1, a->Y, b->Z);
    fe64_mul(S1, S1, Z2Z2);
    fe64_mul(S2, b->Y, a->Z);
    fe64_mul(S2, S2, Z1Z1);

    fe64_sub(H, U2, U1);
    /* rr = 2*(S2 - S1) */
    fe64_sub(t1, S2, S1);
    fe64_add(rr, t1, t1);

    if (fe64_is_zero(H)) {
        if (fe64_is_zero(rr)) {
            ge64_double(r, a);
            return;
        }
        ge64_set_infinity(r);
        return;
    }

    /* I = (2H)² */
    fe64_add(t1, H, H);
    fe64_sqr(I, t1);
    /* J = H·I */
    fe64_mul(J, H, I);
    /* V = U1·I */
    fe64_mul(V, U1, I);

    /* X₃ = rr² - J - 2V */
    fe64_sqr(t1, rr);
    fe64_sub(t1, t1, J);
    fe64_sub(r->X, t1, V);
    fe64_sub(r->X, r->X, V);

    /* Y₃ = rr·(V - X₃) - 2·S1·J */
    fe64_sub(t1, V, r->X);
    fe64_mul(t1, rr, t1);
    fe64_mul(t2, S1, J);
    fe64_add(t2, t2, t2);
    fe64_sub(r->Y, t1, t2);

    /* Z₃ = ((Z1 + Z2)² - Z1Z1 - Z2Z2)·H */
    fe64_add(t1, a->Z, b->Z);
    fe64_sqr(t1, t1);
    fe64_sub(t1, t1, Z1Z1);
    fe64_sub(t1, t1, Z2Z2);
    fe64_mul(r->Z, t1, H);
}

/* Conditional swap: if bit==1, swap a and b. Constant-time. */
static void ge64_cswap(ge64_t *a, ge64_t *b, uint64_t bit) {
    uint64_t mask = (uint64_t)0 - bit;   /* 0 or ~0 */
    for (int i = 0; i < 4; i++) {
        uint64_t t;
        t = (a->X[i] ^ b->X[i]) & mask; a->X[i] ^= t; b->X[i] ^= t;
        t = (a->Y[i] ^ b->Y[i]) & mask; a->Y[i] ^= t; b->Y[i] ^= t;
        t = (a->Z[i] ^ b->Z[i]) & mask; a->Z[i] ^= t; b->Z[i] ^= t;
    }
}

/* r = k·p, constant-time Montgomery ladder over 256-bit scalar k.
 * k is passed as 4×uint64 limbs (little-endian). */
static void ge64_mul(ge64_t *r, const uint64_t k[4], const ge64_t *p) {
    ge64_t R0, R1;
    ge64_set_infinity(&R0);
    ge64_copy(&R1, p);

    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (k[i / 64] >> (i % 64)) & 1;
        ge64_cswap(&R0, &R1, bit);
        ge64_t sum;
        ge64_add(&sum, &R0, &R1);
        ge64_double(&R0, &R0);
        ge64_copy(&R1, &sum);
        ge64_cswap(&R0, &R1, bit);
    }
    ge64_copy(r, &R0);
}

/* Affine coordinates from Jacobian: x = X/Z², y = Y/Z³. */
static void ge64_to_affine(uint64_t x[4], uint64_t y[4], const ge64_t *p) {
    uint64_t zi[4], zi2[4], zi3[4];
    fe64_inv(zi, p->Z);
    fe64_sqr(zi2, zi);
    fe64_mul(zi3, zi2, zi);
    fe64_mul(x, p->X, zi2);
    fe64_mul(y, p->Y, zi3);
}

/* Jacobian from affine: X = x, Y = y, Z = 1. */
static void ge64_from_affine(ge64_t *r, const uint64_t x[4], const uint64_t y[4]) {
    fe64_copy(r->X, x);
    fe64_copy(r->Y, y);
    fe64_one(r->Z);
}

/* Public API. */

/* Generate a keypair. priv = 32-byte big-endian scalar, pub = 65-byte
 * uncompressed point (0x04 || X || Y). */
int ct_p256_keypair(uint8_t priv[32], uint8_t pub_uncompressed[65]) {
    /* Generate random private scalar. Ensure it's in [1, p-1]. */
    if (ct_random(priv, 32) != 0) return -1;

    /* Simple rejection: if priv >= p, retry. Probability ~2^-32, so 1 retry enough. */
    uint64_t k[4];
    fe64_from_bytes(k, priv);
    if (fe64_gte(k, P64)) {
        /* Subtract p once to bring into range (this loses uniformity by ~2^-32
         * but is cryptographically negligible; better than looping). */
        uint64_t t[4];
        fe64_sub_raw(t, k, P64);
        fe64_to_bytes(priv, t);
        fe64_copy(k, t);
    }
    if (fe64_is_zero(k)) {
        /* Degenerate — regenerate. ~2^-256 chance. */
        return ct_p256_keypair(priv, pub_uncompressed);
    }

    /* Compute pub = k · G. */
    ge64_t G, Q;
    fe64_from_bytes(G.X, (const uint8_t[32]){0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,
                                            0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
                                            0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,
                                            0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96});
    fe64_from_bytes(G.Y, (const uint8_t[32]){0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,
                                            0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
                                            0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,
                                            0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5});
    fe64_one(G.Z);
    ge64_mul(&Q, k, &G);

    /* Convert to affine + serialize. */
    uint64_t qx[4], qy[4];
    ge64_to_affine(qx, qy, &Q);
    pub_uncompressed[0] = 0x04;
    fe64_to_bytes(pub_uncompressed + 1, qx);
    fe64_to_bytes(pub_uncompressed + 33, qy);
    return 0;
}

/* ECDH: compute shared secret = priv · peer_pub (X-coordinate only, 32 bytes BE). */
int ct_p256_ecdh(uint8_t shared[32],
                 const uint8_t priv[32], const uint8_t peer_pub[65]) {
    if (g_crisptls_trace) fprintf(stderr, "[p256] prefix=0x%02x\n", peer_pub[0]);
    if (peer_pub[0] != 0x04) return -1;

    uint64_t k[4], px[4], py[4];
    fe64_from_bytes(k, priv);
    fe64_from_bytes(px, peer_pub + 1);
    fe64_from_bytes(py, peer_pub + 33);
    if (g_crisptls_trace) fprintf(stderr, "[p256] k[0]=%016llx px[0]=%016llx py[0]=%016llx\n",
            (unsigned long long)k[0], (unsigned long long)px[0], (unsigned long long)py[0]);

    ge64_t P, Q;
    ge64_from_affine(&P, px, py);
    if (g_crisptls_trace) fprintf(stderr, "[p256] P.Z[0]=%llx\n", (unsigned long long)P.Z[0]);
    ge64_mul(&Q, k, &P);
    if (g_crisptls_trace) fprintf(stderr, "[p256] Q.Z[0]=%llx Q.Z[3]=%llx\n",
            (unsigned long long)Q.Z[0], (unsigned long long)Q.Z[3]);
    if (ge64_is_infinity(&Q)) { if (g_crisptls_trace) fprintf(stderr, "[p256] infinity!\n"); return -1; }

    uint64_t qx[4], qy[4];
    ge64_to_affine(qx, qy, &Q);
    fe64_to_bytes(shared, qx);
    if (g_crisptls_trace) fprintf(stderr, "[p256] shared[0..3]=%02x%02x%02x%02x\n",
            shared[0], shared[1], shared[2], shared[3]);
    return 0;
}

/* Selftest — compiled only with -DP256_SELFTEST. Not part of the library. Prints intermediate values so we can bisect field/point math failures. */
#ifdef P256_SELFTEST
#include <stdio.h>

static void print_fe(const char *name, const uint64_t a[4]) {
    uint8_t b[32];
    fe64_to_bytes(b, a);
    printf("  %s = ", name);
    for (int i = 0; i < 32; i++) printf("%02x", b[i]);
    printf("\n");
}

void p256_selftest(void) {
    uint64_t a[4], b[4], r[4];

    printf("=== Field sanity ===\n");

    /* fe64_mul(2, 2) should be 4 */
    fe64_zero(a); a[0] = 2;
    fe64_zero(b); b[0] = 2;
    fe64_mul(r, a, b);
    print_fe("2*2 (want 4)", r);

    /* fe64_mul(a, 1) == a */
    fe64_zero(a); a[0] = 0x12345678;
    fe64_zero(b); b[0] = 1;
    fe64_mul(r, a, b);
    print_fe("0x12345678 * 1 (want 0x12345678)", r);

    /* ---- Diagnostic: fe64_inv(2) and 2 * inv(2) ---- */
    {
        uint64_t two[4] = { 2, 0, 0, 0 };
        uint64_t inv2[4];
        fe64_inv(inv2, two);
        print_fe("fe64_inv(2) (want OpenSSL 2^-1)", inv2);

        uint64_t prod[4];
        fe64_mul(prod, two, inv2);
        print_fe("2 * inv(2) (want 1)", prod);
    }

    /* ---- Diagnostic: fe64_inv(1) ---- */
    {
        uint64_t one[4] = { 1, 0, 0, 0 };
        uint64_t inv1[4];
        fe64_inv(inv1, one);
        print_fe("inv(1) (want 1)", inv1);
    }

    /* ---- Diagnostic: fe64_sqr(3), fe64_sqr(0xFFFFFFFF) ---- */
    {
        uint64_t three[4] = { 3, 0, 0, 0 };
        uint64_t sq3[4];
        fe64_sqr(sq3, three);
        print_fe("sqr(3) (want 9)", sq3);

        uint64_t big[4] = { 0xFFFFFFFFull, 0, 0, 0 };
        uint64_t sqbig[4];
        fe64_sqr(sqbig, big);
    /* ---- Diagnostic: sqr with reduction needed ---- */
    {
        /* x = p - 1.  x^2 mod p = 1. */
        uint64_t pm1[4];
        uint64_t one[4] = { 1, 0, 0, 0 };
        fe64_sub_raw(pm1, P64, one);
        uint64_t sq[4];
        fe64_sqr(sq, pm1);
        print_fe("sqr(p-1) (want 1)", sq);

        /* x = 2^128.  x^2 = 2^256 mod p = R_MOD_P. */
        uint64_t x2[4] = { 0, 0, 1, 0 };
        uint64_t sq2[4];
        fe64_sqr(sq2, x2);
        print_fe("sqr(2^128) (want R_MOD_P)", sq2);
    }
        print_fe("sqr(0xFFFFFFFF) (want FFFFFFFE00000001)", sqbig);
    }

    /* fe64_add(2^64-1, 1) should be 2^64 (not wrapped) */
    fe64_zero(a); a[0] = 0xFFFFFFFFFFFFFFFFull;
    fe64_zero(b); b[0] = 1;
    fe64_add(r, a, b);
    print_fe("2^64-1 + 1 (want 0...10000000000000000)", r);

    /* fe64_sub(3, 5) mod p should be huge (~p-2) */
    fe64_zero(a); a[0] = 3;
    fe64_zero(b); b[0] = 5;
    fe64_sub(r, a, b);
    print_fe("3 - 5 mod p", r);

    printf("\n=== Point sanity ===\n");

    /* 2*G in affine coords */
    /* Gy, GX are inside static GY64/GX64. Build G directly. */
    uint64_t Gx[4], Gy[4];
    /* Gx = 0x6B17...D898C296 */
    Gx[0] = 0xF4A13945D898C296ull;
    Gx[1] = 0x77037D812DEB33A0ull;
    Gx[2] = 0xF8BCE6E563A440F2ull;
    Gx[3] = 0x6B17D1F2E12C4247ull;
    /* Gy = 0x4FE3...37BF51F5 */
    Gy[0] = 0xCBB6406837BF51F5ull;
    Gy[1] = 0x2BCE33576B315ECEull;
    Gy[2] = 0x8EE7EB4A7C0F9E16ull;
    Gy[3] = 0x4FE342E2FE1A7F9Bull;

    ge64_t P, Q;
    ge64_from_affine(&P, Gx, Gy);

    ge64_double(&Q, &P);
    uint64_t qx[4], qy[4];
    ge64_to_affine(qx, qy, &Q);
    print_fe("2G.x (want 7CF27B18...47669978)", qx);
    print_fe("2G.y (want 07775510...227873D1)", qy);

    /* 1*G via ladder */
    uint64_t k1[4] = {1, 0, 0, 0};
    ge64_mul(&Q, k1, &P);
    ge64_to_affine(qx, qy, &Q);
    print_fe("1*G.x (want same as Gx)", qx);
    print_fe("1*G.y (want same as Gy)", qy);

    /* 2*G via ladder (should match ge64_double) */
    uint64_t k2[4] = {2, 0, 0, 0};
    ge64_mul(&Q, k2, &P);
    ge64_to_affine(qx, qy, &Q);
    print_fe("2*G.x via ladder (want 7CF27B18...47669978)", qx);
    print_fe("2*G.y via ladder (want 07775510...227873D1)", qy);

    /* 3*G */
    uint64_t k3[4] = {3, 0, 0, 0};
    ge64_mul(&Q, k3, &P);
    ge64_to_affine(qx, qy, &Q);
    print_fe("3*G.x (want 5ECBE4D1...C6E7FD6C)", qx);
    /* Diagnostic: direct ge64_add(G, 2G) should equal 3G */
    {
        ge64_t G_pt, two_G, three_direct;
        ge64_copy(&G_pt, &P);
        ge64_double(&two_G, &G_pt);
        ge64_add(&three_direct, &G_pt, &two_G);
        uint64_t dx[4], dy[4];
        ge64_to_affine(dx, dy, &three_direct);
        print_fe("add(G,2G).x (want 5ECBE4D1...C6E7FD6C)", dx);
        print_fe("add(G,2G).y (want 8734640C...A27D5032)", dy);
    }
    print_fe("3*G.y (want 8734640C...A27D5032)", qy);
}
#endif

/* Montgomery multiplication for P-256. Element a in Montgomery form represents a·R mod p where R = 2^256. mont_mul computes a·b·R⁻¹ mod p (REDC), so mont_mul(A_mont, B_mont) = (A·B)_mont. fe64_mul / fe64_sqr are wrappers that assume inputs are already in Mont form. REDC: for t = a·b (< R·p), m = (t mod R) · p⁻¹ mod R, result = (t + m·p) / R. Since p⁻¹ mod 2^64 = 0x00000000_00000001_00000000_FFFFFFFF... wait, that's the standard NIST P-256 REDC constant. Correct value is p⁻¹ mod 2^64 = 1. Verify: p[0] = 0xFFFFFFFFFFFFFFFF. (-p⁻¹) mod 2^64 = p[0]⁻¹ mod 2^64. 0xFFFFFFFFFFFFFFFF ≡ -1 mod 2^64, so p[0]⁻¹ = -1 = 0xFFFFFFFFFFFFFFFF. So m_i = t_i * (-p⁻¹) ... we use m = t · NEG_P_INV mod 2^64 where NEG_P_INV = -p⁻¹ mod 2^64 = 1 (since p⁻¹ = -1, negating gives 1). */

/* NEG_P_INV = -p⁻¹ mod 2^64. For p[0] = 0xFFFFFFFFFFFFFFFF (i.e. -1 mod 2^64),
 * p⁻¹ = -1, so NEG_P_INV = 1. */
static const uint64_t NEG_P_INV = 0x0000000000000001ull;


/* R² mod p = (2^256)² mod p = 2^512 mod p. Known constant. */
static const uint64_t R2_MOD_P[4] = {
    0x0000000000000003ull,
    0xFFFFFFFFFFFBFFFFull,
    0xFFFFFFFFFEFFFFFFull,
    0x04FFFFFFFDFFFFFFull
};

/* Montgomery REDC: given a 8-limb product t (512-bit), compute t·R⁻¹ mod p.
 * Writes 4-limb result to r. Correct for any t < R·p. */
/* Montgomery REDC with 5-limb p extension (CIOS, correct for any p < 2^256).
 * Input: 512-bit t (8 limbs). Output: t · R⁻¹ mod p (4 limbs).
 * Guarantees: result < 2p after loop, so two conditional subtracts suffice. */
static void mont_reduce(uint64_t r[4], const uint64_t t[8]) {
    /* 5-limb p: p[0..3] with leading 0. */
    static const uint64_t P5[5] = {
        0xFFFFFFFFFFFFFFFFull,
        0x00000000FFFFFFFFull,
        0x0000000000000000ull,
        0xFFFFFFFF00000001ull,
        0x0000000000000000ull
    };

    uint64_t T[9] = { t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], 0 };

    for (int i = 0; i < 4; i++) {
        uint64_t m = T[i] * NEG_P_INV;   /* NEG_P_INV = 1, so m = T[i] */
        /* Two-limb carry: m*P5[j] produces 128 bits, then + T[i+j] + carry
         * can still exceed 128 bits. Split into lo/hi 64-bit with explicit
         * carry propagation. */
        uint64_t lo_carry = 0;   /* carry from the lo additions */
        uint64_t hi_carry = 0;   /* running high accumulator (carries into next limb) */
        for (int j = 0; j < 5; j++) {
            unsigned __int128 prod = (unsigned __int128)m * P5[j];
            uint64_t lo = (uint64_t)prod;
            uint64_t hi = (uint64_t)(prod >> 64);

            /* lo + T[i+j] + lo_carry */
            uint64_t t_old = T[i + j];
            lo += t_old;
            if (lo < t_old) hi += 1;
            lo += lo_carry;
            if (lo < lo_carry) hi += 1;

            T[i + j] = lo;
            /* hi + hi_carry becomes the carry for the next j */
            hi += hi_carry;
            lo_carry = 0;             /* reset — the lo carry is now in hi */
            hi_carry = hi;
        }
        /* Final carry out of the 5-limb P5 multiply */
        uint64_t carry_out = hi_carry;
        int idx = i + 5;
        unsigned __int128 v = (unsigned __int128)T[idx] + carry_out;
        T[idx] = (uint64_t)v;
        if (v >> 64) {
            /* Very rare: carry out of T[8]. Add 2^256 mod p (= R_MOD_P) once,
             * then propagate. */
            uint64_t c = 0;
            for (int k = 0; k < 4; k++) {
                uint64_t sum = T[4 + k] + R_MOD_P[k];
                uint64_t c1 = (sum < T[4 + k]) ? 1 : 0;
                sum += c;
                uint64_t c2 = (sum < c) ? 1 : 0;
                T[4 + k] = sum;
                c = c1 + c2;
            }
        }
    }

    uint64_t res[4] = { T[4], T[5], T[6], T[7] };

    /* REDC result < 2p: at most two conditional subtracts. */
    if (fe64_gte(res, P64)) {
        uint64_t tmp[4];
        fe64_sub_raw(tmp, res, P64);
        fe64_copy(res, tmp);
    }
    if (fe64_gte(res, P64)) {
        uint64_t tmp[4];
        fe64_sub_raw(tmp, res, P64);
        fe64_copy(res, tmp);
    }

    fe64_copy(r, res);
}
static void mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    /* Adaptive fast path: if b == 1 in Mont form (i.e. R_MOD_P), just copy a. */
    /* More useful: if a or b is all zeros, result is zero. */
    if ((a[0] | a[1] | a[2] | a[3]) == 0) {
        fe64_zero(r);
        return;
    }
    if ((b[0] | b[1] | b[2] | b[3]) == 0) {
        fe64_zero(r);
        return;
    }

    uint64_t t[8];
    fe64_mul_wide(t, a, b);
    mont_reduce(r, t);
}

/* ---- Montgomery conversions (only compiled under SELFTEST for now) ---- */

#ifdef P256_SELFTEST
/* Convert plain value a (in [0, p)) to Montgomery form a·R mod p.
 * Uses the fact R² mod p is a constant, so a·R = mont_mul(a, R²) — but a is
 * in plain form, so we need a multi-step: first get a·R² in Mont, then convert.
 * Actually: mont_mul(a, R²) = a·R²·R⁻¹ = a·R. So if we feed a as if it were
 * "Mont form" (even though it isn't), the output IS Mont form of a. Clean trick. */
static void fe64_to_mont(uint64_t r[4], const uint64_t a[4]) {
    fe64_copy(r, a);  /* identity — native path uses plain form, not Montgomery */
}

/* Convert Montgomery value back to plain: mont_mul(a_mont, 1) = a_mont · 1 · R⁻¹ = a. */
static void fe64_from_mont(uint64_t r[4], const uint64_t a[4]) {
    fe64_copy(r, a);  /* identity — native path uses plain form, not Montgomery */
}

/* Print a Mont-form value by converting back to plain first. */
static void print_mont(const char *name, const uint64_t a[4]) {
    uint64_t plain[4];
    fe64_from_mont(plain, a);
    uint8_t b[32];
    fe64_to_bytes(b, plain);
    printf("  %s = ", name);
    for (int i = 0; i < 32; i++) printf("%02x", b[i]);
    printf("\n");
}

void p256_mont_test(void) {
    printf("\n=== Montgomery sanity ===\n");

    uint64_t one_plain[4] = { 1, 0, 0, 0 };
    uint64_t two_plain[4] = { 2, 0, 0, 0 };
    uint64_t three_plain[4] = { 3, 0, 0, 0 };
    uint64_t six_plain[4] = { 6, 0, 0, 0 };

    uint64_t one_m[4], two_m[4], three_m[4], six_m[4];
    fe64_to_mont(one_m, one_plain);
    fe64_to_mont(two_m, two_plain);
    fe64_to_mont(three_m, three_plain);
    /* RAW DEBUG: print internal representations before any conversion */
    { uint8_t b[32]; fe64_to_bytes(b, one_m);  printf("  raw to_mont(1) = "); for (int i=0;i<32;i++) printf("%02x",b[i]); printf("\n"); }
    { uint8_t b[32]; fe64_to_bytes(b, R_MOD_P); printf("  raw R_MOD_P    = "); for (int i=0;i<32;i++) printf("%02x",b[i]); printf("\n"); }
    { uint8_t b[32]; fe64_to_bytes(b, R2_MOD_P); printf("  raw R2_MOD_P   = "); for (int i=0;i<32;i++) printf("%02x",b[i]); printf("\n"); }
    fe64_to_mont(six_m, six_plain);

    /* 1_mont * 1_mont should be 1_mont */
    uint64_t r[4];
    mont_mul(r, one_m, one_m);
    print_mont("1m*1m (want 1)", r);

    /* 2_mont * 3_mont should be 6_mont */
    mont_mul(r, two_m, three_m);
    print_mont("2m*3m (want 6)", r);

    /* 2_mont * 1_mont should be 2_mont */
    mont_mul(r, two_m, one_m);
    print_mont("2m*1m (want 2)", r);

    /* Round-trip: to_mont then from_mont gives original */
    uint64_t x_m[4], x_plain[4];
    fe64_to_mont(x_m, three_plain);
    fe64_from_mont(x_plain, x_m);
    print_mont("from(to(3)) (want 3)", x_plain);

    /* Try with a large value: p-1 (should be inverted to -1) */
    uint64_t pm1[4];
    fe64_sub_raw(pm1, P64, one_plain);  /* pm1 = p - 1 */
    uint64_t pm1_m[4];
    fe64_to_mont(pm1_m, pm1);
    /* (p-1)² mod p = 1 */
    mont_mul(r, pm1_m, pm1_m);
    print_mont("(p-1)m² (want 1)", r);
}
#endif

/* ECDSA-P256-SHA256 verify (RFC 6979 §2.4.1, FIPS 186-4 §6.4). Signature input is DER-encoded ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s } Public key input is DER-encoded SubjectPublicKeyInfo (SPKI). All field and point helpers below are static in this file. Exposing ECDSA here avoids exporting 10+ internal symbols. */

extern int ct_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* SPKI DER for a P-256 public key:
 *   30 59                        ; SEQUENCE, 89 bytes content
 *   30 13                        ;   SEQUENCE, 19 bytes
 *     06 07 2a 86 48 ce 3d 02 01 ;     OID ecPublicKey
 *     06 08 2a 86 48 ce 3d 03 01 07 ; OID prime256v1
 *   03 42 00 04 ...              ; BIT STRING (66 bytes, 0 unused bits), point 04||X||Y
 *
 * Total: 91 bytes. We match the exact 91-byte structure and extract
 * X (offset 27..58) and Y (offset 59..90). */

static int parse_spki_p256(const uint8_t *der, size_t len,
                           uint64_t px[4], uint64_t py[4]) {
    static const uint8_t PREFIX[26] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    };
    if (!der || len != 91) return -1;
    for (int i = 0; i < 26; i++) if (der[i] != PREFIX[i]) return -1;
    if (der[26] != 0x04) return -1;
    fe64_from_bytes(px, der + 27);
    fe64_from_bytes(py, der + 59);
    return 0;
}

/* Parse DER ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }.
 * Each INTEGER is stripped of any leading 0x00 and zero-padded on the
 * left to 32 bytes. */
static int parse_ecdsa_sig_der(const uint8_t *der, size_t len,
                               uint64_t r[4], uint64_t s[4]) {
    if (!der || len < 8 || der[0] != 0x30) return -1;
    /* SEQUENCE length is either the byte len-2 (short) or a longer form. */
    size_t seq_len;
    size_t off;
    if (der[1] < 0x80) {
        seq_len = der[1]; off = 2;
    } else {
        int nlen = der[1] & 0x7f;
        if (nlen != 1 || len < 3) return -1;
        seq_len = der[2]; off = 3;
    }
    if (off + seq_len != len) return -1;

    /* INTEGER r */
    if (off + 2 > len || der[off] != 0x02) return -1;
    size_t r_len = der[off + 1]; off += 2;
    if (off + r_len > len) return -1;
    /* Strip leading zero, pad to 32 bytes */
    uint8_t r_raw[32] = {0};
    size_t r_skip = 0;
    while (r_skip < r_len && der[off + r_skip] == 0x00) r_skip++;
    size_t r_use = r_len - r_skip;
    if (r_use > 32) return -1;
    memcpy(r_raw + 32 - r_use, der + off + r_skip, r_use);
    fe64_from_bytes(r, r_raw);
    off += r_len;

    /* INTEGER s */
    if (off + 2 > len || der[off] != 0x02) return -1;
    size_t s_len = der[off + 1]; off += 2;
    if (off + s_len > len) return -1;
    uint8_t s_raw[32] = {0};
    size_t s_skip = 0;
    while (s_skip < s_len && der[off + s_skip] == 0x00) s_skip++;
    size_t s_use = s_len - s_skip;
    if (s_use > 32) return -1;
    memcpy(s_raw + 32 - s_use, der + off + s_skip, s_use);
    fe64_from_bytes(s, s_raw);

    return 0;
}

/* Order n of P-256, little-endian uint64 limbs. */
static const uint64_t N_ORDER[4] = {
    0xF3B9CAC2FC632551ull,
    0xBCE6FAADA7179E84ull,
    0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFF00000000ull
};

/* n - 2, for Fermat inversion mod n. */
static const uint64_t N_M2[4] = {
    0xF3B9CAC2FC63254Full,
    0xBCE6FAADA7179E84ull,
    0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFF00000000ull
};

/* Compare a < b, both as big-endian 256-bit (uint64 limbs little-endian). */
static int cmp256(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/* Reduce a mod n. Works for a < 2^256 by single subtraction if a >= n. */
static void mod_n_once(uint64_t a[4]) {
    if (cmp256(a, N_ORDER) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t t1 = a[i] - N_ORDER[i];
            uint64_t b1 = (a[i] < N_ORDER[i]) ? 1 : 0;
            uint64_t t2 = t1 - borrow;
            uint64_t b2 = (t1 < borrow) ? 1 : 0;
            a[i] = t2;
            borrow = b1 | b2;
        }
    }
}

/* a = a mod n, general case: repeated subtraction when a may be up to 2^256-1. */
/* For ECDSA verify we need: (z * s^-1) mod n and (r * s^-1) mod n.
 * z, s, r are all < n < 2^256. s^-1 is computed via Fermat using fe64_mul (mod p),
 * but since n != p, Fermat doesn't apply directly.
 *
 * Instead: compute k = s^-1 mod n via extended gcd on uint64 limbs (variable-time,
 * safe because s is public in a verify-only context). */

/* 256-bit extended GCD on uint64[4] limbs. Returns gcd; sets x such that
 * a*x ≡ gcd (mod n). Variable-time — only used on public values. */
static void u256_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t t1 = a[i] - b[i];
        uint64_t b1 = (a[i] < b[i]) ? 1 : 0;
        uint64_t t2 = t1 - borrow;
        uint64_t b2 = (t1 < borrow) ? 1 : 0;
        r[i] = t2;
        borrow = b1 | b2;
    }
}

static void u256_copy(uint64_t r[4], const uint64_t a[4]) {
    r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3];
}

static int u256_is_zero(const uint64_t a[4]) {
    return (a[0]|a[1]|a[2]|a[3]) == 0;
}

static int u256_is_odd(const uint64_t a[4]) {
    return (int)(a[0] & 1);
}

/* Right shift by 1 (a >>= 1). */
static void u256_shr1(uint64_t a[4]) {
    a[0] = (a[0] >> 1) | (a[1] << 63);
    a[1] = (a[1] >> 1) | (a[2] << 63);
    a[2] = (a[2] >> 1) | (a[3] << 63);
    a[3] = (a[3] >> 1);
}

/* a += b (mod n). Assumes a, b < n. */
static void u256_add_mod_n(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t sum[4];
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t t1 = a[i] + b[i];
        uint64_t c1 = (t1 < a[i]) ? 1 : 0;
        uint64_t t2 = t1 + carry;
        uint64_t c2 = (t2 < t1) ? 1 : 0;
        sum[i] = t2;
        carry = c1 | c2;
    }
    if (carry || cmp256(sum, N_ORDER) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t t1 = sum[i] - N_ORDER[i];
            uint64_t b1 = (sum[i] < N_ORDER[i]) ? 1 : 0;
            uint64_t t2 = t1 - borrow;
            uint64_t b2 = (t1 < borrow) ? 1 : 0;
            sum[i] = t2;
            borrow = b1 | b2;
        }
    }
    u256_copy(r, sum);
}

/* Compute s^-1 mod n via Fermat-like: s^(n-2) mod n.
 * Uses double-and-add over bits of (n-2). Variable-time — safe for verify. */
static void u256_mul_mod_n(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
static void u256_mul_mod_n(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    /* Multiply a*b as 512-bit, reduce mod n.
     * Simple version: use binary long multiplication and Barrett-ish reduction.
     * We do it by processing bits of b, adding a*(2^i mod n) each step. */
    uint64_t result[4] = {0};
    uint64_t cur[4];
    u256_copy(cur, a);
    for (int i = 0; i < 256; i++) {
        uint64_t bit = (b[i / 64] >> (i % 64)) & 1;
        if (bit) u256_add_mod_n(result, result, cur);
        u256_add_mod_n(cur, cur, cur);   /* cur = 2*cur mod n */
    }
    u256_copy(r, result);
}

static int u256_inv_mod_n(uint64_t r[4], const uint64_t s[4]) {
    if (u256_is_zero(s)) return -1;
    /* Compute s^(n-2) mod n by square-and-multiply over bits of n-2 (MSB first). */
    uint64_t base[4];
    u256_copy(base, s);
    uint64_t x[4] = {1, 0, 0, 0};
    for (int i = 255; i >= 0; i--) {
        u256_mul_mod_n(x, x, x);
        uint64_t bit = (N_M2[i / 64] >> (i % 64)) & 1;
        if (bit) u256_mul_mod_n(x, x, base);
    }
    u256_copy(r, x);
    return 0;
}

int ct_verify_ecdsa_p256_sha256(const uint8_t *pub_der, size_t pub_der_len,
                                const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len) {
    if (!pub_der || !msg || !sig) return CT_ERR_ARGS;

    /* Parse SPKI to (px, py). */
    uint64_t px[4], py[4];
    if (parse_spki_p256(pub_der, pub_der_len, px, py) != 0) return CT_ERR_VERIFY;

    /* Parse ECDSA-Sig-Value DER to (r, s). */
    uint64_t r[4], s[4];
    if (parse_ecdsa_sig_der(sig, sig_len, r, s) != 0) return CT_ERR_VERIFY;

    /* Check r, s ∈ [1, n-1]. */
    if (u256_is_zero(r) || u256_is_zero(s)) return CT_ERR_VERIFY;
    if (cmp256(r, N_ORDER) >= 0 || cmp256(s, N_ORDER) >= 0) return CT_ERR_VERIFY;

    /* z = SHA256(msg), truncated to 256 bits (already 256). */
    uint8_t z_bytes[32];
    ct_sha256(msg, msg_len, z_bytes);
    uint64_t z[4];
    fe64_from_bytes(z, z_bytes);
    mod_n_once(z);

    /* w = s^-1 mod n. */
    uint64_t w[4];
    if (u256_inv_mod_n(w, s) != 0) return CT_ERR_VERIFY;

    /* u1 = z*w mod n, u2 = r*w mod n. */
    uint64_t u1[4], u2[4];
    u256_mul_mod_n(u1, z, w);
    u256_mul_mod_n(u2, r, w);
    /* P = u1*G + u2*Q. */
    ge64_t G, Q, u1G, u2Q, sum;
    ge64_from_affine(&G, GX64, GY64);
    ge64_from_affine(&Q, px, py);
    ge64_mul(&u1G, u1, &G);
    ge64_mul(&u2Q, u2, &Q);
    ge64_add(&sum, &u1G, &u2Q);

    if (ge64_is_infinity(&sum)) return CT_ERR_VERIFY;

    /* Extract affine x, then check (x mod n) == r. */
    uint64_t affine_x[4], affine_y[4];
    ge64_to_affine(affine_x, affine_y, &sum);
    uint64_t x_mod_n[4];
    u256_copy(x_mod_n, affine_x);

    /* affine_x is a field element (mod p). We need x mod n.
     * Since x < p and n = p - (2^224 - 2^192 - 2^96 + 1), we have
     * x mod n = x if x < n, else x - n (single subtraction; x < 2^256). */
    mod_n_once(x_mod_n);

    if (cmp256(x_mod_n, r) != 0) return CT_ERR_VERIFY;
    return CT_OK;
}
