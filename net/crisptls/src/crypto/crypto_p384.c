/** crypto_p384.c — native P-384 ECDSA-SHA384 verification.
 *
 * Reference: NIST FIPS 186-4 §D.1.2.5 (secp384r1).
 * Barrett reduction algorithm: adapted from Cinnabar (Pascal Levy, MIT).
 *
 * Field arithmetic: 6 × 64-bit limbs, Barrett reduction per multiply.
 * Signature: DER SEQUENCE { INTEGER r, INTEGER s }, verified per RFC 6090.
 *
 * Zero OpenSSL. All constants from FIPS 186-4 / SEC2 §2.4.1.
 */

#include "crypto.h"
#include "asn1.h"
#include <stdint.h>
#include <string.h>

/* ============================================================
 * P-384 constants
 * ============================================================ */

static const uint64_t P384_P[6] = {
    0x00000000FFFFFFFFull, 0xFFFFFFFF00000000ull,
    0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull
};

static const uint64_t P384_N[6] = {
    0xECEC196ACCC52973ull, 0x581A0DB248B0A77Aull,
    0xC7634D81F4372DDFull, 0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull
};

/* n - 2 (for Fermat inversion mod n) */
static const uint64_t P384_NM2[6] = {
    0xECEC196ACCC52971ull, 0x581A0DB248B0A77Aull,
    0xC7634D81F4372DDFull, 0xFFFFFFFFFFFFFFFFull,
    0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull
};

/* Generator G */
static const uint64_t P384_GX[6] = {
    0x3A545E3872760AB7ull, 0x5502F25DBF55296Cull,
    0x59F741E082542A38ull, 0x6E1D3B628BA79B98ull,
    0x8EB1C71EF320AD74ull, 0xAA87CA22BE8B0537ull
};

static const uint64_t P384_GY[6] = {
    0x7A431D7C90EA0E5Full, 0x0A60B1CE1D7E819Dull,
    0xE9DA3113B5F0B8C0ull, 0xF8F41DBD289A147Cull,
    0x5D9E98BF9292DC29ull, 0x3617DE4A96262C6Full
};

/* ============================================================
 * Generic 6-limb integer helpers (also used as field elements)
 * ============================================================ */

typedef struct { uint64_t limb[6]; } bi384_t;

static void bi384_zero(bi384_t *a) { memset(a->limb, 0, sizeof a->limb); }
static void bi384_copy(bi384_t *r, const bi384_t *a) { *r = *a; }

static int bi384_is_zero(const bi384_t *a) {
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) acc |= a->limb[i];
    return acc == 0;
}

static int bi384_cmp(const bi384_t *a, const bi384_t *b) {
    for (int i = 5; i >= 0; i--) {
        if (a->limb[i] > b->limb[i]) return 1;
        if (a->limb[i] < b->limb[i]) return -1;
    }
    return 0;
}

static void bi384_sub(bi384_t *r, const bi384_t *a, const bi384_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 d = (unsigned __int128)a->limb[i] - b->limb[i] - borrow;
        r->limb[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
}

/* r = a * b as 12 limbs (schoolbook, Cinnabar-style). */
static void bi384_mulwide(uint64_t r[12], const uint64_t a[6], const uint64_t b[6]) {
    memset(r, 0, 12 * sizeof(uint64_t));
    for (int i = 0; i < 6; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; j++) {
            unsigned __int128 p = (unsigned __int128)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        r[i + 6] = carry;
    }
}

/* ============================================================
 * Barrett reduction context (per modulus)
 * ============================================================
 * factor = floor(2^(2k) / mod), where k = bit length of mod (384 for p, n)
 * k computed at init; factor is a 384-bit integer (7 limbs may be needed).
 * shift_digits = k / 64 (whole limbs to shift right), shift_bits = k % 64.
 *
 * For P-384, k = 384:
 *   shift_digits = 6, shift_bits = 0  (k divisible by 64 for P-384)
 */

typedef struct {
    uint64_t mod[6];
    uint64_t factor[7];  /* floor(2^768 / mod) — 7 limbs to hold 384+ bits */
} barrett_ctx_t;

static void barrett_init(barrett_ctx_t *ctx, const uint64_t mod[6]) {
    memcpy(ctx->mod, mod, 6 * sizeof(uint64_t));

    /* factor = floor(2^768 / mod).
     * 2^768 is a 769-bit number (bit 768 set).
     * Compute via long division: put 2^768 in a 13-limb buffer, divide by mod.
     *
     * Cinnabar's approach: use bigint_divide. Here we implement inline.
     */

    /* Dividend: 2^768 → bit 768 set = limb 12, bit 0. */
    uint64_t dividend[13] = {0};
    dividend[12] = 1;  /* 2^(12*64) = 2^768 */

    uint64_t quotient[13] = {0};
    uint64_t remainder[13] = {0};
    size_t rem_len = 0;

    /* Iterate from MSB to LSB of dividend */
    for (int bit = 768; bit >= 0; bit--) {
        /* remainder = (remainder << 1) | (dividend bit) */
        uint64_t carry = (dividend[bit / 64] >> (bit % 64)) & 1;
        for (size_t k = 0; k < rem_len; k++) {
            uint64_t nv = (remainder[k] << 1) | carry;
            carry = remainder[k] >> 63;
            remainder[k] = nv;
        }
        if (carry) {
            remainder[rem_len++] = carry;
        }

        /* if remainder >= mod, subtract and set quotient bit */
        /* Compare: remainder (rem_len limbs) vs mod (6 limbs) */
        int cmp = 0;
        if (rem_len > 6) cmp = 1;
        else if (rem_len < 6) cmp = -1;
        else {
            for (int i = 5; i >= 0; i--) {
                if (remainder[i] > mod[i]) { cmp = 1; break; }
                if (remainder[i] < mod[i]) { cmp = -1; break; }
            }
        }
        if (cmp >= 0) {
            /* remainder -= mod */
            uint64_t borrow = 0;
            for (int i = 0; i < 6; i++) {
                unsigned __int128 d = (unsigned __int128)remainder[i] - mod[i] - borrow;
                remainder[i] = (uint64_t)d;
                borrow = (uint64_t)(d >> 64) & 1;
            }
            if (rem_len > 6) {
                remainder[6] -= borrow;
                if (remainder[6] == 0 && rem_len > 6) rem_len = 6;
            }
            /* Set quotient bit */
            quotient[bit / 64] |= (uint64_t)1 << (bit % 64);
        }
    }

    /* factor occupies quotient[0..6] (7 limbs for 2^768 / 384-bit mod) */
    for (int i = 0; i < 7; i++) ctx->factor[i] = quotient[i];
}

/* r = x mod mod, where x is up to 12 limbs.
 * Barrett: q = floor(x/mod) ≈ floor(((x >> (k-1)) * factor) >> (k+1))
 *          r = x - q * mod
 * For k = 384: q ≈ ((x >> 383) * factor) >> 385. We simplify: use shift_digits=6. */
static void barrett_reduce(bi384_t *r, const uint64_t x[12], const barrett_ctx_t *ctx) {
    /* q1 = x >> 384 (6 limbs, from x[6..11]) */
    uint64_t q1[6] = { x[6], x[7], x[8], x[9], x[10], x[11] };

    /* q2 = q1 * factor — 6 × 7 = 13 limbs */
    uint64_t q2[13] = {0};
    for (int i = 0; i < 6; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 7; j++) {
            unsigned __int128 p = (unsigned __int128)q1[i] * ctx->factor[j] + q2[i + j] + carry;
            q2[i + j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        q2[i + 7] = carry;
    }

    /* q3 = q2 >> 384 (6 limbs, from q2[6..11]; q2[12] rarely used) */
    uint64_t q3[7] = { q2[6], q2[7], q2[8], q2[9], q2[10], q2[11], q2[12] };

    /* r2 = q3 * mod — 7 × 6 = 13 limbs, but we only need low 12 */
    uint64_t r2[13] = {0};
    for (int i = 0; i < 7; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; j++) {
            unsigned __int128 p = (unsigned __int128)q3[i] * ctx->mod[j] + r2[i + j] + carry;
            r2[i + j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        r2[i + 6] = carry;
    }

    /* r = x - r2 mod 2^768 (i.e., low 12 limbs) */
    uint64_t diff[12];
    uint64_t borrow = 0;
    for (int i = 0; i < 12; i++) {
        unsigned __int128 d = (unsigned __int128)x[i] - r2[i] - borrow;
        diff[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }

    /* diff = x - q3*mod is a full 12-limb value, and q3 is an
     * underestimate of floor(x/mod), so diff < ~4*mod.  Reduce it
     * completely -- truncating to 6 limbs first would lose multiples
     * of 2^384, which are not multiples of the modulus. */
    bi384_t mod_bi;
    memcpy(mod_bi.limb, ctx->mod, 6 * sizeof(uint64_t));
    for (;;) {
        int high = 0;
        for (int i = 6; i < 12; i++) high |= (diff[i] != 0);
        bi384_t low;
        memcpy(low.limb, diff, 6 * sizeof(uint64_t));
        if (!high && bi384_cmp(&low, &mod_bi) < 0) {
            bi384_copy(r, &low);
            return;
        }
        uint64_t borrow = 0;
        for (int i = 0; i < 12; i++) {
            uint64_t sub = (i < 6) ? ctx->mod[i] : 0;
            unsigned __int128 d = (unsigned __int128)diff[i] - sub - borrow;
            diff[i] = (uint64_t)d;
            borrow = (uint64_t)(d >> 64) & 1;
        }
    }
}

/* ============================================================
 * Field element: 6 × uint64_t (value in [0, p))
 * ============================================================ */

typedef struct { uint64_t limb[6]; } p384_fe;

static void fe_zero(p384_fe *a) { memset(a->limb, 0, sizeof a->limb); }
static void fe_one(p384_fe *a) { fe_zero(a); a->limb[0] = 1; }
static void fe_copy(p384_fe *r, const p384_fe *a) { *r = *a; }
static int fe_is_zero(const p384_fe *a) {
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) acc |= a->limb[i];
    return acc == 0;
}
static int fe_gte(const p384_fe *a, const p384_fe *b) {
    for (int i = 5; i >= 0; i--) {
        if (a->limb[i] > b->limb[i]) return 1;
        if (a->limb[i] < b->limb[i]) return 0;
    }
    return 1;
}
static uint64_t fe_add_raw(p384_fe *r, const p384_fe *a, const p384_fe *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 s = (unsigned __int128)a->limb[i] + b->limb[i] + carry;
        r->limb[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    return carry;
}
static uint64_t fe_sub_raw(p384_fe *r, const p384_fe *a, const p384_fe *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 d = (unsigned __int128)a->limb[i] - b->limb[i] - borrow;
        r->limb[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    return borrow;
}
static void fe_add(p384_fe *r, const p384_fe *a, const p384_fe *b) {
    p384_fe t;
    uint64_t carry = fe_add_raw(&t, a, b);
    if (carry || fe_gte(&t, (const p384_fe *)P384_P)) {
        fe_sub_raw(r, &t, (const p384_fe *)P384_P);
    } else {
        *r = t;
    }
}
static void fe_sub(p384_fe *r, const p384_fe *a, const p384_fe *b) {
    p384_fe t;
    uint64_t borrow = fe_sub_raw(&t, a, b);
    if (borrow) {
        p384_fe p_fe;
        memcpy(p_fe.limb, P384_P, sizeof P384_P);
        fe_add_raw(&t, &t, &p_fe);
    }
    *r = t;
}

/* Per-modulus Barrett context. */
static barrett_ctx_t g_p_ctx;
static barrett_ctx_t g_n_ctx;
static int g_ctx_initialized = 0;

static void init_ctx(void) {
    if (g_ctx_initialized) return;
    barrett_init(&g_p_ctx, P384_P);
    barrett_init(&g_n_ctx, P384_N);
    g_ctx_initialized = 1;
}

/* r = a * b mod p — fast, Barrett-based. */
static void fe_mul(p384_fe *r, const p384_fe *a, const p384_fe *b) {
    init_ctx();
    uint64_t wide[12];
    bi384_mulwide(wide, a->limb, b->limb);
    bi384_t tmp;
    barrett_reduce(&tmp, wide, &g_p_ctx);
    memcpy(r->limb, tmp.limb, sizeof r->limb);
}

static void fe_sqr(p384_fe *r, const p384_fe *a) { fe_mul(r, a, a); }

/* r = a^(p-2) mod p — Fermat inversion via fast fe_mul. */
static void fe_inv(p384_fe *r, const p384_fe *a) {
    static const uint64_t P_MINUS_2[6] = {
        0x00000000FFFFFFFDull, 0xFFFFFFFF00000000ull,
        0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull,
        0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull
    };
    p384_fe x, base;
    fe_one(&x);
    fe_copy(&base, a);
    for (int i = 383; i >= 0; i--) {
        fe_sqr(&x, &x);
        uint64_t bit = (P_MINUS_2[i / 64] >> (i % 64)) & 1;
        if (bit) fe_mul(&x, &x, &base);
    }
    *r = x;
}

/* ============================================================
 * P-384 curve point (Jacobian)
 * ============================================================ */

typedef struct { p384_fe X, Y, Z; } p384_ge;

static void ge_set_infinity(p384_ge *p) {
    fe_zero(&p->X); fe_zero(&p->Y); fe_zero(&p->Z);
}
static int ge_is_infinity(const p384_ge *p) { return fe_is_zero(&p->Z); }
static void ge_copy(p384_ge *r, const p384_ge *a) { *r = *a; }

static void ge_from_affine(p384_ge *r, const p384_fe *x, const p384_fe *y) {
    fe_copy(&r->X, x); fe_copy(&r->Y, y); fe_one(&r->Z);
}

/* Point doubling (Jacobian, a = -3). */
static void ge_double(p384_ge *r, const p384_ge *a) {
    if (ge_is_infinity(a)) { ge_set_infinity(r); return; }
    p384_fe A, B, C, D, E, F, t1, t2, t3;
    fe_sqr(&A, &a->X);
    fe_sqr(&B, &a->Y);
    fe_sqr(&C, &B);
    fe_add(&t1, &a->X, &B);
    fe_sqr(&t1, &t1);
    fe_sub(&t1, &t1, &A);
    fe_sub(&t1, &t1, &C);
    fe_add(&D, &t1, &t1);
    fe_sqr(&t2, &a->Z);
    fe_sqr(&t2, &t2);
    fe_sub(&t3, &A, &t2);
    fe_add(&t1, &t3, &t3);
    fe_add(&E, &t1, &t3);
    fe_sqr(&F, &E);
    fe_add(&t1, &D, &D);
    fe_sub(&r->X, &F, &t1);
    /* r may alias a: compute Z3 from the original Y before overwriting r->Y. */
    fe_mul(&t1, &a->Y, &a->Z);
    fe_add(&r->Z, &t1, &t1);
    fe_sub(&t1, &D, &r->X);
    fe_mul(&t1, &E, &t1);
    fe_add(&t2, &C, &C);
    fe_add(&t2, &t2, &t2);
    fe_add(&t2, &t2, &t2);
    fe_sub(&r->Y, &t1, &t2);
}

/* Point addition (Jacobian). */
static void ge_add(p384_ge *r, const p384_ge *a, const p384_ge *b) {
    if (ge_is_infinity(a)) { ge_copy(r, b); return; }
    if (ge_is_infinity(b)) { ge_copy(r, a); return; }
    p384_fe Z1Z1, Z2Z2, U1, U2, S1, S2, H, rr, I, J, V, t1, t2;
    fe_sqr(&Z1Z1, &a->Z);
    fe_sqr(&Z2Z2, &b->Z);
    fe_mul(&U1, &a->X, &Z2Z2);
    fe_mul(&U2, &b->X, &Z1Z1);
    fe_mul(&S1, &a->Y, &b->Z);
    fe_mul(&S1, &S1, &Z2Z2);
    fe_mul(&S2, &b->Y, &a->Z);
    fe_mul(&S2, &S2, &Z1Z1);
    fe_sub(&H, &U2, &U1);
    fe_sub(&t1, &S2, &S1);
    fe_add(&rr, &t1, &t1);
    if (fe_is_zero(&H)) {
        if (fe_is_zero(&rr)) { ge_double(r, a); return; }
        ge_set_infinity(r);
        return;
    }
    fe_add(&t1, &H, &H);
    fe_sqr(&I, &t1);
    fe_mul(&J, &H, &I);
    fe_mul(&V, &U1, &I);
    fe_sqr(&t1, &rr);
    fe_sub(&t1, &t1, &J);
    fe_sub(&r->X, &t1, &V);
    fe_sub(&r->X, &r->X, &V);
    fe_sub(&t1, &V, &r->X);
    fe_mul(&t1, &rr, &t1);
    fe_mul(&t2, &S1, &J);
    fe_add(&t2, &t2, &t2);
    fe_sub(&r->Y, &t1, &t2);
    fe_add(&t1, &a->Z, &b->Z);
    fe_sqr(&t1, &t1);
    fe_sub(&t1, &t1, &Z1Z1);
    fe_sub(&t1, &t1, &Z2Z2);
    fe_mul(&r->Z, &t1, &H);
}

static void ge_mul(p384_ge *r, const uint64_t k[6], const p384_ge *p) {
    p384_ge R, base;
    ge_set_infinity(&R);
    ge_copy(&base, p);
    for (int i = 0; i < 6; i++) {
        uint64_t w = k[i];
        for (int bit = 0; bit < 64; bit++) {
            if (w & 1) ge_add(&R, &R, &base);
            ge_double(&base, &base);
            w >>= 1;
        }
    }
    ge_copy(r, &R);
}

static void ge_to_affine(p384_fe *x, p384_fe *y, const p384_ge *p) {
    p384_fe zi, zi2, zi3;
    fe_inv(&zi, &p->Z);
    fe_sqr(&zi2, &zi);
    fe_mul(&zi3, &zi2, &zi);
    fe_mul(x, &p->X, &zi2);
    fe_mul(y, &p->Y, &zi3);
}

/* ============================================================
 * Mod n arithmetic (Barrett with g_n_ctx)
 * ============================================================ */

static void bi384_mulmod_n(bi384_t *r, const bi384_t *a, const bi384_t *b) {
    init_ctx();
    uint64_t wide[12];
    bi384_mulwide(wide, a->limb, b->limb);
    barrett_reduce(r, wide, &g_n_ctx);
}

static void mod_n_once(bi384_t *a) {
    bi384_t n_bi;
    memcpy(n_bi.limb, P384_N, sizeof P384_N);
    while (bi384_cmp(a, &n_bi) >= 0) {
        bi384_sub(a, a, &n_bi);
    }
}

static void bi384_from_bytes(bi384_t *r, const uint8_t in[48]) {
    for (int i = 0; i < 6; i++) {
        const uint8_t *p = in + i * 8;
        r->limb[5 - i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
                       | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
                       | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
                       | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
    }
}

/* ============================================================
 * SPKI parse
 * ============================================================ */

static int parse_spki_p384(const uint8_t *pub_der, size_t pub_der_len,
                           p384_fe *px, p384_fe *py)
{
    asn1_tlv spki, algid, oid1, oid2, bitstr;
    if (asn1_parse(pub_der, pub_der_len, &spki) == 0) return -1;
    if (spki.tag != ASN1_TAG_SEQUENCE) return -1;
    size_t off = 0;
    if (asn1_parse(spki.value, spki.value_len, &algid) == 0) return -1;
    if (algid.tag != ASN1_TAG_SEQUENCE) return -1;
    off += algid.header_len + algid.value_len;

    size_t inner_off = 0;
    if (asn1_parse(algid.value, algid.value_len, &oid1) == 0) return -1;
    if (oid1.tag != ASN1_TAG_OID) return -1;
    char oid_str[64];
    if (asn1_read_oid(oid1.value - oid1.header_len, oid1.header_len + oid1.value_len,
                      oid_str, sizeof oid_str) == 0) return -1;
    if (strcmp(oid_str, "1.2.840.10045.2.1") != 0) return -1;
    inner_off += oid1.header_len + oid1.value_len;

    if (asn1_parse(algid.value + inner_off, algid.value_len - inner_off, &oid2) == 0) return -1;
    if (oid2.tag != ASN1_TAG_OID) return -1;
    if (asn1_read_oid(oid2.value - oid2.header_len, oid2.header_len + oid2.value_len,
                      oid_str, sizeof oid_str) == 0) return -1;
    if (strcmp(oid_str, "1.3.132.0.34") != 0) return -1;

    if (asn1_parse(spki.value + off, spki.value_len - off, &bitstr) == 0) return -1;
    if (bitstr.tag != ASN1_TAG_BIT_STRING) return -1;
    if (bitstr.value_len < 1 + 97) return -1;
    if (bitstr.value[0] != 0) return -1;
    const uint8_t *pt = bitstr.value + 1;
    if (pt[0] != 0x04) return -1;

    uint8_t x_be[48], y_be[48];
    for (int i = 0; i < 48; i++) { x_be[i] = pt[1 + i]; y_be[i] = pt[49 + i]; }

    bi384_t xbi, ybi;
    bi384_from_bytes(&xbi, x_be);
    bi384_from_bytes(&ybi, y_be);
    memcpy(px->limb, xbi.limb, sizeof xbi.limb);
    memcpy(py->limb, ybi.limb, sizeof ybi.limb);
    return 0;
}

static int parse_ecdsa_sig_der_384(const uint8_t *der, size_t len, bi384_t *r, bi384_t *s) {
    asn1_tlv seq, ir, is;
    if (asn1_parse(der, len, &seq) == 0) return -1;
    if (seq.tag != ASN1_TAG_SEQUENCE) return -1;
    size_t off = 0;
    if (asn1_parse(seq.value, seq.value_len, &ir) == 0) return -1;
    if (ir.tag != ASN1_TAG_INTEGER) return -1;
    off += ir.header_len + ir.value_len;
    if (asn1_parse(seq.value + off, seq.value_len - off, &is) == 0) return -1;
    if (is.tag != ASN1_TAG_INTEGER) return -1;

    uint8_t r_raw[48] = {0}, s_raw[48] = {0};
    size_t r_skip = 0;
    while (r_skip < ir.value_len && ir.value[r_skip] == 0) r_skip++;
    size_t r_use = ir.value_len - r_skip;
    if (r_use > 48) return -1;
    memcpy(r_raw + 48 - r_use, ir.value + r_skip, r_use);

    size_t s_skip = 0;
    while (s_skip < is.value_len && is.value[s_skip] == 0) s_skip++;
    size_t s_use = is.value_len - s_skip;
    if (s_use > 48) return -1;
    memcpy(s_raw + 48 - s_use, is.value + s_skip, s_use);

    bi384_from_bytes(r, r_raw);
    bi384_from_bytes(s, s_raw);
    return 0;
}

/* ============================================================
 * Public API
 * ============================================================ */

int ct_verify_ecdsa_p384_sha384(const uint8_t *pub_der, size_t pub_der_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len)
{
    if (!pub_der || !msg || !sig) return CT_ERR_ARGS;

    p384_fe px, py;
    if (parse_spki_p384(pub_der, pub_der_len, &px, &py) != 0) return CT_ERR_VERIFY;

    bi384_t r, s;
    if (parse_ecdsa_sig_der_384(sig, sig_len, &r, &s) != 0) return CT_ERR_VERIFY;

    if (bi384_is_zero(&r) || bi384_is_zero(&s)) return CT_ERR_VERIFY;
    bi384_t n_bi;
    memcpy(n_bi.limb, P384_N, sizeof P384_N);
    if (bi384_cmp(&r, &n_bi) >= 0 || bi384_cmp(&s, &n_bi) >= 0) return CT_ERR_VERIFY;

    /* z = SHA-384(msg) mod n */
    uint8_t z_bytes[48];
    if (ct_sha384(msg, msg_len, z_bytes) != CT_OK) return CT_ERR_VERIFY;
    bi384_t z;
    bi384_from_bytes(&z, z_bytes);
    mod_n_once(&z);

    /* w = s^-1 mod n = s^(n-2) mod n (Fermat) */
    bi384_t w, base;
    bi384_zero(&w); w.limb[0] = 1;
    bi384_copy(&base, &s);
    for (int i = 383; i >= 0; i--) {
        bi384_mulmod_n(&w, &w, &w);
        uint64_t bit = (P384_NM2[i / 64] >> (i % 64)) & 1;
        if (bit) bi384_mulmod_n(&w, &w, &base);
    }

    /* u1 = z*w mod n, u2 = r*w mod n */
    bi384_t u1, u2;
    bi384_mulmod_n(&u1, &z, &w);
    bi384_mulmod_n(&u2, &r, &w);

    /* P = u1·G + u2·Q */
    p384_ge G, Q, u1G, u2Q, sum;
    p384_fe gx, gy;
    memcpy(gx.limb, P384_GX, sizeof P384_GX);
    memcpy(gy.limb, P384_GY, sizeof P384_GY);
    ge_from_affine(&G, &gx, &gy);
    ge_from_affine(&Q, &px, &py);
    ge_mul(&u1G, u1.limb, &G);
    ge_mul(&u2Q, u2.limb, &Q);
    ge_add(&sum, &u1G, &u2Q);

    if (ge_is_infinity(&sum)) return CT_ERR_VERIFY;

    p384_fe affine_x, affine_y;
    ge_to_affine(&affine_x, &affine_y, &sum);
    bi384_t x_mod_n;
    memcpy(x_mod_n.limb, affine_x.limb, sizeof x_mod_n.limb);
    mod_n_once(&x_mod_n);

    if (bi384_cmp(&x_mod_n, &r) != 0) return CT_ERR_VERIFY;
    return CT_OK;
}
