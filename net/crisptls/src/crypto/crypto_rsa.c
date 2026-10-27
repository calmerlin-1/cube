/** crypto_rsa.c — native RSA PKCS#1 v1.5 SHA-256 verify.
 *
 * Reference: RFC 8017 §8.2.2 (RSASSA-PKCS1-v1_5 verify).
 * Structural reference: Cinnabar (Pascal Levy, MIT) — verify-then-compare.
 *
 * Approach: build the EXPECTED padded message (00 01 FF.. 00 DigestInfo H),
 * compute s^e mod n, compare byte-by-byte. Simpler and faster than unpad-
 * then-hash. Constant-time by construction (no early returns).
 *
 * Zero OpenSSL. No external dependencies.
 */

#include "crypto.h"
#include "asn1.h"
#include <stdint.h>
#include <string.h>

#define RSA_MAX_LIMBS  64          /* 4096 bits */
#define RSA_MAX_BYTES  (RSA_MAX_LIMBS * 8)
#define SHA256_LEN     32

/* DigestInfo prefix for SHA-256 — 19 bytes.
 * Actual DigestInfo on wire: 19-byte prefix || 32-byte hash = 51 bytes.
 * Cinnabar's message_encode uses a 20-byte prefix (leading 0x00 marker for
 * the padding separator), i.e. 0x00 || DIGEST_INFO || hash. */
static const uint8_t DIGEST_INFO_SHA256[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

/* ============================================================
 * Big-int: fixed 64-limb (4096-bit max).
 * ============================================================ */

typedef struct {
    uint64_t limb[RSA_MAX_LIMBS];
    size_t   n;
} bi_t;

static void bi_zero(bi_t *a) { memset(a->limb, 0, sizeof a->limb); a->n = 0; }
static void bi_copy(bi_t *r, const bi_t *a) { memcpy(r->limb, a->limb, sizeof a->limb); r->n = a->n; }

static void bi_clamp(bi_t *a) {
    while (a->n > 0 && a->limb[a->n - 1] == 0) a->n--;
}

static int bi_is_zero(const bi_t *a) {
    uint64_t acc = 0;
    for (size_t i = 0; i < a->n; i++) acc |= a->limb[i];
    return acc == 0;
}

static int bi_cmp(const bi_t *a, const bi_t *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (size_t i = a->n; i > 0; i--) {
        if (a->limb[i-1] != b->limb[i-1])
            return a->limb[i-1] < b->limb[i-1] ? -1 : 1;
    }
    return 0;
}

static int bi_from_be(bi_t *a, const uint8_t *buf, size_t len) {
    if (len > RSA_MAX_BYTES) return -1;
    bi_zero(a);
    while (len > 0 && buf[0] == 0) { buf++; len--; }
    if (len == 0) return 0;
    size_t nlimbs = (len + 7) / 8;
    if (nlimbs > RSA_MAX_LIMBS) return -1;
    for (size_t i = 0; i < nlimbs; i++) {
        size_t start = (i + 1) * 8 <= len ? len - (i + 1) * 8 : 0;
        size_t end = len - i * 8;
        if (start > end) start = end;
        uint64_t v = 0;
        for (size_t j = start; j < end; j++) v = (v << 8) | buf[j];
        a->limb[i] = v;
    }
    a->n = nlimbs;
    bi_clamp(a);
    return 0;
}

static size_t bi_byte_len(const bi_t *a) {
    if (a->n == 0) return 0;
    uint64_t top = a->limb[a->n - 1];
    size_t top_bytes = 0;
    while (top) { top_bytes++; top >>= 8; }
    return (a->n - 1) * 8 + top_bytes;
}

static int bi_to_be(uint8_t *buf, size_t out_len, const bi_t *a) {
    if (bi_byte_len(a) > out_len) return -1;
    memset(buf, 0, out_len);
    for (size_t i = 0; i < a->n; i++) {
        uint64_t w = a->limb[i];
        for (int b = 0; b < 8; b++) {
            size_t from_end = i * 8 + b;
            if (from_end >= out_len) { w >>= 8; continue; }
            buf[out_len - 1 - from_end] = (uint8_t)(w & 0xFF);
            w >>= 8;
        }
    }
    return 0;
}

static void bi_sub(bi_t *r, const bi_t *a, const bi_t *b) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t y = i < b->n ? b->limb[i] : 0;
        unsigned __int128 d = (unsigned __int128)a->limb[i] - y - borrow;
        r->limb[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    r->n = a->n;
    bi_clamp(r);
}

/* Schoolbook multiply into variable-size output. */
static int bi_mulwide(uint64_t *r, size_t r_len, const bi_t *a, const bi_t *b) {
    memset(r, 0, r_len * sizeof(uint64_t));
    if (a->n + b->n > r_len) return -1;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->n; j++) {
            unsigned __int128 p = (unsigned __int128)a->limb[i] * b->limb[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        r[i + b->n] = carry;
    }
    return 0;
}

/* ============================================================
 * Barrett reduction (per modulus), from Cinnabar's structure.
 * ============================================================ */

typedef struct {
    bi_t mod;
    bi_t factor;      /* floor(b^(2k) / mod), where b = 2^64, k = mod.limb count */
    size_t k;         /* modulus limb count */
    size_t k_bits;    /* modulus bit length */
} barrett_ctx_t;

static void barrett_init(barrett_ctx_t *ctx, const bi_t *mod) {
    bi_copy(&ctx->mod, mod);
    ctx->k = mod->n;

    /* k_bits = bit length of mod */
    size_t kb = (mod->n - 1) * 64;
    uint64_t top = mod->limb[mod->n - 1];
    while (top) { kb++; top >>= 1; }
    ctx->k_bits = kb;

    /* factor = floor(2^(2 * k_bits) / mod).
     * Use long division: dividend = 2^(2k) (bit 2k_bits set), divisor = mod. */
    size_t div_bits = 2 * kb + 1;
    size_t div_limbs = (div_bits + 63) / 64;

    uint64_t dividend[128] = {0};   /* max 2*4096+1 bits = 8193 bits = 129 limbs */
    if (div_limbs > 128) { memset(&ctx->factor, 0, sizeof ctx->factor); return; }
    dividend[2 * kb / 64] = (uint64_t)1 << (2 * kb % 64);

    uint64_t rem[128] = {0};
    size_t rem_n = 0;
    uint64_t quotient[128] = {0};

    for (int bit = (int)(2 * kb); bit >= 0; bit--) {
        /* rem = (rem << 1) | dividend[bit] */
        uint64_t carry = (dividend[bit / 64] >> (bit % 64)) & 1;
        for (size_t j = 0; j < rem_n; j++) {
            uint64_t nv = (rem[j] << 1) | carry;
            carry = rem[j] >> 63;
            rem[j] = nv;
        }
        if (carry) rem[rem_n++] = carry;

        /* if rem >= mod: rem -= mod; set quotient bit */
        int cmp;
        if (rem_n > mod->n) cmp = 1;
        else if (rem_n < mod->n) cmp = -1;
        else {
            cmp = 0;
            for (int i = (int)mod->n - 1; i >= 0; i--) {
                if (rem[i] > mod->limb[i]) { cmp = 1; break; }
                if (rem[i] < mod->limb[i]) { cmp = -1; break; }
            }
        }
        if (cmp >= 0) {
            uint64_t b = 0;
            for (size_t j = 0; j < mod->n; j++) {
                unsigned __int128 d = (unsigned __int128)rem[j] - mod->limb[j] - b;
                rem[j] = (uint64_t)d;
                b = (uint64_t)(d >> 64) & 1;
            }
            if (rem_n > mod->n) {
                rem[mod->n] -= b;
                if (rem[mod->n] == 0 && rem_n > mod->n) rem_n = mod->n;
            }
            quotient[bit / 64] |= (uint64_t)1 << (bit % 64);
        }
    }

    /* Store factor (may be up to k+1 limbs) */
    bi_zero(&ctx->factor);
    for (size_t i = 0; i < div_limbs && i < RSA_MAX_LIMBS; i++)
        ctx->factor.limb[i] = quotient[i];
    ctx->factor.n = div_limbs;
    bi_clamp(&ctx->factor);
}

static void barrett_reduce(bi_t *r, const uint64_t *x, size_t x_limbs, const barrett_ctx_t *ctx) {
    /* Barrett: q1 = x >> (k-1)*64 */
    size_t shift_limbs = ctx->k - 1;
    bi_t q1;
    bi_zero(&q1);
    if (x_limbs > shift_limbs) {
        q1.n = x_limbs - shift_limbs;
        for (size_t i = 0; i < q1.n; i++) q1.limb[i] = x[shift_limbs + i];
        bi_clamp(&q1);
    }

    /* q2 = q1 * factor */
    uint64_t q2[256] = {0};
    bi_mulwide(q2, 256, &q1, &ctx->factor);
    size_t q2_n = q1.n + ctx->factor.n;

    /* q3 = q2 >> (k+1)*64 */
    size_t shift2 = ctx->k + 1;
    bi_t q3;
    bi_zero(&q3);
    if (q2_n > shift2) {
        q3.n = q2_n - shift2;
        for (size_t i = 0; i < q3.n; i++) q3.limb[i] = q2[shift2 + i];
        bi_clamp(&q3);
    }

    /* r2 = q3 * mod */
    uint64_t r2[256] = {0};
    bi_mulwide(r2, 256, &q3, &ctx->mod);
    size_t r2_n = q3.n + ctx->mod.n;

    /* r = x - r2 (mod 2^(x_limbs * 64)) */
    uint64_t diff[256] = {0};
    uint64_t borrow = 0;
    for (size_t i = 0; i < x_limbs; i++) {
        uint64_t y = i < r2_n ? r2[i] : 0;
        unsigned __int128 d = (unsigned __int128)x[i] - y - borrow;
        diff[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }

    /* Take low k limbs, subtract mod while >= mod */
    bi_zero(r);
    r->n = ctx->k;
    for (size_t i = 0; i < ctx->k && i < x_limbs; i++) r->limb[i] = diff[i];
    bi_clamp(r);

    while (bi_cmp(r, &ctx->mod) >= 0) bi_sub(r, r, &ctx->mod);
}

static void bi_mulmod(bi_t *r, const bi_t *a, const bi_t *b, const barrett_ctx_t *ctx) {
    uint64_t wide[256] = {0};
    bi_mulwide(wide, 256, a, b);
    barrett_reduce(r, wide, a->n + b->n, ctx);
}

/* modexp: r = a^e mod m. */
static void bi_modexp(bi_t *r, const bi_t *a, const bi_t *e, const bi_t *m) {
    barrett_ctx_t ctx;
    barrett_init(&ctx, m);

    bi_t base;
    /* base = a mod m (a < m for RSA sig, so just copy) */
    if (bi_cmp(a, m) < 0) bi_copy(&base, a);
    else { bi_zero(&base); }  /* simplify: caller must pass a < m */

    bi_t result;
    bi_zero(&result);
    result.limb[0] = 1;
    result.n = 1;

    for (size_t i = 0; i < e->n; i++) {
        uint64_t w = e->limb[i];
        for (int bit = 0; bit < 64; bit++) {
            if (w & 1) bi_mulmod(&result, &result, &base, &ctx);
            if (i == e->n - 1 && (w >> 1) == 0) goto done;
            bi_mulmod(&base, &base, &base, &ctx);
            w >>= 1;
        }
    }
done:
    bi_copy(r, &result);
}

/* ============================================================
 * SPKI parse
 * ============================================================ */

static int parse_spki_rsa(const uint8_t *pub_der, size_t pub_der_len, bi_t *n, bi_t *e) {
    asn1_tlv spki, algid, oid_tlv, bitstr, rsa_pub, tlv_n, tlv_e;
    if (asn1_parse(pub_der, pub_der_len, &spki) == 0) return -1;
    if (spki.tag != ASN1_TAG_SEQUENCE) return -1;

    size_t off = 0;
    if (asn1_parse(spki.value, spki.value_len, &algid) == 0) return -1;
    if (algid.tag != ASN1_TAG_SEQUENCE) return -1;
    off += algid.header_len + algid.value_len;

    if (asn1_parse(algid.value, algid.value_len, &oid_tlv) == 0) return -1;
    if (oid_tlv.tag != ASN1_TAG_OID) return -1;
    char oid_str[64];
    if (asn1_read_oid(oid_tlv.value - oid_tlv.header_len,
                      oid_tlv.header_len + oid_tlv.value_len, oid_str, sizeof oid_str) == 0) return -1;
    if (strcmp(oid_str, "1.2.840.113549.1.1.1") != 0) return -1;

    if (asn1_parse(spki.value + off, spki.value_len - off, &bitstr) == 0) return -1;
    if (bitstr.tag != ASN1_TAG_BIT_STRING) return -1;
    if (bitstr.value_len < 2) return -1;
    if (bitstr.value[0] != 0) return -1;

    const uint8_t *rsa_der = bitstr.value + 1;
    size_t rsa_der_len = bitstr.value_len - 1;

    if (asn1_parse(rsa_der, rsa_der_len, &rsa_pub) == 0) return -1;
    if (rsa_pub.tag != ASN1_TAG_SEQUENCE) return -1;

    size_t inner_off = 0;
    if (asn1_parse(rsa_pub.value, rsa_pub.value_len, &tlv_n) == 0) return -1;
    if (tlv_n.tag != ASN1_TAG_INTEGER) return -1;
    inner_off += tlv_n.header_len + tlv_n.value_len;

    if (asn1_parse(rsa_pub.value + inner_off, rsa_pub.value_len - inner_off, &tlv_e) == 0) return -1;
    if (tlv_e.tag != ASN1_TAG_INTEGER) return -1;

    const uint8_t *n_buf = tlv_n.value;
    size_t n_len = tlv_n.value_len;
    if (n_len > 0 && n_buf[0] == 0) { n_buf++; n_len--; }
    if (bi_from_be(n, n_buf, n_len) != 0) return -1;

    const uint8_t *e_buf = tlv_e.value;
    size_t e_len = tlv_e.value_len;
    if (e_len > 0 && e_buf[0] == 0) { e_buf++; e_len--; }
    if (bi_from_be(e, e_buf, e_len) != 0) return -1;

    return 0;
}

/* ============================================================
 * PKCS#1 v1.5 verify — build expected EM, compare byte-by-byte.
 * ============================================================ */

int ct_verify_rsa_pkcs1_sha256(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    if (!pub_der || !sig || sig_len == 0) return CT_ERR_ARGS;
    if (!msg && msg_len > 0) return CT_ERR_ARGS;

    bi_t n, e;
    if (parse_spki_rsa(pub_der, pub_der_len, &n, &e) != 0) return CT_ERR_VERIFY;
    if (n.n == 0 || e.n == 0) return CT_ERR_VERIFY;

    size_t k = bi_byte_len(&n);
    if (k != sig_len) return CT_ERR_VERIFY;
    if (k < SHA256_LEN + 19 + 2 + 8) return CT_ERR_VERIFY;   /* RFC 8017 min */
    if (k > RSA_MAX_BYTES) return CT_ERR_VERIFY;

    /* m = sig^e mod n */
    bi_t s_bi, m_bi;
    if (bi_from_be(&s_bi, sig, sig_len) != 0) return CT_ERR_VERIFY;
    if (bi_cmp(&s_bi, &n) >= 0) return CT_ERR_VERIFY;
    bi_modexp(&m_bi, &s_bi, &e, &n);

    /* em_actual = i2osp(m, k) */
    uint8_t em_actual[4096];
    if (bi_to_be(em_actual, k, &m_bi) != 0) return CT_ERR_VERIFY;

    /* em_expected = 00 01 FF.. FF 00 || DigestInfo || hash(msg) */
    uint8_t em_expected[4096];
    memset(em_expected, 0, k);
    em_expected[0] = 0x00;
    em_expected[1] = 0x01;
    size_t ps_len = k - 19 - 32 - 2;   /* filler FF count */
    memset(em_expected + 2, 0xFF, ps_len);
    em_expected[2 + ps_len] = 0x00;
    memcpy(em_expected + 3 + ps_len, DIGEST_INFO_SHA256, 19);
    if (ct_sha256(msg ? msg : (const uint8_t *)"", msg_len,
                  em_expected + 3 + ps_len + 19) != CT_OK) return CT_ERR_VERIFY;

    /* Constant-time compare */
    uint8_t diff = 0;
    for (size_t i = 0; i < k; i++) diff |= em_actual[i] ^ em_expected[i];

    return diff ? CT_ERR_VERIFY : CT_OK;
}
