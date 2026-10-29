/** crypto_rsa.c — native RSA PKCS#1 v1.5 and RSA-PSS SHA-256 verify.
 *
 * References:
 *   RFC 8017 §8.2.2  (RSASSA-PKCS1-v1_5 verify)
 *   RFC 8017 §8.1.2  (RSASSA-PSS verify)
 *   RFC 8017 §9.1.2  (EMSA-PSS encoding, MGF1)
 *
 * PKCS#1 v1.5: build the EXPECTED padded message (00 01 FF.. 00 DigestInfo H),
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
#define SHA384_LEN     48
#define SHA512_LEN     64

/* DigestInfo prefix for SHA-256 — 19 bytes.
 * Actual DigestInfo on wire: 19-byte prefix || 32-byte hash = 51 bytes.
 * Cinnabar's message_encode uses a 20-byte prefix (leading 0x00 marker for
 * the padding separator), i.e. 0x00 || DIGEST_INFO || hash. */
static const uint8_t DIGEST_INFO_SHA256[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
static const uint8_t DIGEST_INFO_SHA384[19] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};
static const uint8_t DIGEST_INFO_SHA512[19] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
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
 * Modular reduction
 * ============================================================
 * Full-width binary long division: shift the remainder one bit at a
 * time, conditionally subtracting the modulus.  This handles moduli of
 * any size up to RSA_MAX_LIMBS without the fixed-size overflow and
 * high-limb truncation that the previous Barrett table implementation
 * had for 3072/4096-bit keys.
 */

static void bi_mod_reduce(bi_t *r, const uint64_t *x, size_t x_limbs,
                          const bi_t *mod)
{
    uint64_t rem[RSA_MAX_LIMBS + 2] = {0};
    size_t rem_n = 0;

    if (mod->n == 0) { bi_zero(r); return; }

    for (size_t bit = x_limbs * 64; bit-- > 0; ) {
        uint64_t carry = (x[bit >> 6] >> (bit & 63)) & 1;
        for (size_t j = 0; j < rem_n; j++) {
            uint64_t nv = (rem[j] << 1) | carry;
            carry = rem[j] >> 63;
            rem[j] = nv;
        }
        if (carry) rem[rem_n++] = carry;

        int cmp;
        if (rem_n > mod->n) cmp = 1;
        else if (rem_n < mod->n) cmp = -1;
        else {
            cmp = 0;
            for (size_t i = mod->n; i-- > 0; ) {
                if (rem[i] > mod->limb[i]) { cmp = 1; break; }
                if (rem[i] < mod->limb[i]) { cmp = -1; break; }
            }
        }
        if (cmp >= 0) {
            uint64_t borrow = 0;
            for (size_t j = 0; j < rem_n; j++) {
                uint64_t y = j < mod->n ? mod->limb[j] : 0;
                unsigned __int128 d = (unsigned __int128)rem[j] - y - borrow;
                rem[j] = (uint64_t)d;
                borrow = (uint64_t)(d >> 64) & 1;
            }
            while (rem_n > 0 && rem[rem_n - 1] == 0) rem_n--;
        }
    }

    bi_zero(r);
    r->n = rem_n;
    memcpy(r->limb, rem, rem_n * sizeof(uint64_t));
    bi_clamp(r);
}

static void bi_mulmod(bi_t *r, const bi_t *a, const bi_t *b, const bi_t *mod) {
    uint64_t wide[2 * RSA_MAX_LIMBS + 4] = {0};
    const size_t wide_len = sizeof wide / sizeof wide[0];
    if (a->n + b->n > wide_len) { bi_zero(r); return; }
    bi_mulwide(wide, wide_len, a, b);
    bi_mod_reduce(r, wide, a->n + b->n, mod);
}

/* modexp: r = a^e mod m. */
static void bi_modexp(bi_t *r, const bi_t *a, const bi_t *e, const bi_t *m) {
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
            if (w & 1) bi_mulmod(&result, &result, &base, m);
            if (i == e->n - 1 && (w >> 1) == 0) goto done;
            bi_mulmod(&base, &base, &base, m);
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

typedef int (*ct_hash_fn)(const uint8_t *, size_t, uint8_t *);

static int rsa_pkcs1_verify_hash(const uint8_t *pub_der, size_t pub_der_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *digest_info, size_t digest_info_len,
                                 size_t hash_len, ct_hash_fn hash_fn)
{
    if (!pub_der || !sig || sig_len == 0) return CT_ERR_ARGS;
    if (!msg && msg_len > 0) return CT_ERR_ARGS;

    bi_t n, e;
    if (parse_spki_rsa(pub_der, pub_der_len, &n, &e) != 0) return CT_ERR_VERIFY;
    if (n.n == 0 || e.n == 0) return CT_ERR_VERIFY;

    size_t k = bi_byte_len(&n);
    if (k != sig_len) return CT_ERR_VERIFY;
    if (k < digest_info_len + hash_len + 11) return CT_ERR_VERIFY;   /* RFC 8017 min */
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
    size_t ps_len = k - digest_info_len - hash_len - 3;
    memset(em_expected + 2, 0xFF, ps_len);
    em_expected[2 + ps_len] = 0x00;
    memcpy(em_expected + 3 + ps_len, digest_info, digest_info_len);
    if (hash_fn(msg ? msg : (const uint8_t *)"", msg_len,
                em_expected + 3 + ps_len + digest_info_len) != CT_OK)
        return CT_ERR_VERIFY;

    /* Constant-time compare */
    uint8_t diff = 0;
    for (size_t i = 0; i < k; i++) diff |= em_actual[i] ^ em_expected[i];

    return diff ? CT_ERR_VERIFY : CT_OK;
}

int ct_verify_rsa_pkcs1_sha256(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    return rsa_pkcs1_verify_hash(pub_der, pub_der_len, msg, msg_len, sig, sig_len,
                                 DIGEST_INFO_SHA256, sizeof DIGEST_INFO_SHA256,
                                 SHA256_LEN, ct_sha256);
}

int ct_verify_rsa_pkcs1_sha384(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    return rsa_pkcs1_verify_hash(pub_der, pub_der_len, msg, msg_len, sig, sig_len,
                                 DIGEST_INFO_SHA384, sizeof DIGEST_INFO_SHA384,
                                 SHA384_LEN, ct_sha384);
}

int ct_verify_rsa_pkcs1_sha512(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    return rsa_pkcs1_verify_hash(pub_der, pub_der_len, msg, msg_len, sig, sig_len,
                                 DIGEST_INFO_SHA512, sizeof DIGEST_INFO_SHA512,
                                 SHA512_LEN, ct_sha512);
}

/* ============================================================
 * RSA-PSS SHA-256 verify (RFC 8017 §8.1.2 / §9.1.2)
 * Salt length is recovered from the encoding, so certificates that
 * use a non-default salt length (RFC 4055 permits variable sLen)
 * still verify. TLS 1.3 CertificateVerify uses sLen == hLen.
 * ============================================================ */

static size_t bi_bit_len(const bi_t *a) {
    if (a->n == 0) return 0;
    size_t bits = (a->n - 1) * 64;
    uint64_t top = a->limb[a->n - 1];
    while (top) { bits++; top >>= 1; }
    return bits;
}

/* MGF1 with SHA-256 (RFC 8017 §B.2.1). */
static int mgf1_sha256(const uint8_t *seed, size_t seed_len,
                       uint8_t *out, size_t out_len)
{
    size_t done = 0;
    uint32_t counter = 0;
    while (done < out_len) {
        uint8_t ctr_be[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >> 8),  (uint8_t)counter
        };
        uint8_t h[32];
        ct_sha256_ctx_t c;
        ct_sha256_init(&c);
        ct_sha256_update(&c, seed, seed_len);
        ct_sha256_update(&c, ctr_be, sizeof ctr_be);
        ct_sha256_final(&c, h);

        size_t n = out_len - done < sizeof h ? out_len - done : sizeof h;
        memcpy(out + done, h, n);
        done += n;
        counter++;
    }
    return 0;
}

int ct_verify_rsa_pss_sha256(const uint8_t *pub_der, size_t pub_der_len,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len)
{
    if (!pub_der || !sig || sig_len == 0) return CT_ERR_ARGS;
    if (!msg && msg_len > 0) return CT_ERR_ARGS;

    bi_t n, e;
    if (parse_spki_rsa(pub_der, pub_der_len, &n, &e) != 0) return CT_ERR_VERIFY;
    if (n.n == 0 || e.n == 0) return CT_ERR_VERIFY;

    size_t k = bi_byte_len(&n);
    if (k != sig_len || k > RSA_MAX_BYTES) return CT_ERR_VERIFY;

    size_t mod_bits = bi_bit_len(&n);
    if (mod_bits < 2) return CT_ERR_VERIFY;
    size_t em_bits = mod_bits - 1;
    size_t em_len = (em_bits + 7) / 8;
    const size_t hlen = SHA256_LEN;
    if (em_len > k || em_len < hlen + 2) return CT_ERR_VERIFY;

    /* m = sig^e mod n; EM = I2OSP(m, k), left-padded to k bytes. */
    bi_t s_bi, m_bi;
    if (bi_from_be(&s_bi, sig, sig_len) != 0) return CT_ERR_VERIFY;
    if (bi_cmp(&s_bi, &n) >= 0) return CT_ERR_VERIFY;
    bi_modexp(&m_bi, &s_bi, &e, &n);

    uint8_t em_buf[RSA_MAX_BYTES];
    if (bi_to_be(em_buf, k, &m_bi) != 0) return CT_ERR_VERIFY;

    /* When k > emLen the leading bytes MUST be zero (RFC 8017 §8.1.2). */
    size_t lead = k - em_len;
    uint8_t diff = 0;
    for (size_t i = 0; i < lead; i++) diff |= em_buf[i];
    const uint8_t *em = em_buf + lead;

    size_t db_len = em_len - hlen - 1;
    const uint8_t *masked_db = em;
    const uint8_t *h = em + db_len;

    /* Leftmost 8*emLen - emBits bits of maskedDB must be zero. */
    size_t unused_bits = 8 * em_len - em_bits;
    if (unused_bits) {
        uint8_t keep = (uint8_t)(0xFF >> unused_bits);
        if (masked_db[0] & (uint8_t)~keep) return CT_ERR_VERIFY;
    }

    /* DB = maskedDB XOR MGF1(H, dbLen); clear the unused top bits. */
    uint8_t db[RSA_MAX_BYTES];
    mgf1_sha256(h, hlen, db, db_len);
    for (size_t i = 0; i < db_len; i++) db[i] ^= masked_db[i];
    if (unused_bits) db[0] &= (uint8_t)(0xFF >> unused_bits);

    /* DB = PS || 0x01 || salt. Recover salt length from the delimiter. */
    size_t ps_len = 0;
    while (ps_len < db_len && db[ps_len] == 0) ps_len++;
    if (ps_len >= db_len || db[ps_len] != 0x01) return CT_ERR_VERIFY;
    const uint8_t *salt = db + ps_len + 1;
    size_t salt_len = db_len - ps_len - 1;

    /* H' = SHA-256(0x00^8 || mHash || salt). */
    uint8_t mhash[SHA256_LEN];
    if (ct_sha256(msg ? msg : (const uint8_t *)"", msg_len, mhash) != CT_OK)
        return CT_ERR_VERIFY;

    uint8_t hprime[SHA256_LEN];
    ct_sha256_ctx_t hc;
    ct_sha256_init(&hc);
    {
        static const uint8_t zero8[8] = {0};
        ct_sha256_update(&hc, zero8, sizeof zero8);
    }
    ct_sha256_update(&hc, mhash, sizeof mhash);
    ct_sha256_update(&hc, salt, salt_len);
    ct_sha256_final(&hc, hprime);

    for (size_t i = 0; i < hlen; i++) diff |= (uint8_t)(h[i] ^ hprime[i]);
    return diff ? CT_ERR_VERIFY : CT_OK;
}
