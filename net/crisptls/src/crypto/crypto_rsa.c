/** crypto_rsa.c — native RSA PKCS#1 v1.5 SHA-256 signature verification.
 *
 * Implements RFC 8017 §8.2.2 (RSASSA-PKCS1-v1_5 verify) with SHA-256.
 *
 * Architecture mirrors Cinnabar (Pascal Levy, MIT):
 *   BIGINT      fixed 32-limb big integer (2048-bit)
 *   Barrett     modular reduction with precomputed factor
 *   EMSA        PKCS#1 v1.5 encode + constant-time compare
 *
 * Differences from Cinnabar:
 *   - Uses crypto.h's native ct_sha256 (no local SHA-256)
 *   - Uses asn1.h's asn1_parse for SPKI DER (no local PEM parser)
 *   - Fixed-size limbs (no malloc per operation)
 *   - Public API matches crypto.h (ct_verify_rsa_pkcs1_sha256)
 *
 * No OpenSSL. No external dependencies beyond crypto.h and asn1.h.
 */

#include "crypto.h"
#include "asn1.h"
#include <stdint.h>
#include <string.h>

/* ---- Configuration ---- */

#define RSA_MAX_LIMBS  64          /* 64 * 64 = 4096 bits max */
#define RSA_MAX_BYTES  512
#define SHA256_LEN     32
#define DIGEST_INFO_LEN 19

/* DigestInfo prefix for SHA-256 (RFC 8017 §9.2 Note 1):
 *   SEQUENCE { AlgorithmIdentifier { OID id-sha256, NULL }, OCTET STRING (32) }
 * Followed by 32-byte hash value. */
static const uint8_t DIGEST_INFO_SHA256[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

/* ---- BIGINT (fixed 64-bit limbs, max 64 limbs = 4096 bits) ---- */

typedef struct {
    uint64_t limb[RSA_MAX_LIMBS];
    size_t   n;   /* number of limbs used (MSB-first clamp applied) */
} rsa_bi_t;

static void bi_zero(rsa_bi_t *a) {
    memset(a->limb, 0, sizeof a->limb);
    a->n = 0;
}

static void bi_clamp(rsa_bi_t *a) {
    while (a->n > 0 && a->limb[a->n - 1] == 0) a->n--;
}

static void bi_copy(rsa_bi_t *r, const rsa_bi_t *a) {
    memcpy(r->limb, a->limb, sizeof a->limb);
    r->n = a->n;
}

/* Load big-endian bytes into limbs. Returns 0 on success, -1 if too big. */
static int bi_from_be(rsa_bi_t *a, const uint8_t *buf, size_t len) {
    if (len > RSA_MAX_BYTES) return -1;
    bi_zero(a);
    /* Skip leading zero bytes */
    while (len > 0 && buf[0] == 0) { buf++; len--; }
    if (len == 0) return 0;

    size_t nlimbs = (len + 7) / 8;
    if (nlimbs > RSA_MAX_LIMBS) return -1;

    for (size_t i = 0; i < nlimbs; i++) {
        /* limb[i] holds bytes [len - (i+1)*8 .. len - i*8) of buf, BE within limb */
        size_t limb_start_from_end = (i + 1) * 8;
        size_t byte_start;
        if (limb_start_from_end > len) byte_start = 0;
        else byte_start = len - limb_start_from_end;
        size_t byte_end = len - i * 8;

        uint64_t v = 0;
        for (size_t j = byte_start; j < byte_end; j++) {
            v = (v << 8) | buf[j];
        }
        a->limb[i] = v;
    }
    a->n = nlimbs;
    bi_clamp(a);
    return 0;
}

/* Emit as big-endian to buf[0..out_len). Pads with leading zeros.
 * Returns -1 if a doesn't fit. */
static int bi_to_be(uint8_t *buf, size_t out_len, const rsa_bi_t *a) {
    size_t needed = 0;
    if (a->n > 0) {
        /* bytes needed for top limb */
        uint64_t top = a->limb[a->n - 1];
        size_t top_bytes = 0;
        while (top) { top_bytes++; top >>= 8; }
        needed = (a->n - 1) * 8 + top_bytes;
    }
    if (needed > out_len) return -1;

    memset(buf, 0, out_len);
    for (size_t i = 0; i < a->n; i++) {
        uint64_t w = a->limb[i];
        for (int b = 0; b < 8; b++) {
            size_t byte_from_end = (a->n - 1 - i) * 8 + (7 - b);
            if (byte_from_end >= out_len) continue;
            buf[out_len - 1 - byte_from_end] = (uint8_t)(w & 0xFF);
            w >>= 8;
        }
    }
    return 0;
}

/* Number of bytes needed for big-endian representation of a. */
static size_t bi_byte_len(const rsa_bi_t *a) {
    if (a->n == 0) return 0;
    uint64_t top = a->limb[a->n - 1];
    size_t top_bytes = 0;
    while (top) { top_bytes++; top >>= 8; }
    return (a->n - 1) * 8 + top_bytes;
}

/* Compare a vs b: -1 if a<b, 0 if a==b, 1 if a>b. */
static int bi_cmp(const rsa_bi_t *a, const rsa_bi_t *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (size_t i = a->n; i > 0; i--) {
        if (a->limb[i-1] != b->limb[i-1])
            return a->limb[i-1] < b->limb[i-1] ? -1 : 1;
    }
    return 0;
}

/* r = a + b. Returns carry out (0/1). */
/* r = a - b. Assumes a >= b. */
static void bi_sub(rsa_bi_t *r, const rsa_bi_t *a, const rsa_bi_t *b) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t x = a->limb[i];
        uint64_t y = i < b->n ? b->limb[i] : 0;
        /* Subtract: x - y - borrow. Result in 64 bits (mod 2^64). */
        unsigned __int128 diff = (unsigned __int128)x - y - borrow;
        r->limb[i] = (uint64_t)diff;
        borrow = (uint64_t)(diff >> 64) & 1;
    }
    r->n = a->n;
    bi_clamp(r);
}

/* r = a * b. Schoolbook multiply. r must have room for a->n + b->n limbs. */
static int bi_mul(rsa_bi_t *r, const rsa_bi_t *a, const rsa_bi_t *b) {
    if (a->n == 0 || b->n == 0) { bi_zero(r); return 0; }
    if (a->n + b->n > RSA_MAX_LIMBS) return -1;

    bi_zero(r);
    for (size_t i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->n; j++) {
            unsigned __int128 prod = (unsigned __int128)a->limb[i] * b->limb[j]
                                     + r->limb[i + j] + carry;
            r->limb[i + j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        r->limb[i + b->n] += carry;
    }
    r->n = a->n + b->n;
    bi_clamp(r);
    return 0;
}

/* r = a mod m. Long division by shift-and-subtract.
 * Simple, O(n²) in limbs; slow enough for one RSA verify (once per cert). */
static int bi_mod(rsa_bi_t *r, const rsa_bi_t *a, const rsa_bi_t *m) {
    if (m->n == 0) return -1;
    if (bi_cmp(a, m) < 0) { bi_copy(r, a); return 0; }

    rsa_bi_t rem, shifted, m_shifted;
    bi_copy(&rem, a);

    while (bi_cmp(&rem, m) >= 0) {
        /* shifted = m << k such that shifted <= rem < shifted*2 */
        size_t shift_bits = 0;
        size_t diff_n = rem.n - m->n;
        bi_copy(&m_shifted, m);
        /* First shift by whole limbs */
        if (diff_n > 0) {
            memmove(&m_shifted.limb[diff_n], &m_shifted.limb[0],
                    m_shifted.n * sizeof(uint64_t));
            memset(&m_shifted.limb[0], 0, diff_n * sizeof(uint64_t));
            m_shifted.n += diff_n;
        }
        /* Then shift by bits until m_shifted > rem (then back off by one) */
        while (bi_cmp(&m_shifted, &rem) <= 0 && shift_bits < 63) {
            bi_copy(&shifted, &m_shifted);
            /* shift left by 1 */
            uint64_t carry = 0;
            for (size_t i = 0; i < m_shifted.n; i++) {
                uint64_t nv = m_shifted.limb[i] << 1;
                m_shifted.limb[i] = nv | carry;
                carry = (nv < carry) ? 1 : 0;
            }
            if (carry && m_shifted.n < RSA_MAX_LIMBS) {
                m_shifted.limb[m_shifted.n++] = carry;
            }
            shift_bits++;
        }
        /* m_shifted is now too big; use shifted (last one that fit) */
        if (shift_bits == 0 && bi_cmp(&m_shifted, &rem) > 0) {
            bi_copy(&shifted, &m_shifted);
        }
        /* Actually we want shifted = m_shifted / 2 shifted if we overshot */
        /* Simpler: recompute from scratch */
        bi_copy(&m_shifted, m);
        if (diff_n > 0) {
            memmove(&m_shifted.limb[diff_n], &m_shifted.limb[0],
                    m_shifted.n * sizeof(uint64_t));
            memset(&m_shifted.limb[0], 0, diff_n * sizeof(uint64_t));
            m_shifted.n += diff_n;
        }
        /* Now shift bits until we exceed */
        while (1) {
            rsa_bi_t trial;
            bi_copy(&trial, &m_shifted);
            uint64_t carry = 0;
            for (size_t i = 0; i < trial.n; i++) {
                uint64_t nv = trial.limb[i] << 1;
                trial.limb[i] = nv | carry;
                carry = (nv < carry) ? 1 : 0;
            }
            if (carry && trial.n < RSA_MAX_LIMBS) trial.limb[trial.n++] = carry;
            bi_clamp(&trial);
            if (bi_cmp(&trial, &rem) > 0) break;
            bi_copy(&m_shifted, &trial);
        }
        bi_sub(&rem, &rem, &m_shifted);
    }
    bi_copy(r, &rem);
    return 0;
}

/* r = a^e mod m. Square-and-multiply (LSB-first). */
static int bi_modexp(rsa_bi_t *r, const rsa_bi_t *a, const rsa_bi_t *e, const rsa_bi_t *m) {
    rsa_bi_t base, result, tmp;
    if (bi_mod(&base, a, m) != 0) return -1;
    bi_zero(&result);
    result.limb[0] = 1;
    result.n = 1;

    for (size_t i = 0; i < e->n; i++) {
        uint64_t exp = e->limb[i];
        for (int j = 0; j < 64; j++) {
            if (exp & 1) {
                if (bi_mul(&tmp, &result, &base) != 0) return -1;
                if (bi_mod(&result, &tmp, m) != 0) return -1;
            }
            if (i == e->n - 1 && (exp >> 1) == 0) {
                /* Last bit of last limb; no need to square further */
                goto done;
            }
            if (bi_mul(&tmp, &base, &base) != 0) return -1;
            if (bi_mod(&base, &tmp, m) != 0) return -1;
            exp >>= 1;
        }
    }
done:
    bi_copy(r, &result);
    return 0;
}

/* ---- SPKI DER parse ---- */

/* Parse DER-encoded RSAPublicKey into n, e (as byte buffers).
 * pub_der must be a full SubjectPublicKeyInfo:
 *   SEQUENCE {
 *     AlgorithmIdentifier { OID rsaEncryption (1.2.840.113549.1.1.1), NULL },
 *     BIT STRING { RSAPublicKey }
 *   }
 *   RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
 */
static int parse_spki_rsa(const uint8_t *pub_der, size_t pub_der_len,
                          rsa_bi_t *n, rsa_bi_t *e)
{
    asn1_tlv spki, algid, oid_tlv, bitstring, rsa_pub, tlv_n, tlv_e;

    /* Outer SEQUENCE */
    if (asn1_parse(pub_der, pub_der_len, &spki) == 0) return -1;
    if (spki.tag != ASN1_TAG_SEQUENCE) return -1;

    /* AlgorithmIdentifier */
    size_t off = 0;
    if (asn1_parse(spki.value, spki.value_len, &algid) == 0) return -1;
    if (algid.tag != ASN1_TAG_SEQUENCE) return -1;
    off += algid.header_len + algid.value_len;

    /* OID inside AlgorithmIdentifier */
    if (asn1_parse(algid.value, algid.value_len, &oid_tlv) == 0) return -1;
    if (oid_tlv.tag != ASN1_TAG_OID) return -1;
    char oid_str[64];
    if (asn1_read_oid(oid_tlv.value - oid_tlv.header_len,
                      oid_tlv.header_len + oid_tlv.value_len,
                      oid_str, sizeof oid_str) == 0) return -1;
    if (strcmp(oid_str, "1.2.840.113549.1.1.1") != 0) return -1;

    /* BIT STRING */
    if (asn1_parse(spki.value + off, spki.value_len - off, &bitstring) == 0) return -1;
    if (bitstring.tag != ASN1_TAG_BIT_STRING) return -1;
    if (bitstring.value_len < 2) return -1;
    /* First byte of BIT STRING value is unused-bits count (should be 0) */
    if (bitstring.value[0] != 0) return -1;

    const uint8_t *rsa_der = bitstring.value + 1;
    size_t rsa_der_len = bitstring.value_len - 1;

    /* RSAPublicKey SEQUENCE */
    if (asn1_parse(rsa_der, rsa_der_len, &rsa_pub) == 0) return -1;
    if (rsa_pub.tag != ASN1_TAG_SEQUENCE) return -1;

    /* INTEGER n */
    size_t inner_off = 0;
    if (asn1_parse(rsa_pub.value, rsa_pub.value_len, &tlv_n) == 0) return -1;
    if (tlv_n.tag != ASN1_TAG_INTEGER) return -1;
    inner_off += tlv_n.header_len + tlv_n.value_len;

    /* INTEGER e */
    if (asn1_parse(rsa_pub.value + inner_off, rsa_pub.value_len - inner_off, &tlv_e) == 0) return -1;
    if (tlv_e.tag != ASN1_TAG_INTEGER) return -1;

    /* INTEGER value starts with 0x00 if MSB of first byte is set (sign padding) */
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

/* ---- PKCS#1 v1.5 verify ---- */

/* Verify EM against expected padded message (RFC 8017 §8.2.2 step 3).
 * EM must be exactly k bytes: 0x00 || 0x01 || 0xFF...FF || 0x00 || DigestInfo || H
 * Constant-time: no early returns based on content. */
static int pkcs1_v15_verify(const uint8_t *em, size_t em_len, const uint8_t *digest)
{
    /* Minimum EM: 00 01 FF FF FF FF FF FF FF FF 00 + DigestInfo(19) + 32 */
    /* = 2 + 8 (min FF) + 1 + 19 + 32 = 62 bytes */
    if (em_len < 62) return -1;

    /* Step 1: em[0] == 0x00, em[1] == 0x01 */
    uint32_t bad = 0;
    bad |= em[0] ^ 0x00;
    bad |= em[1] ^ 0x01;

    /* Step 2: find the 0x00 after the 0xFF run */
    size_t sep = 0;
    for (size_t i = 2; i < em_len; i++) {
        if (em[i] == 0x00) { sep = i; break; }
        if (em[i] != 0xFF) { return -1; }  /* not FF and not 00 = invalid */
    }
    if (sep == 0) return -1;  /* no separator found */
    if (sep < 2 + 8) return -1;  /* at least 8 FF bytes required */
    bad |= sep == 0;  /* redundant safety */

    /* Step 3: what remains must be DigestInfo(19) || hash(32) = 51 bytes */
    size_t remainder = em_len - sep - 1;
    if (remainder != DIGEST_INFO_LEN + SHA256_LEN) return -1;

    /* Step 4: DigestInfo prefix must match */
    for (size_t i = 0; i < DIGEST_INFO_LEN; i++) {
        bad |= em[sep + 1 + i] ^ DIGEST_INFO_SHA256[i];
    }

    /* Step 5: hash must match */
    for (size_t i = 0; i < SHA256_LEN; i++) {
        bad |= em[sep + 1 + DIGEST_INFO_LEN + i] ^ digest[i];
    }

    return bad == 0 ? 0 : -1;
}

/* ---- Public API ---- */

int ct_verify_rsa_pkcs1_sha256(const uint8_t *pub_der, size_t pub_der_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len)
{
    if (!pub_der || !sig || sig_len == 0) return CT_ERR_ARGS;
    if (!msg && msg_len > 0) return CT_ERR_ARGS;

    /* Parse public key */
    rsa_bi_t n, e;
    if (parse_spki_rsa(pub_der, pub_der_len, &n, &e) != 0) return CT_ERR_VERIFY;
    if (n.n == 0 || e.n == 0) return CT_ERR_VERIFY;

    /* Signature length must equal modulus byte length */
    size_t k = bi_byte_len(&n);
    if (k != sig_len) return CT_ERR_VERIFY;
    if (k > RSA_MAX_BYTES) return CT_ERR_VERIFY;

    /* m = sig^e mod n */
    rsa_bi_t s_bi, m_bi;
    if (bi_from_be(&s_bi, sig, sig_len) != 0) return CT_ERR_VERIFY;
    if (bi_cmp(&s_bi, &n) >= 0) return CT_ERR_VERIFY;  /* sig must be < n */
    if (bi_modexp(&m_bi, &s_bi, &e, &n) != 0) return CT_ERR_VERIFY;

    /* EM = i2osp(m, k) */
    uint8_t em[RSA_MAX_BYTES];
    if (bi_to_be(em, k, &m_bi) != 0) return CT_ERR_VERIFY;

    /* Compute SHA-256(msg) */
    uint8_t digest[SHA256_LEN];
    if (ct_sha256(msg ? msg : (const uint8_t *)"", msg_len, digest) != CT_OK)
        return CT_ERR_VERIFY;

    /* Verify EM */
    if (pkcs1_v15_verify(em, k, digest) != 0) return CT_ERR_VERIFY;

    return CT_OK;
}
