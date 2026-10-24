/** record_cbc.c — CBC record layer. See record_cbc.h. */
#include "record_cbc.h"
#include "record.h"
#include <string.h>

#define BITS ((int)(sizeof(size_t) * 8))
#define TLS_V_SSL3 0x0300
#define TLS_V_11   0x0302

/* ---- branch-free helpers (values here are small: < 2^31) ---- */
static inline size_t m_nz(size_t x)            { return (size_t)0 - ((x | ((size_t)0 - x)) >> (BITS - 1)); }
static inline size_t m_eq(size_t a, size_t b)  { return ~m_nz(a ^ b); }
static inline size_t m_lt(size_t a, size_t b)  { return (size_t)0 - ((a - b) >> (BITS - 1)); }
static inline size_t m_le(size_t a, size_t b)  { return ~m_lt(b, a); }

static const uint8_t ZEROS[1024];
static const uint8_t PAD1[48] = {
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };
static const uint8_t PAD2[48] = {
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };

int tls_record_encrypt_cbc_stub(void) { return -1; }

int tls_cbc_state_init(tls_cbc_state_t *st, uint16_t version, ctl_cbc_t cipher,
                       ctl_hash_t mac_hash, const uint8_t *key, const uint8_t *mac_key,
                       const uint8_t *implicit_iv, int etm) {
    if (!st || !key || !mac_key) return -1;
    if (version < TLS_V_SSL3 || version > 0x0303) return -1;
    size_t B = ctl_cbc_block(cipher), K = ctl_cbc_keylen(cipher), M = ctl_hash_len(mac_hash);
    if (!B || !K || !M) return -1;
    if (version == TLS_V_SSL3 && (etm || (mac_hash != CTL_MD5 && mac_hash != CTL_SHA1))) return -1;
    if (version <= 0x0301 && !implicit_iv) return -1;
    memset(st, 0, sizeof *st);
    st->version = version; st->cipher = cipher; st->mac_hash = mac_hash; st->etm = etm ? 1 : 0;
    st->block = B; st->key_len = K; st->mac_len = M;
    memcpy(st->key, key, K);
    memcpy(st->mac_key, mac_key, M);
    if (version <= 0x0301) memcpy(st->iv, implicit_iv, B);
    return 0;
}

void tls_cbc_state_wipe(tls_cbc_state_t *st) { if (st) ctl_wipe(st, sizeof *st); }
int  tls_cbc_needs_split(const tls_cbc_state_t *st) { return st && st->version <= 0x0301; }

/* Record MAC. TLS: HMAC(k, seq|type|ver|len|data). SSL3: H(k|pad2|H(k|pad1|seq|type|len|data)).
 * For EtM the caller passes data = IV||ciphertext and dlen = its length. */
static int mac_compute(const tls_cbc_state_t *st, uint8_t type, uint16_t ver, uint64_t seq,
                       const uint8_t *data, size_t dlen, uint8_t *out) {
    uint8_t hdr[13];
    size_t hl;
    for (int i = 0; i < 8; i++) hdr[i] = (uint8_t)(seq >> (56 - 8 * i));
    hdr[8] = type;
    if (st->version == TLS_V_SSL3) {
        hdr[9] = (uint8_t)(dlen >> 8); hdr[10] = (uint8_t)dlen; hl = 11;
        size_t padn = st->mac_hash == CTL_MD5 ? 48 : 40, M = st->mac_len;
        uint8_t inner[20];
        ctl_part_t a[4] = { { st->mac_key, M }, { PAD1, padn }, { hdr, hl }, { data, dlen } };
        if (ctl_hash_parts(st->mac_hash, a, 4, inner)) return -1;
        ctl_part_t b[3] = { { st->mac_key, M }, { PAD2, padn }, { inner, M } };
        return ctl_hash_parts(st->mac_hash, b, 3, out);
    }
    hdr[9] = (uint8_t)(ver >> 8); hdr[10] = (uint8_t)ver;
    hdr[11] = (uint8_t)(dlen >> 8); hdr[12] = (uint8_t)dlen; hl = 13;
    ctl_part_t p[2] = { { hdr, hl }, { data, dlen } };
    return ctl_hmac_parts(st->mac_hash, st->mac_key, st->mac_len, p, 2, out);
}

int tls_record_encrypt_cbc_with_iv(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                                   const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap,
                                   const uint8_t *fixed_iv) {
    if (!st || !out || (!pt && pt_len) || pt_len > TLS_MAX_PLAINTEXT) return -1;
    const size_t B = st->block, M = st->mac_len;
    const int expl = st->version >= TLS_V_11;
    const size_t ivlen = expl ? B : 0;
    uint8_t wb[TLS_MAX_PLAINTEXT + 48 + 256 + 16];
    uint8_t mac[48], iv[16];
    size_t n, padlen, total;

    if (expl) {
        if (fixed_iv) memcpy(iv, fixed_iv, B);
        else if (ctl_random(iv, B)) return -1;
    } else memcpy(iv, st->iv, B);

    memcpy(wb, pt, pt_len);
    n = pt_len;
    if (!st->etm) {
        if (mac_compute(st, type, rec_version, st->seq, pt, pt_len, mac)) return -1;
        memcpy(wb + n, mac, M); n += M;
    }
    padlen = (B - ((n + 1) % B)) % B;
    memset(wb + n, (int)padlen, padlen + 1);
    total = n + padlen + 1;

    size_t body = ivlen + total + (st->etm ? M : 0);
    if (body > out_cap) { ctl_wipe(wb, sizeof wb); return -1; }

    if (expl) memcpy(out, iv, B);
    if (ctl_cbc_crypt(st->cipher, 1, st->key, iv, wb, total, out + ivlen)) {
        ctl_wipe(wb, sizeof wb); return -1;
    }
    if (st->etm) {
        if (mac_compute(st, type, rec_version, st->seq, out, ivlen + total, mac)) {
            ctl_wipe(wb, sizeof wb); return -1;
        }
        memcpy(out + ivlen + total, mac, M);
    }
    if (!expl) memcpy(st->iv, out + total - B, B);      /* chain: last ciphertext block */
    st->seq++;
    ctl_wipe(wb, sizeof wb);
    return (int)body;
}

int tls_record_encrypt_cbc(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                           const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap) {
    return tls_record_encrypt_cbc_with_iv(st, type, rec_version, pt, pt_len, out, out_cap, NULL);
}

int tls_record_decrypt_cbc(tls_cbc_state_t *st, uint8_t type, uint16_t rec_version,
                           const uint8_t *body, size_t body_len, uint8_t *out, size_t out_cap) {
    if (!st || !body || !out || body_len > TLS_CBC_MAX_BODY) return -1;
    const size_t B = st->block, M = st->mac_len;
    const int expl = st->version >= TLS_V_11;
    const size_t ivlen = expl ? B : 0;
    uint8_t plain[TLS_CBC_MAX_BODY];
    uint8_t mac[48], rmac[48], dummy[48];
    const uint8_t *iv = expl ? body : st->iv;
    int ret = -1;

    if (st->etm) {
        /* Verify first: every byte checked is public, so timing reveals nothing. */
        if (body_len < ivlen + B + M) return -1;
        size_t macpos = body_len - M, enc_len = macpos - ivlen;
        if (enc_len % B) return -1;
        if (mac_compute(st, type, rec_version, st->seq, body, macpos, mac)) return -1;
        if (!ctl_eq(mac, body + macpos, M)) return -1;
        if (ctl_cbc_crypt(st->cipher, 0, st->key, iv, body + ivlen, enc_len, plain)) goto out;
        size_t padlen = plain[enc_len - 1];
        if (padlen + 1 > enc_len) goto out;
        if (st->version != TLS_V_SSL3)
            for (size_t j = 0; j <= padlen; j++) if (plain[enc_len - 1 - j] != padlen) goto out;
        size_t d = enc_len - padlen - 1;
        if (d > TLS_MAX_PLAINTEXT || d > out_cap) goto out;
        memcpy(out, plain, d);
        ret = (int)d;
        goto done;
    }

    /* ---- MAC-then-encrypt ---- */
    if (body_len < ivlen + B) return -1;
    size_t L = body_len - ivlen;
    if ((L % B) || L < M + 1) return -1;               /* lengths are public */
    if (ctl_cbc_crypt(st->cipher, 0, st->key, iv, body + ivlen, L, plain)) goto out;

    const size_t base = L - M - 1;                     /* data length if padlen == 0 */
    size_t padlen = plain[L - 1];
    size_t maxpad = base < 255 ? base : 255;
    size_t bad = ~m_le(padlen, maxpad);
    if (st->version == TLS_V_SSL3) {
        bad |= ~m_lt(padlen, B);                       /* SSL3: pad must fit in one block */
    } else {
        size_t acc = 0;
        for (size_t j = 0; j <= maxpad; j++)
            acc |= m_le(j, padlen) & (size_t)(plain[L - 1 - j] ^ (uint8_t)padlen);
        bad |= m_nz(acc & 0xff);
    }
    size_t pe = padlen & ~bad;                         /* bad padding -> behave as padlen 0 */
    size_t d = base - pe;

    /* received MAC, fetched without a secret-dependent address */
    memset(rmac, 0, sizeof rmac);
    for (size_t c = 0; c <= maxpad; c++) {
        uint8_t m = (uint8_t)m_eq(c, pe);
        for (size_t j = 0; j < M; j++) rmac[j] |= (uint8_t)(plain[base - c + j] & m);
    }

    int mr = mac_compute(st, type, rec_version, st->seq, plain, d, mac);

    /* Balance compression count: real + dummy blocks are the same for every d. */
#ifndef CRISPTLS_CBC_NO_BALANCE
    {
        size_t Bh = ctl_hash_block(st->mac_hash), sh = Bh == 128 ? 7 : 6, Lh = Bh == 128 ? 17 : 9;
        size_t pre = st->version == TLS_V_SSL3 ? M + (st->mac_hash == CTL_MD5 ? 48 : 40) + 11 : Bh + 13;
        size_t bl_real = (pre + d + Lh + Bh - 1) >> sh;
        size_t bl_max  = (pre + base + Lh + Bh - 1) >> sh;
        size_t k = bl_max - bl_real + 3;
        size_t e = (k << sh) - Lh;
        volatile uint8_t sink;
        if (e <= sizeof ZEROS && !ctl_hash(st->mac_hash, ZEROS, e, dummy)) sink = dummy[0];
        (void)sink;
    }
#endif

    size_t fail = bad | m_nz((size_t)(mr != 0)) | m_nz((size_t)!ctl_eq(mac, rmac, M))
                | ~m_le(d, TLS_MAX_PLAINTEXT) | ~m_le(d, out_cap);
    if (fail) goto out;
    memcpy(out, plain, d);
    ret = (int)d;

done:
    if (!expl) memcpy(st->iv, body + (st->etm ? body_len - M : body_len) - B, B);   /* last ciphertext block */
    st->seq++;
out:
    ctl_wipe(plain, sizeof plain);
    return ret;
}

/* ---- suite table ---- */
#define S(id, c, m, kx, v, t) { id, c, m, kx, v, t }
static const tls_cbc_suite_t SUITES[] = {
    S(0x002F, CTL_AES128_CBC, CTL_SHA1,   TLS_KX_RSA,         0x0300, 0),
    S(0x0035, CTL_AES256_CBC, CTL_SHA1,   TLS_KX_RSA,         0x0300, 0),
    S(0x003C, CTL_AES128_CBC, CTL_SHA256, TLS_KX_RSA,         0x0303, 0),
    S(0x003D, CTL_AES256_CBC, CTL_SHA256, TLS_KX_RSA,         0x0303, 0),
    S(0x000A, CTL_3DES_CBC,   CTL_SHA1,   TLS_KX_RSA,         0x0300, 1),
    S(0x0033, CTL_AES128_CBC, CTL_SHA1,   TLS_KX_DHE_RSA,     0x0300, 0),
    S(0x0039, CTL_AES256_CBC, CTL_SHA1,   TLS_KX_DHE_RSA,     0x0300, 0),
    S(0x0067, CTL_AES128_CBC, CTL_SHA256, TLS_KX_DHE_RSA,     0x0303, 0),
    S(0x006B, CTL_AES256_CBC, CTL_SHA256, TLS_KX_DHE_RSA,     0x0303, 0),
    S(0x0016, CTL_3DES_CBC,   CTL_SHA1,   TLS_KX_DHE_RSA,     0x0300, 1),
    S(0xC013, CTL_AES128_CBC, CTL_SHA1,   TLS_KX_ECDHE_RSA,   0x0301, 0),
    S(0xC014, CTL_AES256_CBC, CTL_SHA1,   TLS_KX_ECDHE_RSA,   0x0301, 0),
    S(0xC027, CTL_AES128_CBC, CTL_SHA256, TLS_KX_ECDHE_RSA,   0x0303, 0),
    S(0xC028, CTL_AES256_CBC, CTL_SHA384, TLS_KX_ECDHE_RSA,   0x0303, 0),
    S(0xC012, CTL_3DES_CBC,   CTL_SHA1,   TLS_KX_ECDHE_RSA,   0x0301, 1),
    S(0xC009, CTL_AES128_CBC, CTL_SHA1,   TLS_KX_ECDHE_ECDSA, 0x0301, 0),
    S(0xC00A, CTL_AES256_CBC, CTL_SHA1,   TLS_KX_ECDHE_ECDSA, 0x0301, 0),
    S(0xC023, CTL_AES128_CBC, CTL_SHA256, TLS_KX_ECDHE_ECDSA, 0x0303, 0),
    S(0xC024, CTL_AES256_CBC, CTL_SHA384, TLS_KX_ECDHE_ECDSA, 0x0303, 0),
    S(0xC008, CTL_3DES_CBC,   CTL_SHA1,   TLS_KX_ECDHE_ECDSA, 0x0301, 1),
};

const tls_cbc_suite_t *tls_cbc_suite_lookup(uint16_t suite) {
    for (size_t i = 0; i < sizeof SUITES / sizeof SUITES[0]; i++)
        if (SUITES[i].suite == suite) return &SUITES[i];
    return NULL;
}
