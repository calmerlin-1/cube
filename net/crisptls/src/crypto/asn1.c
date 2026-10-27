/* asn1.c — minimal DER decoder for X.509. No allocation except reads. */
#include "asn1.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Parse tag byte + length. Handles short form (len<128) and long form. */
size_t asn1_parse(const uint8_t *buf, size_t len, asn1_tlv *out) {
    if (!buf || !out || len < 2) return 0;
    uint8_t tag = buf[0];
    size_t  i = 1;
    size_t  vlen = 0;

    uint8_t l0 = buf[i++];
    if (l0 < 0x80) {
        vlen = l0;
    } else if (l0 == 0x80) {
        return 0;  /* indefinite length: not allowed in DER */
    } else {
        size_t n = l0 & 0x7F;
        if (n > 4 || i + n > len) return 0;
        for (size_t k = 0; k < n; k++) vlen = (vlen << 8) | buf[i++];
    }

    if (i + vlen > len) return 0;
    out->tag        = tag;
    out->header_len = i;
    out->value_len  = vlen;
    out->value      = buf + i;
    return i + vlen;
}

size_t asn1_next(const uint8_t *buf, size_t len, size_t off) {
    if (off >= len) return 0;
    asn1_tlv t;
    size_t c = asn1_parse(buf + off, len - off, &t);
    if (c == 0) return 0;
    return off + c;
}

size_t asn1_read_uint64(const uint8_t *buf, size_t len, uint64_t *out) {
    asn1_tlv t;
    size_t c = asn1_parse(buf, len, &t);
    if (c == 0 || t.tag != ASN1_TAG_INTEGER) return 0;
    if (t.value_len == 0 || t.value_len > 9) return 0;
    /* Skip leading 0x00 (unsigned padding) */
    const uint8_t *v = t.value;
    size_t vlen = t.value_len;
    while (vlen > 1 && v[0] == 0x00) { v++; vlen--; }
    if (vlen > 8) return 0;
    uint64_t r = 0;
    for (size_t i = 0; i < vlen; i++) r = (r << 8) | v[i];
    *out = r;
    return c;
}

size_t asn1_read_oid(const uint8_t *buf, size_t len, char *out, size_t cap) {
    asn1_tlv t;
    size_t c = asn1_parse(buf, len, &t);
    if (c == 0 || t.tag != ASN1_TAG_OID || t.value_len == 0 || cap == 0) return 0;

    const uint8_t *v = t.value;
    size_t vlen = t.value_len;
    size_t w = 0;

    /* First byte: X*40 + Y */
    uint32_t first = v[0];
    if (first < 40) {
        w += (size_t)snprintf(out + w, cap - w, "0.%u", (unsigned)first);
    } else if (first < 80) {
        w += (size_t)snprintf(out + w, cap - w, "1.%u", (unsigned)(first - 40));
    } else {
        w += (size_t)snprintf(out + w, cap - w, "2.%u", (unsigned)(first - 80));
    }
    if (w >= cap) return 0;

    /* Remaining bytes: base-128 varints */
    uint64_t acc = 0;
    for (size_t i = 1; i < vlen; i++) {
        acc = (acc << 7) | (v[i] & 0x7F);
        if (!(v[i] & 0x80)) {
            int k = snprintf(out + w, cap - w, ".%llu", (unsigned long long)acc);
            if (k < 0 || (size_t)k >= cap - w) return 0;
            w += (size_t)k;
            acc = 0;
        }
    }
    return c;
}

size_t asn1_read_string(const uint8_t *buf, size_t len, char *out, size_t cap) {
    asn1_tlv t;
    size_t c = asn1_parse(buf, len, &t);
    if (c == 0 || cap == 0) return 0;
    if (t.tag != ASN1_TAG_UTF8STRING && t.tag != ASN1_TAG_PRINTABLE_STR &&
        t.tag != ASN1_TAG_IA5STRING)
        return 0;
    size_t n = t.value_len < cap - 1 ? t.value_len : cap - 1;
    memcpy(out, t.value, n);
    out[n] = 0;
    return c;
}

/* RFC 5280 §7.1 name comparison: normalize each RDN's string bytes
 * (lowercase, strip leading/trailing space, collapse inner whitespace). */
static void normalize_str(char *s) {
    /* lowercase */
    for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
    /* strip leading */
    char *p = s;
    while (*p == ' ') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    /* strip trailing */
    size_t n = strlen(s);
    while (n > 0 && s[n-1] == ' ') s[--n] = 0;
    /* collapse inner runs */
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == ' ' && w > s && w[-1] == ' ') continue;
        *w++ = *r;
    }
    *w = 0;
}

/* Extract all attribute values from a Name (SEQUENCE of SET of SEQUENCE
 * {OID, value}) into a canonical string: "CN=x,O=y,..." (order-insensitive
 * not handled here; that requires RDN set sort, skipped for now — this is
 * adequate for the current CA bundle which uses no multi-valued RDNs). */
static int extract_name(const uint8_t *der, size_t len, char *out, size_t cap) {
    asn1_tlv seq;
    size_t c = asn1_parse(der, len, &seq);
    if (c == 0 || seq.tag != ASN1_TAG_SEQUENCE) return 0;

    size_t w = 0;
    size_t off = 0;
    while (off < seq.value_len) {
        asn1_tlv set;
        size_t c1 = asn1_parse(seq.value + off, seq.value_len - off, &set);
        if (c1 == 0 || set.tag != ASN1_TAG_SET) return 0;

        size_t soff = 0;
        while (soff < set.value_len) {
            asn1_tlv pair;
            size_t c2 = asn1_parse(set.value + soff, set.value_len - soff, &pair);
            if (c2 == 0 || pair.tag != ASN1_TAG_SEQUENCE) return 0;

            asn1_tlv oid, val;
            size_t c3 = asn1_parse(pair.value, pair.value_len, &oid);
            if (c3 == 0) return 0;
            size_t c4 = asn1_parse(pair.value + c3, pair.value_len - c3, &val);
            if (c4 == 0) return 0;

            char oidbuf[64];
            if (asn1_read_oid(pair.value, pair.value_len, oidbuf, sizeof oidbuf) == 0)
                return 0;

            char vb[256] = {0};
            if (val.tag == ASN1_TAG_UTF8STRING || val.tag == ASN1_TAG_PRINTABLE_STR ||
                val.tag == ASN1_TAG_IA5STRING) {
                size_t n = val.value_len < sizeof(vb) - 1 ? val.value_len : sizeof(vb) - 1;
                memcpy(vb, val.value, n);
                vb[n] = 0;
                normalize_str(vb);
            } else {
                snprintf(vb, sizeof vb, "<%02x:%zu>", val.tag, val.value_len);
            }

            int k = snprintf(out + w, cap - w, "%s=%s;", oidbuf, vb);
            if (k < 0 || (size_t)k >= cap - w) return 0;
            w += (size_t)k;
            soff += c2;
        }
        off += c1;
    }
    return 1;
}

int asn1_name_equal(const uint8_t *a, size_t alen,
                    const uint8_t *b, size_t blen) {
    char abuf[4096], bbuf[4096];
    if (!extract_name(a, alen, abuf, sizeof abuf)) return 0;
    if (!extract_name(b, blen, bbuf, sizeof bbuf)) return 0;
    return strcmp(abuf, bbuf) == 0;
}
