/* x509.c — RFC 5280 certificate parsing and validation. No OpenSSL. */
#include "x509.h"
#include "asn1.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* OIDs for signature algorithms we recognise. */
static const char OID_RSA_PSS_SHA256[] = "1.2.840.113549.1.1.10";  /* RSASSA-PSS */
static const char OID_ECDSA_P256_SHA256[] = "1.2.840.10045.4.3.2";
#define T_SEQ  0x30
#define T_SET  0x31
#define T_INT  0x02
#define T_OID  0x06
#define T_BIT  0x03
#define T_OCT  0x04
#define T_BOOL 0x01
#define T_UTC  0x17
#define T_GEN  0x18
#define T_UTF8 0x0C
#define T_PRNT 0x13
#define T_IA5  0x16
#define T_CTX0 0xA0
#define T_CTX1 0xA1
#define T_CTX2 0xA2
#define T_CTX3 0xA3

/* ---- Time parsing (RFC 5280 §4.1.2.5) ---- */
static time_t parse_asn1_time(const uint8_t *v, size_t vlen, int is_gen) {
    /* UTCTime: YYMMDDHHMMSSZ (13 chars, offset optional)
     * GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars) */
    char buf[32];
    size_t n = vlen < sizeof(buf) - 1 ? vlen : sizeof(buf) - 1;
    memcpy(buf, v, n);
    buf[n] = 0;
    if (n > 0 && buf[n-1] == 'Z') buf[--n] = 0;
    /* strip fractional seconds if present (rare) */
    for (size_t i = 0; i < n; i++) if (buf[i] == '.') { buf[i] = 0; n = i; break; }
    for (size_t i = 0; i < n; i++) if (buf[i] < '0' || buf[i] > '9') return -1;

    struct tm tm = {0};
    if (is_gen) {
        if (n < 14) return -1;
        tm.tm_year = (buf[0]-'0')*1000 + (buf[1]-'0')*100 + (buf[2]-'0')*10 + (buf[3]-'0') - 1900;
        tm.tm_mon  = (buf[4]-'0')*10 + (buf[5]-'0') - 1;
        tm.tm_mday = (buf[6]-'0')*10 + (buf[7]-'0');
        tm.tm_hour = (buf[8]-'0')*10 + (buf[9]-'0');
        tm.tm_min  = (buf[10]-'0')*10 + (buf[11]-'0');
        tm.tm_sec  = (buf[12]-'0')*10 + (buf[13]-'0');
    } else {
        if (n < 12) return -1;
        int yy = (buf[0]-'0')*10 + (buf[1]-'0');
        /* RFC 5280 §4.1.2.5.1: YY >= 50 → 19YY; else 20YY */
        tm.tm_year = (yy >= 50 ? 1900 + yy : 2000 + yy) - 1900;
        tm.tm_mon  = (buf[2]-'0')*10 + (buf[3]-'0') - 1;
        tm.tm_mday = (buf[4]-'0')*10 + (buf[5]-'0');
        tm.tm_hour = (buf[6]-'0')*10 + (buf[7]-'0');
        tm.tm_min  = (buf[8]-'0')*10 + (buf[9]-'0');
        tm.tm_sec  = (buf[10]-'0')*10 + (buf[11]-'0');
    }
    return timegm(&tm);
}

/* ---- Name canonicalization ---- */
static void normalize_dn_str(char *s) {
    for (char *p = s; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
    char *p = s; while (*p == ' ') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && s[n-1] == ' ') s[--n] = 0;
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == ' ' && w > s && w[-1] == ' ') continue;
        *w++ = *r;
    }
    *w = 0;
}

/* Extract RDN attribute values as canonical "oid=value;" list. */
static int extract_name(const uint8_t *buf, size_t len, char *out, size_t cap) {
    asn1_tlv seq;
    if (asn1_parse(buf, len, &seq) == 0 || seq.tag != T_SEQ) return 0;
    size_t w = 0;
    size_t off = 0;
    while (off < seq.value_len) {
        asn1_tlv set;
        size_t c1 = asn1_parse(seq.value + off, seq.value_len - off, &set);
        if (c1 == 0 || set.tag != T_SET) return 0;
        size_t soff = 0;
        while (soff < set.value_len) {
            asn1_tlv pair;
            size_t c2 = asn1_parse(set.value + soff, set.value_len - soff, &pair);
            if (c2 == 0 || pair.tag != T_SEQ) return 0;
            char oidbuf[64];
            if (asn1_read_oid(pair.value, pair.value_len, oidbuf, sizeof oidbuf) == 0) return 0;
            asn1_tlv oid, val;
            size_t c3 = asn1_parse(pair.value, pair.value_len, &oid);
            if (c3 == 0) return 0;
            size_t c4 = asn1_parse(pair.value + c3, pair.value_len - c3, &val);
            if (c4 == 0) return 0;
            char vb[256] = {0};
            if (val.tag == T_UTF8 || val.tag == T_PRNT || val.tag == T_IA5) {
                size_t n = val.value_len < sizeof vb - 1 ? val.value_len : sizeof vb - 1;
                memcpy(vb, val.value, n);
                vb[n] = 0;
                normalize_dn_str(vb);
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

int ct_x509_name_equal(const char *a, size_t alen, const char *b, size_t blen) {
    if (alen != blen) return 0;
    return memcmp(a, b, alen) == 0;
}

/* ---- Extension parsing (RFC 5280 §4.2) ---- */

/* subjectAltName: SEQUENCE of GeneralName, each [2] dNSName is IA5String. */
static void parse_san(const uint8_t *buf, size_t len, ct_x509_cert *out) {
    asn1_tlv seq;
    if (asn1_parse(buf, len, &seq) == 0 || seq.tag != T_SEQ) return;
    size_t off = 0;
    while (off < seq.value_len && out->san_count < CT_X509_MAX_SAN) {
        asn1_tlv gn;
        size_t c = asn1_parse(seq.value + off, seq.value_len - off, &gn);
        if (c == 0) return;
        if (gn.tag == 0x82) {  /* context [2] PRIMITIVE = dNSName */
            size_t n = gn.value_len < CT_X509_MAX_SAN_LEN - 1 ? gn.value_len : CT_X509_MAX_SAN_LEN - 1;
            memcpy(out->san[out->san_count], gn.value, n);
            out->san[out->san_count][n] = 0;
            out->san_len[out->san_count] = n;
            out->san_count++;
        }
        off += c;
    }
}

/* basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL } */
static void parse_basic_constraints(const uint8_t *buf, size_t len, ct_x509_cert *out) {
    asn1_tlv seq;
    if (asn1_parse(buf, len, &seq) == 0 || seq.tag != T_SEQ) return;
    size_t off = 0;
    while (off < seq.value_len) {
        asn1_tlv f;
        size_t c = asn1_parse(seq.value + off, seq.value_len - off, &f);
        if (c == 0) return;
        if (f.tag == T_BOOL && f.value_len == 1 && f.value[0] != 0) {
            out->is_ca = 1;
        }
        off += c;
    }
}

/* Iterate extensions: SEQUENCE of SEQUENCE { OID, [critical BOOLEAN], OCTET STRING } */
static void parse_extensions(const uint8_t *buf, size_t len, ct_x509_cert *out) {
    asn1_tlv seq;
    if (asn1_parse(buf, len, &seq) == 0 || seq.tag != T_SEQ) return;
    size_t off = 0;
    while (off < seq.value_len) {
        asn1_tlv ext;
        size_t c = asn1_parse(seq.value + off, seq.value_len - off, &ext);
        if (c == 0 || ext.tag != T_SEQ) return;
        char oidbuf[64];
        if (asn1_read_oid(ext.value, ext.value_len, oidbuf, sizeof oidbuf) == 0) { off += c; continue; }
        asn1_tlv oid;
        size_t c1 = asn1_parse(ext.value, ext.value_len, &oid);
        if (c1 == 0) { off += c; continue; }
        size_t eoff = c1;
        asn1_tlv maybe_bool;
        if (eoff < ext.value_len) {
            size_t c2 = asn1_parse(ext.value + eoff, ext.value_len - eoff, &maybe_bool);
            if (c2 > 0 && maybe_bool.tag == T_BOOL) eoff += c2;
        }
        asn1_tlv val;
        if (eoff >= ext.value_len) { off += c; continue; }
        if (asn1_parse(ext.value + eoff, ext.value_len - eoff, &val) == 0) { off += c; continue; }

        if (strcmp(oidbuf, "2.5.29.17") == 0) {          /* subjectAltName */
            parse_san(val.value, val.value_len, out);
        } else if (strcmp(oidbuf, "2.5.29.19") == 0) {   /* basicConstraints */
            parse_basic_constraints(val.value, val.value_len, out);
        }
        off += c;
    }
}

/* ---- Main parse ---- */
ct_x509_err ct_x509_parse(const uint8_t *der, size_t der_len, ct_x509_cert *out) {
    if (!der || !out || der_len == 0) return CT_X509_ERR_ARGS;
    memset(out, 0, sizeof(*out));

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature } */
    asn1_tlv cert, tbs, sigalg, sig;
    size_t consumed = asn1_parse(der, der_len, &cert);
    if (consumed == 0 || cert.tag != T_SEQ) return CT_X509_ERR_PARSE;

    size_t c1 = asn1_parse(cert.value, cert.value_len, &tbs);
    if (c1 == 0 || tbs.tag != T_SEQ) return CT_X509_ERR_PARSE;
    size_t c2 = asn1_parse(cert.value + c1, cert.value_len - c1, &sigalg);
    if (c2 == 0 || sigalg.tag != T_SEQ) return CT_X509_ERR_PARSE;
    size_t c3 = asn1_parse(cert.value + c1 + c2, cert.value_len - c1 - c2, &sig);
    if (c3 == 0 || sig.tag != T_BIT) return CT_X509_ERR_PARSE;

    out->tbs_der = cert.value;
    out->tbs_len = c1;

    /* signatureAlgorithm: SEQUENCE { OID } */
    if (asn1_read_oid(sigalg.value, sigalg.value_len, out->sigalg_oid, sizeof out->sigalg_oid) == 0)
        return CT_X509_ERR_PARSE;

    /* signature BIT STRING: first byte is unused-bits count; skip it. */
    if (sig.value_len < 1) return CT_X509_ERR_NO_SIG;
    if (sig.value_len - 1 > CT_X509_MAX_SIG) return CT_X509_ERR_TOO_LONG;
    out->sig = sig.value + 1;
    out->sig_len = sig.value_len - 1;

    /* TBSCertificate ::= SEQUENCE {
     *   [0] version, serialNumber INTEGER, signature SEQ,
     *   issuer Name, validity SEQ, subject Name, spki SEQ, [extensions [3]] }
     */
    size_t toff = 0;
    asn1_tlv f;
    if (asn1_parse(tbs.value, tbs.value_len, &f) == 0) return CT_X509_ERR_PARSE;
    if (f.tag == T_CTX0) toff += asn1_parse(tbs.value, tbs.value_len, &f);
    asn1_tlv serial, sigalg2, issuer, validity, subject, spki, extensions;
    size_t cc;
    if (toff >= tbs.value_len) return CT_X509_ERR_PARSE;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &serial); toff += cc;
    if (cc == 0) return CT_X509_ERR_PARSE;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &sigalg2); toff += cc;
    if (cc == 0) return CT_X509_ERR_PARSE;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &issuer); toff += cc;
    if (cc == 0 || issuer.tag != T_SEQ) return CT_X509_ERR_PARSE;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &validity); toff += cc;
    if (cc == 0 || validity.tag != T_SEQ) return CT_X509_ERR_NO_VALIDITY;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &subject); toff += cc;
    if (cc == 0 || subject.tag != T_SEQ) return CT_X509_ERR_PARSE;
    cc = asn1_parse(tbs.value + toff, tbs.value_len - toff, &spki); toff += cc;
    if (cc == 0 || spki.tag != T_SEQ) return CT_X509_ERR_NO_SPKI;

    out->spki_der = tbs.value + toff - cc;
    out->spki_len = cc;

    /* issuer / subject as canonical DN strings */
    if (!extract_name(issuer.value - issuer.header_len, issuer.header_len + issuer.value_len,
                      out->issuer, sizeof out->issuer))
        return CT_X509_ERR_TOO_LONG;
    out->issuer_len = strlen(out->issuer);
    if (!extract_name(subject.value - subject.header_len, subject.header_len + subject.value_len,
                      out->subject, sizeof out->subject))
        return CT_X509_ERR_TOO_LONG;
    out->subject_len = strlen(out->subject);

    /* validity: SEQUENCE { notBefore Time, notAfter Time } */
    asn1_tlv nb, na;
    size_t vc1 = asn1_parse(validity.value, validity.value_len, &nb);
    size_t vc2 = asn1_parse(validity.value + vc1, validity.value_len - vc1, &na);
    if (vc1 == 0 || vc2 == 0) return CT_X509_ERR_NO_VALIDITY;
    out->not_before = parse_asn1_time(nb.value, nb.value_len, nb.tag == T_GEN);
    out->not_after  = parse_asn1_time(na.value, na.value_len, na.tag == T_GEN);

    /* CN — walk subject RDNs looking for OID 2.5.4.3 */
    {
        asn1_tlv subjseq;
        if (asn1_parse(subject.value - subject.header_len,
                       subject.header_len + subject.value_len, &subjseq) > 0) {
            size_t off = 0;
            while (off < subjseq.value_len) {
                asn1_tlv set;
                size_t sc = asn1_parse(subjseq.value + off, subjseq.value_len - off, &set);
                if (sc == 0) break;
                size_t soff = 0;
                while (soff < set.value_len) {
                    asn1_tlv pair;
                    size_t pc = asn1_parse(set.value + soff, set.value_len - soff, &pair);
                    if (pc == 0) break;
                    char oidbuf[64];
                    if (asn1_read_oid(pair.value, pair.value_len, oidbuf, sizeof oidbuf) > 0) {
                        if (strcmp(oidbuf, "2.5.4.3") == 0) {
                            asn1_tlv oid, val;
                            size_t oc = asn1_parse(pair.value, pair.value_len, &oid);
                            if (oc > 0) {
                                size_t vc = asn1_parse(pair.value + oc, pair.value_len - oc, &val);
                                if (vc > 0 && (val.tag == T_UTF8 || val.tag == T_PRNT || val.tag == T_IA5)) {
                                    size_t n = val.value_len < sizeof out->cn - 1 ? val.value_len : sizeof out->cn - 1;
                                    memcpy(out->cn, val.value, n);
                                    out->cn[n] = 0;
                                    out->cn_len = n;
                                    break;
                                }
                            }
                        }
                    }
                    soff += pc;
                }
                if (out->cn_len) break;
                off += sc;
            }
        }
    }

    /* Extensions: optional [3] EXPLICIT */
    if (toff < tbs.value_len) {
        size_t cc2 = asn1_parse(tbs.value + toff, tbs.value_len - toff, &extensions);
        if (cc2 > 0 && extensions.tag == T_CTX3) {
            parse_extensions(extensions.value, extensions.value_len, out);
        }
    }

    return CT_X509_OK;
}

int ct_x509_time_valid(const ct_x509_cert *c, time_t now) {
    if (!c) return 0;
    return c->not_before <= now && now <= c->not_after;
}

/* RFC 6125 hostname match. */
int ct_x509_hostname_matches(const ct_x509_cert *c, const char *host, size_t host_len) {
    if (!c || !host) return 0;
    /* lowercase for compare */
    char hbuf[256];
    size_t hn = host_len < sizeof hbuf - 1 ? host_len : sizeof hbuf - 1;
    for (size_t i = 0; i < hn; i++) {
        char ch = host[i];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        hbuf[i] = ch;
    }
    hbuf[hn] = 0;
    for (size_t i = 0; i < c->san_count; i++) {
        const char *san = c->san[i];
        size_t sn = c->san_len[i];
        if (sn == 0) continue;
        /* wildcard: "*.example.com" matches "a.example.com" (one label only) */
        if (sn > 2 && san[0] == '*' && san[1] == '.') {
            const char *dot = strchr(hbuf, '.');
            if (dot && strcmp(dot + 1, san + 2) == 0) return 1;
        } else if (sn == hn && memcmp(san, hbuf, sn) == 0) {
            return 1;
        }
    }
    /* CN fallback only if no SAN present (RFC 6125 §6.4.4) */
    if (c->san_count == 0 && c->cn_len > 0) {
        if (c->cn_len == hn) {
            char cbuf[CT_X509_MAX_CN];
            for (size_t i = 0; i < c->cn_len; i++) {
                char ch = c->cn[i];
                if (ch >= 'A' && ch <= 'Z') ch += 32;
                cbuf[i] = ch;
            }
            if (memcmp(cbuf, hbuf, hn) == 0) return 1;
        }
    }
    return 0;
}

/* Extract raw pubkey bytes from SPKI. SPKI ::= SEQUENCE { algid SEQ, BIT STRING }.
 * Returns 1 on success. On success, *out and *out_len point into spki_der; alg_oid
 * is filled with the algorithm OID (dotted decimal). Returns 0 on error. */
static int spki_extract_raw(const uint8_t *spki_der, size_t spki_len,
                            const uint8_t **out, size_t *out_len,
                            char *alg_oid, size_t cap) {
    asn1_tlv spki, alg, bits;
    if (asn1_parse(spki_der, spki_len, &spki) == 0 || spki.tag != T_SEQ) return 0;
    size_t c1 = asn1_parse(spki.value, spki.value_len, &alg);
    if (c1 == 0 || alg.tag != T_SEQ) return 0;
    if (asn1_read_oid(alg.value, alg.value_len, alg_oid, cap) == 0) return 0;
    size_t c2 = asn1_parse(spki.value + c1, spki.value_len - c1, &bits);
    if (c2 == 0 || bits.tag != T_BIT || bits.value_len < 1) return 0;
    *out = bits.value + 1;
    *out_len = bits.value_len - 1;
    return 1;
}

int ct_x509_verify_sig(const ct_x509_cert *c, const ct_x509_cert *issuer) {
    if (!c || !issuer) return CT_ERR_ARGS;
    if (!issuer->spki_der || issuer->spki_len == 0) return CT_ERR_ARGS;
    if (!c->sig || c->sig_len == 0) return CT_ERR_ARGS;

    /* Verify functions expect full SPKI DER (not the extracted raw key
     * bits). parse_spki_p256 hard-checks the exact 91-byte P-256 SPKI
     * prefix; crypto_ec.c calls d2i_PUBKEY which also wants SPKI DER. */
    if (strcmp(c->sigalg_oid, OID_RSA_PSS_SHA256) == 0) {
        return ct_verify_rsa_pss_sha256(issuer->spki_der, issuer->spki_len,
                                        c->tbs_der, c->tbs_len,
                                        c->sig, c->sig_len);
    }
    if (strcmp(c->sigalg_oid, OID_ECDSA_P256_SHA256) == 0) {
        return ct_verify_ecdsa_p256_sha256(issuer->spki_der, issuer->spki_len,
                                           c->tbs_der, c->tbs_len,
                                           c->sig, c->sig_len);
    }
    /* P-384 and Ed25519 deferred to crypto_ec.c native rewrite. */
    return CT_X509_ERR_UNSUPPORTED;
}

const char *ct_x509_err_name(ct_x509_err e) {
    switch (e) {
        case CT_X509_OK:              return "ok";
        case CT_X509_ERR_ARGS:        return "args";
        case CT_X509_ERR_PARSE:       return "parse";
        case CT_X509_ERR_TOO_LONG:    return "too-long";
        case CT_X509_ERR_NO_SPKI:     return "no-spki";
        case CT_X509_ERR_NO_SIG:      return "no-sig";
        case CT_X509_ERR_NO_VALIDITY: return "no-validity";
        case CT_X509_ERR_UNSUPPORTED: return "unsupported";
    }
    return "unknown";
}
