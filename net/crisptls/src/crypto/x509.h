/* x509.h — RFC 5280 certificate parsing and validation. */
#ifndef CT_X509_H
#define CT_X509_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Maximum lengths we keep in fixed buffers. Certificates containing larger
 * fields are rejected as CT_X509_ERR_TOO_LONG rather than truncated. */
#define CT_X509_MAX_NAME     512    /* canonical DN string */
#define CT_X509_MAX_SAN      64     /* number of DNS SANs */
#define CT_X509_MAX_SAN_LEN  256    /* bytes per DNS SAN */
#define CT_X509_MAX_CN       256    /* common name length */
#define CT_X509_MAX_SIG      1024   /* signature blob */
#define CT_X509_MAX_SPKI     1024   /* SPKI DER blob */

/* Error codes. Every function that can fail returns one of these. */
typedef enum {
    CT_X509_OK = 0,
    CT_X509_ERR_ARGS,           /* NULL pointer or zero-length input */
    CT_X509_ERR_PARSE,          /* malformed DER */
    CT_X509_ERR_TOO_LONG,       /* field exceeds fixed buffer */
    CT_X509_ERR_NO_SPKI,        /* certificate has no SPKI */
    CT_X509_ERR_NO_SIG,         /* certificate has no signature */
    CT_X509_ERR_NO_VALIDITY,    /* certificate has no validity field */
    CT_X509_ERR_UNSUPPORTED     /* algorithm we don't implement */
} ct_x509_err;

/* Parsed certificate. All fields are fixed-size; no heap allocation.
 *
 * The DER blobs (spki_der, sig) are references into the original cert
 * buffer — the caller must keep it alive for the lifetime of this struct. */
typedef struct {
    /* Issuer and subject as canonical DN strings ("CN=...,O=...;"). */
    char    subject[CT_X509_MAX_NAME];
    size_t  subject_len;
    char    issuer[CT_X509_MAX_NAME];
    size_t  issuer_len;

    /* Validity window as seconds since Unix epoch. */
    time_t  not_before;
    time_t  not_after;

    /* Subject Common Name (first CN found), empty if none. */
    char    cn[CT_X509_MAX_CN];
    size_t  cn_len;

    /* Subject Alternative Name DNS entries. */
    char    san[CT_X509_MAX_SAN][CT_X509_MAX_SAN_LEN];
    size_t  san_len[CT_X509_MAX_SAN];
    size_t  san_count;

    /* SubjectPublicKeyInfo DER blob (points into original cert). */
    const uint8_t *spki_der;
    size_t         spki_len;

    /* Signature algorithm OID (dotted decimal) + signature blob (points
     * into original cert). */
    char           sigalg_oid[64];
    const uint8_t *sig;
    size_t         sig_len;

    /* TBSCertificate DER blob (needed for signature verify — the sig is
     * computed over this, not the whole cert). Points into original cert. */
    const uint8_t *tbs_der;
    size_t         tbs_len;

    /* Flags */
    uint8_t is_ca;              /* basicConstraints CA:TRUE */
} ct_x509_cert;

/* Parse one DER certificate into `out`. `der` must be the complete
 * SEQUENCE (i.e. what d2i_X509 would accept). Returns CT_X509_OK or error. */
ct_x509_err ct_x509_parse(const uint8_t *der, size_t der_len, ct_x509_cert *out);

/* Return 1 if `now` is within [not_before, not_after], else 0. */
int ct_x509_time_valid(const ct_x509_cert *c, time_t now);

/* Return 1 if `host` matches any SAN DNS entry or the CN fallback. */
int ct_x509_hostname_matches(const ct_x509_cert *c, const char *host, size_t host_len);

/* Return 1 if `subj` and `iss` are the same Distinguished Name per RFC
 * 5280 §7.1 normalization. */
int ct_x509_name_equal(const char *a, size_t alen, const char *b, size_t blen);

/* Signature verification. Returns CT_OK (0) on success, or a crypto.h
 * error code. Caller chooses the algorithm based on `sigalg_oid`. */
int ct_x509_verify_sig(const ct_x509_cert *c, const ct_x509_cert *issuer);

/* Static name for an error code. Never NULL. */
const char *ct_x509_err_name(ct_x509_err e);

#endif
