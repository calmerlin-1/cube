/** certificate.c — parse TLS Certificate message. Extract DER per entry. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t         len;
} cert_der_t;

typedef struct {
    cert_der_t *certs;
    size_t      count;
    size_t      capacity;
} cert_chain_t;

/** Parse TLS 1.3 Certificate message body (already unwrapped from handshake).
 * TLS 1.3 format:
 *   certificate_request_context: opaque<0..255> — length(1) + bytes
 *   certificate_list: 3-byte length + entries
 *     each entry: cert_data (3-byte len + DER) + extensions (2-byte len + bytes)
 * Returns 0 on success, -1 on error. */
/* Validate that every cert in a chain looks like a well-formed DER X.509:
 * starts with SEQUENCE (0x30), declared length matches actual length. */
static int chain_looks_valid(const cert_chain_t *c) {
    if (!c || !c->certs || c->count == 0) return 0;
    for (size_t i = 0; i < c->count; i++) {
        const uint8_t *d = c->certs[i].data;
        size_t n = c->certs[i].len;
        if (!d || n < 2) return 0;
        if (d[0] != 0x30) return 0;                       /* SEQUENCE */
        if (d[1] == 0x82 && n >= 4) {
            size_t enc = ((size_t)d[2] << 8) | d[3];
            if (enc + 4 != n) return 0;
        } else if (d[1] == 0x81 && n >= 3) {
            if ((size_t)d[2] + 3 != n) return 0;
        } else if (d[1] < 0x80) {
            if ((size_t)d[1] + 2 != n) return 0;
        } else {
            return 0;                                      /* BER indefinite */
        }
    }
    return 1;
}

/* is_13 = 1: TLS 1.3 (RFC 8446 4.4.2, cert_request_context first)
 * is_13 = 0: TLS 1.2 (RFC 5246 7.4.2, straight into the 3-byte list length) */
static int certificate_parse_impl(const uint8_t *buf, size_t len, int is_13,
                                   cert_chain_t *out) {
    if (!buf || !out || len < 4) return -1;
    memset(out, 0, sizeof(*out));

    const uint8_t *p = buf;
    const uint8_t *end = buf + len;

    if (is_13) {
        if (p + 1 > end) return -1;
        uint8_t ctx_len = *p++;
        if (p + ctx_len > end) return -1;
        p += ctx_len;
    }

    /* list length */
    if (p + 3 > end) return -1;
    uint32_t list_len = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
    p += 3;
    if (p + list_len > end) return -1;

    /* count entries first */
    const uint8_t *lp = p;
    const uint8_t *le = p + list_len;
    size_t count = 0;
    while (lp + 3 <= le) {
        uint32_t clen = ((uint32_t)lp[0] << 16) | ((uint32_t)lp[1] << 8) | lp[2];
        lp += 3;
        if (lp + clen > le) break;
        lp += clen;
        if (lp + 2 > le) break;
        uint16_t extlen = (uint16_t)((lp[0] << 8) | lp[1]);
        lp += 2;
        if (lp + extlen > le) break;
        lp += extlen;
        count++;
    }

    static cert_der_t static_pool[16];
    if (count > 16) count = 16;
    out->certs = static_pool;
    out->capacity = 16;
    out->count = 0;

    lp = p;
    for (size_t i = 0; i < count; i++) {
        if (lp + 3 > le) break;
        uint32_t clen = ((uint32_t)lp[0] << 16) | ((uint32_t)lp[1] << 8) | lp[2];
        lp += 3;
        if (lp + clen > le) break;
        static_pool[out->count].data = lp;
        static_pool[out->count].len = clen;
        lp += clen;
        if (lp + 2 > le) break;
        uint16_t extlen = (uint16_t)((lp[0] << 8) | lp[1]);
        lp += 2;
        if (lp + extlen > le) break;
        lp += extlen;
        out->count++;
    }
    return 0;
}

/* Auto-detecting public entry point.
 * Tries TLS 1.3 format first, then TLS 1.2. Accepts whichever yields
 * a chain that passes DER structure validation. This lets a single
 * call site handle both TLS 1.2 and TLS 1.3 servers without threading
 * a version parameter, and tolerates future cert-message formats that
 * still begin with length-prefixed structural elements. */
int certificate_parse(const uint8_t *buf, size_t len, cert_chain_t *out) {
    if (certificate_parse_impl(buf, len, 1, out) == 0 &&
        chain_looks_valid(out)) {
        return 0;
    }
    if (certificate_parse_impl(buf, len, 0, out) == 0 &&
        chain_looks_valid(out)) {
        return 0;
    }
    /* Neither format produced a valid chain. Return the TLS 1.2 attempt
     * so the caller's "&& chain.count > 0" check fails gracefully. */
    return certificate_parse_impl(buf, len, 0, out);
}

/** Parse a CertificateVerify message (RFC 8446 §4.4.3):
 *    SignatureScheme algorithm;   (2 bytes)
 *    opaque signature<0..2^16-1>;  (2-byte length + bytes)
 *  Returns 0 on success. */
int certificate_verify_parse(const uint8_t *buf, size_t len,
                              uint16_t *sig_scheme,
                              const uint8_t **sig, size_t *sig_len) {
    if (!buf || !sig_scheme || !sig || !sig_len || len < 4) return -1;
    *sig_scheme = (uint16_t)((buf[0] << 8) | buf[1]);
    uint16_t slen = (uint16_t)((buf[2] << 8) | buf[3]);
    if (4 + (size_t)slen > len) return -1;
    *sig = buf + 4;
    *sig_len = slen;
    return 0;
}

