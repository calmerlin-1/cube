/* pem.h — PEM (RFC 7468) base64 envelope for X.509. */
#ifndef CT_PEM_H
#define CT_PEM_H

#include <stddef.h>
#include <stdint.h>

/* Error codes. */
typedef enum {
    CT_PEM_OK = 0,
    CT_PEM_ERR_ARGS,
    CT_PEM_ERR_NO_BLOCK,   /* no BEGIN/END marker found */
    CT_PEM_ERR_BAD_BASE64, /* illegal character or padding */
    CT_PEM_ERR_OVERFLOW    /* output buffer too small */
} ct_pem_err;

/* Decode one PEM block: extract base64 body between "-----BEGIN <label>-----"
 * and "-----END <label>-----", decode to DER in `out`.
 * If `label` is non-NULL, only blocks with that exact label are accepted.
 * Returns CT_PEM_OK on success. `*out_len` receives DER byte count.
 * `*consumed` (if non-NULL) receives bytes of `in` consumed up to end of
 * block (useful for iterating PEM bundles). */
ct_pem_err ct_pem_decode(const char *in, size_t in_len,
                         const char *label,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         size_t *consumed);

/* Convenience: base64 decode of an arbitrary buffer (no BEGIN/END wrapper).
 * Returns CT_PEM_OK or CT_PEM_ERR_BAD_BASE64/OVERFLOW. */
ct_pem_err ct_pem_b64_decode(const char *in, size_t in_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

const char *ct_pem_err_name(ct_pem_err e);

#endif
