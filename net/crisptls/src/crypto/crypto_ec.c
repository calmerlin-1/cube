/** crypto_ec.c — asymmetric primitives. X25519, P-256 ECDH, RSA-PSS, ECDSA, Ed25519.
 * Uses libcrypto's EVP_* layer only. No SSL_*. */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>




/* P-256 ECDH */


/* Signature verify */

/** Load a public key from DER (SPKI format). */
static EVP_PKEY *pubkey_from_der(const uint8_t *der, size_t der_len) {
    const unsigned char *p = der;
    return d2i_PUBKEY(NULL, &p, (long)der_len);
}

int ct_verify_rsa_pss_sha256(const uint8_t *pub_der, size_t pub_der_len,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len) {
    if (!pub_der || !msg || !sig) return CT_ERR_ARGS;
    EVP_PKEY *key = pubkey_from_der(pub_der, pub_der_len);
    if (!key) return CT_ERR_VERIFY;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = CT_ERR_VERIFY;
    if (!ctx) goto out;

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, key) != 1) goto out;

    /* Set RSA-PSS padding */
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto out;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0) goto out;

    if (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1)
        rc = CT_OK;

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

int ct_verify_ecdsa_p384_sha384(const uint8_t *pub_der, size_t pub_der_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len) {
    if (!pub_der || !msg || !sig) return CT_ERR_ARGS;
    EVP_PKEY *key = pubkey_from_der(pub_der, pub_der_len);
    if (!key) return CT_ERR_VERIFY;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = CT_ERR_VERIFY;
    if (!ctx) goto out;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha384(), NULL, key) != 1) goto out;
    if (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) rc = CT_OK;

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

int ct_verify_ed25519(const uint8_t pub[32],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[64]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!key) return CT_ERR_VERIFY;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = CT_ERR_VERIFY;
    if (!ctx) goto out;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1) goto out;
    if (EVP_DigestVerify(ctx, sig, 64, msg, msg_len) == 1) rc = CT_OK;

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

/* Cert helpers */

/** Extract SubjectPublicKeyInfo DER from a full certificate DER.
 * Returns 0 on success, sets out/out_len. */
int ct_cert_get_spki(const uint8_t *cert_der, size_t cert_der_len,
                     const uint8_t **spki_out, size_t *spki_len_out) {
    const unsigned char *p = cert_der;
    X509 *cert = d2i_X509(NULL, &p, (long)cert_der_len);
    if (!cert) return -1;

    X509_PUBKEY *xpk = X509_get_X509_PUBKEY(cert);
    if (!xpk) { X509_free(cert); return -1; }

    unsigned char *spki = NULL;
    int len = i2d_X509_PUBKEY(xpk, &spki);
    if (len <= 0 || !spki) { X509_free(cert); return -1; }

    /* Copy into a caller-owned pointer — for now, we leak the buffer
     * back into the cert's memory; caller must free with ct_free_spki. */
    *spki_out = spki;
    *spki_len_out = (size_t)len;
    X509_free(cert);
    return 0;
}

void ct_free_spki(const uint8_t *spki) {
    OPENSSL_free((void *)spki);
}
