/** crypto_ec.c — asymmetric glue with no libcrypto dependency.
 *
 * RSA-PSS lives in crypto_rsa.c, P-256/P-384 ECDSA in crypto_p256.c /
 * crypto_p384.c, and X25519/P-256 ECDH in their native files. This file
 * only provides Ed25519 (via libsodium) and SPKI extraction (via the
 * native X.509 parser).
 */

#include "crypto.h"
#include "x509.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int ct_verify_ed25519(const uint8_t pub[32],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[64])
{
    if (!pub || !sig) return CT_ERR_ARGS;
    if (!msg && msg_len > 0) return CT_ERR_ARGS;
    if (sodium_init() < 0) return CT_ERR_CRYPTO;
    const uint8_t *m = msg ? msg : (const uint8_t *)"";
    return crypto_sign_verify_detached(sig, m, msg_len, pub) == 0
               ? CT_OK : CT_ERR_VERIFY;
}

/** Extract SubjectPublicKeyInfo DER from a full certificate DER.
 * Returns 0 on success, sets out/out_len. The copy is caller-owned and
 * must be released with ct_free_spki(). */
int ct_cert_get_spki(const uint8_t *cert_der, size_t cert_der_len,
                     const uint8_t **spki_out, size_t *spki_len_out)
{
    if (!cert_der || cert_der_len == 0 || !spki_out || !spki_len_out)
        return -1;

    ct_x509_cert cert;
    if (ct_x509_parse(cert_der, cert_der_len, &cert) != CT_X509_OK)
        return -1;
    if (!cert.spki_der || cert.spki_len == 0)
        return -1;

    uint8_t *copy = malloc(cert.spki_len);
    if (!copy) return -1;
    memcpy(copy, cert.spki_der, cert.spki_len);

    *spki_out = copy;
    *spki_len_out = cert.spki_len;
    return 0;
}

void ct_free_spki(const uint8_t *spki) {
    free((void *)spki);
}
