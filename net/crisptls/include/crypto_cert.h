/** crypto_cert.h — RFC 5280 chain validation + RFC 6125 hostname verify. */
#ifndef CRISPTLS_CRYPTO_CERT_H
#define CRISPTLS_CRYPTO_CERT_H

#include <stddef.h>
#include <stdint.h>

/* Result codes */
#define CERT_OK          0
#define CERT_ERR_ARGS   -1
#define CERT_ERR_PARSE  -2
#define CERT_ERR_SIG    -3
#define CERT_ERR_EXPIRED -4
#define CERT_ERR_ROOT   -5
#define CERT_ERR_HOST   -6
#define CERT_ERR_CHAIN  -7
#define CERT_ERR_CA_MISSING -8

/** Verify a certificate chain against a CA bundle for the given hostname.
 *
 * chain: array of DER-encoded certs, leaf at index 0, intermediates after.
 * n:     number of certs.
 * host:  SNI hostname the client connected to.
 * ca_bundle_path: PEM file with trusted root CAs. NULL → use env (SSL_CERT_FILE
 *                 then Termux default /data/data/com.termux/files/usr/etc/tls/cert.pem).
 *
 * Returns CERT_OK on success, or one of the error codes above.
 * On success, *verified_chain_len_out (if non-NULL) is set to the number of
 * certs successfully validated. */
int cert_verify_chain(const uint8_t *const *chain, const size_t *chain_lens, size_t n,
                      const char *host, const char *ca_bundle_path,
                      size_t *verified_chain_len_out);

#endif
