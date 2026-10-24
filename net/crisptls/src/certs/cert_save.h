/** cert_save.h — persist peer certificates to disk for OSINT. */

#ifndef CRISPTLS_CERT_SAVE_H
#define CRISPTLS_CERT_SAVE_H

#include <stddef.h>
#include <stdint.h>

/** Save a DER cert as PEM plus a JSON metadata sidecar.
 * Directory: <cert_dir>/<hostname>.pem + <hostname>.json
 * Returns 0 on success, -1 on error. */
int cert_save(const char *cert_dir, const char *hostname,
              const uint8_t *der, size_t der_len);

/** Save a full chain: index 0 is leaf, 1..n are intermediates. */
int cert_save_chain(const char *cert_dir, const char *hostname,
                    const uint8_t **ders, const size_t *der_lens, size_t count);

/** Convert DER to PEM. Writes to out. Returns bytes written. */
size_t cert_der_to_pem(const uint8_t *der, size_t der_len,
                       char *out, size_t out_cap);

#endif
