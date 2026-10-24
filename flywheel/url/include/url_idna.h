/* url_idna.h — unicode hostname <-> punycode (RFC 3492). */

#ifndef FLYWHEEL_URL_IDNA_H
#define FLYWHEEL_URL_IDNA_H

#include <stddef.h>

/* IDN error codes. */
#define URLI_OK            0
#define URLI_ERR_BAD_UTF8  1
#define URLI_ERR_TOO_LONG  2
#define URLI_ERR_OVERFLOW  3

/* Encode a UTF-8 hostname into ASCII (punycode for non-ASCII labels).
 * "例え.jp" -> "xn--r8jz45g.jp". ASCII-only input passes through unchanged.
 * Returns URLI_OK, URLI_ERR_*, or error code. outlen receives bytes written. */
int url_idna_to_ascii(const char *in, size_t inlen,
                      char *out, size_t outcap, size_t *outlen);

/* Decode an ASCII hostname (xn-- labels) back into UTF-8. Best-effort. */
int url_idna_to_unicode(const char *in, size_t inlen,
                        char *out, size_t outcap, size_t *outlen);

#endif
