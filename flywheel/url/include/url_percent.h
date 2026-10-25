/* url_percent.h — percent-decode, percent-encode, UTF-8 validation. */

#ifndef FLYWHEEL_URL_PERCENT_H
#define FLYWHEEL_URL_PERCENT_H

#include <stddef.h>
#include <stdint.h>

/* Return codes. */
#define URLP_OK          0
#define URLP_ERR_BAD_PCT 1   /* %xx malformed, or % at end */
#define URLP_ERR_BAD_UTF8 2  /* invalid UTF-8 sequence after decode */
#define URLP_ERR_OVERFLOW 3  /* output buffer too small */

/* Decode percent-sequences in `in` into `out`. **Out is not NUL-terminated.**
 *  Use *outlen, not strlen().
 * Invalid hex sequences are passed through literally (browser behavior).
 * `plus_to_space` — 1 for query strings, 0 for paths.
 * Returns URLP_OK or URLP_ERR_OVERFLOW. */
int url_percent_decode(const char *in, size_t inlen,
                       char *out, size_t outcap, size_t *outlen,
                       int plus_to_space);

/* Validate a UTF-8 byte sequence. 1 = valid, 0 = invalid. */
int url_utf8_valid(const char *s, size_t n);

/* Encode unsafe bytes for a path segment. Letters, digits, and
 * -_.~ / ! $ & ' ( ) * + , ; = : @ are left alone. Everything else -> %XX.
 * Returns URLP_OK or URLP_ERR_OVERFLOW. */
int url_percent_encode_path(const char *in, size_t inlen,
                            char *out, size_t outcap, size_t *outlen);

/* Encode unsafe bytes for a query value. Same rules, but "+" is left alone. */
int url_percent_encode_query(const char *in, size_t inlen,
                             char *out, size_t outcap, size_t *outlen);

/* Encode all non-unreserved bytes (strict, for components like userinfo). */
int url_percent_encode_strict(const char *in, size_t inlen,
                              char *out, size_t outcap, size_t *outlen);

#endif
