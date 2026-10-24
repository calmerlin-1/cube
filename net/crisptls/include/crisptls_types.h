/** crisptls_types.h — enums, opaque handles, constants. No logic. */

#ifndef CRISPTLS_TYPES_H
#define CRISPTLS_TYPES_H

#include <stddef.h>
#include <stdint.h>

/** TLS protocol versions (16-bit wire value) */
#define CRISPTLS_VERSION_SSL3   0x0300
#define CRISPTLS_VERSION_TLS10  0x0301
#define CRISPTLS_VERSION_TLS11  0x0302
#define CRISPTLS_VERSION_TLS12  0x0303
#define CRISPTLS_VERSION_TLS13  0x0304

/** Backend selection */
#define CRISPTLS_BACKEND_OPENSSL  1
#define CRISPTLS_BACKEND_MBEDTLS  2
#define CRISPTLS_BACKEND_NATIVE   3

/** Error codes */
#define CRISPTLS_OK                0
#define CRISPTLS_ERR_ARGS         -1
#define CRISPTLS_ERR_NOMEM        -2
#define CRISPTLS_ERR_BACKEND      -3
#define CRISPTLS_ERR_SOCKET       -4
#define CRISPTLS_ERR_HANDSHAKE    -5
#define CRISPTLS_ERR_VERIFY       -6   /* cert chain/hostname failure */
#define CRISPTLS_ERR_TIMEOUT      -7
#define CRISPTLS_ERR_CLOSED       -8
#define CRISPTLS_ERR_ALPN         -9   /* no common ALPN protocol */
#define CRISPTLS_ERR_POLICY      -10   /* policy rejected handshake */
#define CRISPTLS_ERR_PROFILE     -11   /* unknown fingerprint profile */

/** Verify result codes (for callbacks) */
#define CRISPTLS_VERIFY_OK         0
#define CRISPTLS_VERIFY_BADCHAIN   1
#define CRISPTLS_VERIFY_EXPIRED    2
#define CRISPTLS_VERIFY_WRONGHOST  3
#define CRISPTLS_VERIFY_UNTRUSTED  4
#define CRISPTLS_VERIFY_SELFSIGNED 5

/** ALPN wire protocol strings (length-prefixed in ClientHello) */
#define CRISPTLS_ALPN_H2         "h2"
#define CRISPTLS_ALPN_H1         "http/1.1"
#define CRISPTLS_ALPN_H3         "h3"
#define CRISPTLS_ALPN_DOT        "dot"

/** Opaque handles */
typedef struct crisptls_ctx  crisptls_ctx_t;
typedef struct crisptls_conn crisptls_conn_t;
typedef struct crisptls_profile crisptls_profile_t;

/** JA3/JA4 fingerprint hash (opaque to caller; printable via helper) */
typedef struct {
    uint8_t  bytes[32];
    uint32_t len;
} crisptls_fingerprint_t;

/** Verify callback signature */
typedef int (*crisptls_verify_fn)(int verify_result,
                                  const char *hostname,
                                  void *user);

#endif
