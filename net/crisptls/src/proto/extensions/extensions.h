/** extensions.h — TLS extension types and registry. */

#ifndef CRISPTLS_EXTENSIONS_H
#define CRISPTLS_EXTENSIONS_H

#include <stddef.h>
#include <stdint.h>

/** Extension type IDs (RFC 8446 + historical) */
#define EXT_SERVER_NAME            0
#define EXT_MAX_FRAGMENT_LENGTH    1
#define EXT_CLIENT_CERTIFICATE_URL 2
#define EXT_TRUSTED_CA_KEYS        3
#define EXT_TRUNCATED_HMAC         4
#define EXT_STATUS_REQUEST         5
#define EXT_USER_MAPPING           6
#define EXT_CLIENT_AUTHZ           7
#define EXT_SERVER_AUTHZ           8
#define EXT_CERT_TYPE              9
#define EXT_SUPPORTED_GROUPS      10
#define EXT_EC_POINT_FORMATS      11
#define EXT_SRP                   12
#define EXT_SIGNATURE_ALGORITHMS  13
#define EXT_USE_SRTP              14
#define EXT_HEARTBEAT             15
#define EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION 16
#define EXT_STATUS_REQUEST_V2     17
#define EXT_SIGNED_CERTIFICATE_TIMESTAMP 18
#define EXT_CLIENT_CERTIFICATE_TYPE 19
#define EXT_SERVER_CERTIFICATE_TYPE 20
#define EXT_PADDING               21
#define EXT_ENCRYPT_THEN_MAC      22
#define EXT_EXTENDED_MASTER_SECRET 23
#define EXT_TOKEN_BINDING         24
#define EXT_CACHED_INFO           25
#define EXT_COMPRESS_CERTIFICATE  27
#define EXT_RECORD_SIZE_LIMIT     28
#define EXT_DELEGATED_CREDENTIALS 34
#define EXT_SESSION_TICKET        35
#define EXT_PRE_SHARED_KEY        41
#define EXT_EARLY_DATA            42
#define EXT_SUPPORTED_VERSIONS    43
#define EXT_COOKIE                44
#define EXT_PSK_KEY_EXCHANGE_MODES 45
#define EXT_CERTIFICATE_AUTHORITIES 47
#define EXT_OID_FILTERS           48
#define EXT_POST_HANDSHAKE_AUTH   49
#define EXT_SIGNATURE_ALGORITHMS_CERT 50
#define EXT_KEY_SHARE             51

/** Encode helper: writes extension header (type + 2-byte length) + body. */
size_t ext_write(uint16_t type, const uint8_t *body, uint16_t body_len,
                 uint8_t *out, size_t cap);

#endif
