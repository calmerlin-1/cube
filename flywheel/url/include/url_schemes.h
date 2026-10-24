/* url_schemes.h — scheme lookup: port + flags. One table, one lookup. */

#ifndef FLYWHEEL_URL_SCHEMES_H
#define FLYWHEEL_URL_SCHEMES_H

#include <stddef.h>

/* Flag bits returned by lookup. */
#define SCHEME_HAS_PORT  0x01   /* row carries a default port */
#define SCHEME_NO_HOST   0x02   /* host is optional (file:, data:, mailto:) */
#define SCHEME_OPAQUE    0x04   /* no //authority at all (mailto:, javascript:) */
#define SCHEME_TLS       0x08   /* TLS-terminated by default (https, wss, ldaps) */

typedef struct {
    unsigned short port;
    unsigned char  flags;
} scheme_info;

/* Look up scheme. Returns 1 if found, 0 if not (out left as port=0, flags=0). */
int url_scheme_lookup(const char *scheme, size_t len, scheme_info *out);

/* Load extra schemes from conf. Returns count loaded, -1 on error. */
int url_schemes_load(const char *conf_path);

/* Drop runtime-loaded entries. */
void url_schemes_unload(void);

/* Convenience wrappers. */
unsigned short url_scheme_default_port(const char *scheme, size_t len);
int url_scheme_allows_no_host(const char *scheme, size_t len);
int url_scheme_is_tls(const char *scheme, size_t len);

#endif
