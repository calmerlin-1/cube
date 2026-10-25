/* url_schemes.h — scheme lookup: port + flags. */

/**
 * Scheme lookup. Answers one question: given scheme bytes, what is this
 * scheme's default port, and what structural rules apply to a URL with
 * this scheme?
 *
 * Two tables:
 *   - A built-in const table compiled into the library (http, https,
 *     mailto, data, ws, wss, ftp, ...). Thread-safe by construction —
 *     read-only.
 *   - A runtime table filled by url_schemes_load() from a conf file.
 *     Checked first, so callers can override built-in schemes. This
 *     table is process-global and NOT thread-safe: call load/unload
 *     before spawning threads, or take your own lock. Lookups that
 *     race with load/unload are undefined.
 *
 * Parsing is permissive by design; the flags below only describe
 * structure (does the scheme carry a port? a host? an authority?).
 * Enforcement of caller-supplied rules is url_validate's job.
 */

#ifndef FLYWHEEL_URL_SCHEMES_H
#define FLYWHEEL_URL_SCHEMES_H

#include <stddef.h>

/* Structural flags for a scheme. */
#define SCHEME_HAS_PORT  0x01   /* row carries a default port */
#define SCHEME_NO_HOST   0x02   /* host is optional (file:, data:, mailto:) */
#define SCHEME_OPAQUE    0x04   /* no //authority at all (mailto:, javascript:) */
#define SCHEME_TLS       0x08   /* TLS-terminated by default (https, wss, ldaps) */

typedef struct {
    unsigned short port;
    unsigned char  flags;
} scheme_info;

/** Look up scheme. Returns 1 if found, 0 if not (out left as port=0, flags=0).
 *  Runtime-loaded schemes are checked before built-ins. */
int url_scheme_lookup(const char *scheme, size_t len, scheme_info *out);

/** Load extra schemes from a conf file, replacing any previously loaded set.
 *  **Not thread-safe with url_scheme_lookup.** Call before spawning threads.
 *  Returns the number of schemes loaded (may be 0).
 *  Returns -1 if conf_path is NULL or the file cannot be opened.
 *  On allocation failure mid-load, returns the count loaded so far.
 *  Not thread-safe; see the file header. */
int url_schemes_load(const char *conf_path);

/** Drop runtime-loaded schemes. Safe to call when none are loaded.
 *  Not thread-safe; see the file header. */
void url_schemes_unload(void);

/** Default port for scheme, or 0 if the scheme is unknown or has no default. */
unsigned short url_scheme_default_port(const char *scheme, size_t len);

/** 1 if the scheme permits a missing host (file:, data:, mailto:), else 0. */
int url_scheme_allows_no_host(const char *scheme, size_t len);

/** 1 if the scheme is TLS-terminated by default (https, wss, ...), else 0. */
int url_scheme_is_tls(const char *scheme, size_t len);

#endif
