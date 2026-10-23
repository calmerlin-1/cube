/* url_parser.h — URL parsing, validation, resolution. Zero-copy views. */

/**
 * URL parser, validator, joiner, and builder.
 *
 * Layers:
 *   url_parse / url_parse_ex     strict RFC 3986 parse
 *   url_parse_whatwg_stable      WHATWG-compat (browser) parse
 *   url_parse_auto               try strict, fall back to WHATWG
 *   url_validate                 component-level validation after parse
 *   url_join                     RFC 3986 §5.2 reference resolution
 *   url_build_*                  reconstruct URL from a view
 *   url_same_*                   RFC 6454 Same-Origin comparisons
 *   url_canonicalize             RFC 3986 §6.2.2 canonical form
 *
 * Zero-copy design: every field in url_view points into the input, or
 * into url_view.idna_storage for IDN hosts. No function in this header
 * allocates. The caller owns the input buffer and must keep it alive
 * for as long as any url_view referencing it is used.
 *
 * Parsing and validation are separate concerns (RFC 3986 §1.1.3).
 * url_parse is permissive; url_validate applies the strict rules.
 */

#ifndef FLYWHEEL_URL_PARSER_H
#define FLYWHEEL_URL_PARSER_H

#include <stddef.h>
#include <stdint.h>

/* Runtime-configurable max URL length. Default 8 MB. Callers who
 * parse user-pasted URLs may want to raise this; callers on
 * constrained memory may want to lower it. Applied to every
 * url_parse / url_parse_ex / url_parse_whatwg_stable call.
 *
 * Minimum enforced 64 bytes (below that, no useful URL fits).
 * Set to 0 to reset to default. */
void   url_set_max_len(size_t bytes);
size_t url_get_max_len(void);

/* Parse flags — control acceptance policy. Default (0) accepts any RFC-valid scheme. */
#define URL_F_STRICT_HTTP   (1u << 0)  /* only http/https allowed */
#define URL_F_ALLOW_CTRL    (1u << 1)  /* don't reject control chars */
#define URL_F_ALLOW_SPACE   (1u << 2)  /* don't reject unencoded whitespace */
#define URL_F_NO_DEFAULT    (1u << 3)  /* don't substitute scheme default port */
#define URL_F_LOWERCASE_HOST (1u << 4) /* lowercase host (default on) */

/* Error codes. 0 = success. Non-zero callers switch on. */
typedef enum {
    URL_OK = 0,
    URL_ERR_EMPTY,              /* empty input */
    URL_ERR_CTRL,               /* control char present */
    URL_ERR_SPACE,              /* unencoded whitespace present */
    URL_ERR_SCHEME,             /* malformed scheme */
    URL_ERR_SCHEME_NOT_ALLOWED, /* scheme outside whitelist flag */
    URL_ERR_HOST_MISSING,       /* host required by scheme but absent */
    URL_ERR_HOST_INVALID,       /* host has illegal bytes */
    URL_ERR_PORT_INVALID,       /* port non-numeric */
    URL_ERR_PORT_RANGE,         /* port outside 1..65535 */
    URL_ERR_TOO_LONG,           /* input exceeds configured max */
    URL_ERR_JOIN_FAILED,        /* relative could not be resolved */
    URL_ERR_BUFFER_TOO_SMALL,   /* caller output buffer insufficient */

    /* Component-level validation errors (url_validate) */
    URL_ERR_USERINFO_INVALID,   /* malformed percent-encoding in userinfo */
    URL_ERR_PATH_INVALID,       /* malformed percent-encoding in path */
    URL_ERR_QUERY_INVALID,      /* malformed percent-encoding in query */
    URL_ERR_FRAGMENT_INVALID,   /* malformed percent-encoding in fragment */
    URL_ERR_IPV6_INVALID        /* malformed IPv6 literal */
} url_err;

/* Zero-copy view. Every field points into `raw`, not owned. Lengths in bytes. */
typedef struct {
    const char *raw;         size_t raw_len;

    const char *scheme;      size_t scheme_len;    /* lowercase, no ':' */
    const char *userinfo;    size_t userinfo_len;  /* "user:pass", undecoded, may be 0 */
    const char *host;        size_t host_len;      /* lowercase ascii, no brackets for v6 */
    const char *port_str;    size_t port_str_len;  /* NULL if absent */
    const char *path;        size_t path_len;      /* "/" if empty path */
    const char *query;       size_t query_len;     /* no leading '?' */
    const char *fragment;    size_t fragment_len;  /* no leading '#' */

    uint16_t port;           /* 0 if scheme has no default and none given */
    uint8_t  is_ipv6;        /* host was bracketed */
    uint8_t  is_default_port;/* port equals scheme default */
    uint8_t  has_authority;  /* input had "//" before host */
    uint8_t  _pad;

    /* Internal: punycode storage for IDN hosts. When the host contains
     * non-ASCII bytes, url_parse() converts it to punycode and stores the
     * result here; `host` then points into this buffer instead of into the
     * caller's input. This keeps every url_view self-contained — no pointer
     * in *out references shared or thread-local state, so *out is valid for
     * as long as *out itself is valid.
     *
     * Do not read or write this field directly. */
    char     idna_storage[512];
} url_view;

/** Parse a URL string, strict RFC 3986. Zero-copy view into `s`. */
url_err url_parse(const char *s, size_t len, url_view *out);
/** Same as url_parse, with flag-controlled acceptance (URL_F_*). */
url_err url_parse_ex(const char *s, size_t len, uint32_t flags, url_view *out);

/** WHATWG (browser) parse — DEPRECATED; returns a view into a dead stack buffer. Use _stable. */
url_err url_parse_whatwg(const char *s, size_t len, url_view *out)
    __attribute__((deprecated("use url_parse_whatwg_stable — this variant returns a view into a dead stack buffer")));

/** WHATWG (browser) parse, writing the normalized URL into caller-owned norm_buf. */
url_err url_parse_whatwg_stable(const char *s, size_t len,
                                char *norm_buf, size_t norm_cap,
                                size_t *norm_len_out, url_view *out);

/** Strict component-level validation: percent-encoding, IPv6 syntax. */
url_err url_validate(const url_view *u);

/** Try url_parse first; fall back to url_parse_whatwg_stable if strict rejects. */
url_err url_parse_auto(const char *s, size_t len,
                       char *norm_buf, size_t norm_cap,
                       size_t *norm_len_out, url_view *out);

/** Resolve relative reference `rel` against `base`, RFC 3986 §5.2. */
url_err url_join(const url_view *base, const char *rel, size_t rel_len,
                 char *out, size_t out_cap, size_t *out_len);

/** Write scheme://host[:port] into caller buffer (port omitted if default). */
url_err url_build_origin(const url_view *u, char *out, size_t cap, size_t *n);

/** Write full URL verbatim — byte-exact inverse of url_parse. */
url_err url_build_href(const url_view *u, char *out, size_t cap, size_t *n);

/** Like url_build_href, but percent-encodes unsafe path/query bytes for wire output. */
url_err url_build_href_encoded(const url_view *u, char *out, size_t cap, size_t *n);

/** Like url_build_href, but include userinfo (user:pass@). Rarely safe to log. */
url_err url_build_full(const url_view *u, char *out, size_t cap, size_t *n);

/** 1 if hosts are equal, case-insensitive, trailing dots stripped, IDN in punycode. */
int url_same_host(const url_view *a, const url_view *b);
/** 1 if scheme + host + effective port all match (RFC 6454 Same-Origin Policy). */
int url_same_origin(const url_view *a, const url_view *b);

/** Write the RFC 3986 §6.2.2 canonical form: case-fold, drop default port, resolve dot segments. */
url_err url_canonicalize(const url_view *u, char *out, size_t cap, size_t *n);

/** Scheme's default port, 0 if the scheme has none or isn't known. */
uint16_t url_scheme_default_port(const char *scheme, size_t len);

/** Static human-readable name for a url_err value. Never NULL. */
const char *url_err_name(url_err e);

#endif
