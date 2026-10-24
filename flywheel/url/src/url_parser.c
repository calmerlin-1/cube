/* url_parser.c — URL parse, join, build. Zero-copy. No allocation inside parse. */

#include "url_parser.h"
#include "url_schemes.h"
#include "url_percent.h"
#include "url_idna.h"
#include "scan.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifndef inet_pton
        #define inet_pton(fam, src, dst) InetPtonA(fam, src, dst)
    #endif
#else
    #include <arpa/inet.h>
#endif

/* Runtime-configurable max URL length.
 * URL_MAX_LEN is a compat alias for URL_MAX_LEN_DEFAULT (external
 * callers may reference it). New code should use url_set_max_len()
 * / url_get_max_len() to control the limit at runtime. */
#define URL_MAX_LEN_DEFAULT  (8u * 1024u * 1024u)
#define URL_MAX_LEN          URL_MAX_LEN_DEFAULT
#define URL_MAX_LEN_MIN      (64u)

static size_t g_url_max_len = URL_MAX_LEN_DEFAULT;

void url_set_max_len(size_t bytes) {
    if (bytes == 0) { g_url_max_len = URL_MAX_LEN_DEFAULT; return; }
    if (bytes < URL_MAX_LEN_MIN) bytes = URL_MAX_LEN_MIN;
    g_url_max_len = bytes;
}

size_t url_get_max_len(void) {
    return g_url_max_len;
}

/* Return 1 if c is an RFC 3986 scheme char (after first letter). */
static int is_scheme_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
}

/* Return lowercase of c. */
static unsigned char to_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

/* Return 1 if string has any byte < 0x20 or == 0x7F. */
/* One pass over the input: sets saw_space / saw_ctrl flags. */
static void has_bad_char(const char *s, size_t n, int *saw_space, int *saw_ctrl) {
    *saw_space = 0;
    *saw_ctrl  = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f) {
            if (c == ' ' || c == '\t') *saw_space = 1;
            else                        *saw_ctrl  = 1;
        }
        if (*saw_space && *saw_ctrl) return;
    }
}

static int has_ctrl(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F) return 1;
    }
    return 0;
}

/* Return 1 if string has space, tab, CR, LF. */
static int has_space(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') return 1;
    }
    return 0;
}

/* Return 1 if s starts with "//". */
static int starts_with_slashslash(const char *s, size_t n) {
    return n >= 2 && s[0] == '/' && s[1] == '/';
}

/* Scan scheme at start. Returns scheme length before ':' or 0.
 * Rejects "X:" when the input starts with "./" or "../" — those are
 * path-relative references, not scheme-qualified URIs. RFC 3986 §4.2. */
static size_t scan_scheme(const char *s, size_t n) {
    if (n >= 1 && s[0] == '.') return 0;   /* ./ or ../ or . — path, not scheme */
    if (n < 2) return 0;
    if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'))) return 0;
    size_t i = 1;
    while (i < n && is_scheme_char((unsigned char)s[i])) i++;
    if (i >= n || s[i] != ':') return 0;
    return i;
}
/* Parse port digits into out. Returns 0 ok, -1 invalid, -2 range. */
static int parse_port(const char *s, size_t n, uint16_t *out) {
    if (n == 0) { *out = 0; return 0; }
    unsigned long v = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (unsigned long)(c - '0');
        if (v > 65535) return -2;
    }
    if (v == 0) return -2;
    *out = (uint16_t)v;
    return 0;
}

/* Slice compare, case-insensitive. 1 = equal. */
static int slice_ci_eq(const char *a, size_t al, const char *b, size_t bl) {
    if (al != bl) return 0;
    for (size_t i = 0; i < al; i++) {
        if (to_lower((unsigned char)a[i]) != to_lower((unsigned char)b[i])) return 0;
    }
    return 1;
}

/* Normalize a path: remove "." segments and "x/.." pairs, but DO NOT
 * remove empty segments. "a//b" stays "a//b" (RFC 3986 §5.2.4 only
 * removes . and .. — not empty segments). Writes into out, returns len. */
static size_t normalize_path(const char *in, size_t in_len,
                             char *out, size_t out_cap,
                             int has_authority) {
    if (in_len == 0) {
        if (has_authority && out_cap > 0) { out[0] = '/'; out[1] = 0; return 1; }
        if (out_cap) out[0] = 0;
        return 0;
    }

    size_t w = 0;
    size_t i = 0;
    while (i < in_len && w + 1 < out_cap) {
        if (in[i] == '/') {
            /* peek at next segment */
            size_t seg_start = i + 1;
            size_t seg_end = seg_start;
            while (seg_end < in_len && in[seg_end] != '/') seg_end++;
            size_t seg_len = seg_end - seg_start;

            if (seg_len == 1 && in[seg_start] == '.') {
                /* "/." segment — remove it. If it's the last, keep trailing / */
                i = seg_end;
                if (i >= in_len && (w == 0 || out[w-1] != '/')) {
                    if (w + 1 < out_cap) out[w++] = '/';
                }
                continue;
            }
            if (seg_len == 2 && in[seg_start] == '.' && in[seg_start+1] == '.') {
                /* "/.." segment — remove previous segment */
                if (w > 0) {
                    /* drop trailing '/' */
                    if (w > 0 && out[w-1] == '/') w--;
                    /* back up to previous '/' */
                    while (w > 0 && out[w-1] != '/') w--;
                }
                i = seg_end;
                if (i >= in_len && (w == 0 || out[w-1] != '/')) {
                    if (w + 1 < out_cap) out[w++] = '/';
                }
                continue;
            }
            /* normal segment — copy '/' and advance */
            out[w++] = '/';
            i++;
            continue;
        }
        out[w++] = in[i++];
    }
#if __STDC_VERSION__ >= 201112L
    #define CUBE_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
    #define CUBE_THREAD_LOCAL __thread
#elif defined(_MSC_VER)
    #define CUBE_THREAD_LOCAL __declspec(thread)
#else
    #define CUBE_THREAD_LOCAL
#endif
static CUBE_THREAD_LOCAL const scheme_info *g_known_scheme = NULL;
    return w;
}

/* Optional pre-computed scheme info. When set by url_parse_with_scheme,
 * parse_impl uses it instead of calling url_scheme_lookup. Cleared after
 * every parse, so it can't leak between calls. Not thread-safe — the
 * cache layer is single-threaded by contract. */
static _Thread_local const scheme_info *g_known_scheme = NULL;

/* Scheme info lookup. Uses g_known_scheme when url_parse_with_scheme
 * pre-set it, otherwise falls back to a full url_scheme_lookup. */
static const scheme_info *scheme_info_for(const url_view *out,
                                          scheme_info *local)
{
    if (g_known_scheme) return g_known_scheme;
    memset(local, 0, sizeof(*local));
    url_scheme_lookup(out->scheme, out->scheme_len, local);
    return local;
}

/* Core parser. Fills a view. Zero allocation. */
static url_err parse_impl(const char *s, size_t len, uint32_t flags, url_view *out) {
    if (!s || len == 0) return URL_ERR_EMPTY;
    if (len > g_url_max_len) return URL_ERR_TOO_LONG;
    if (!(flags & URL_F_ALLOW_SPACE) && !(flags & URL_F_ALLOW_CTRL)) {
        int saw_space = 0, saw_ctrl = 0;
        has_bad_char(s, len, &saw_space, &saw_ctrl);
        if (saw_space) return URL_ERR_SPACE;
        if (saw_ctrl)  return URL_ERR_CTRL;
    } else {
        if (!(flags & URL_F_ALLOW_SPACE) && has_space(s, len)) return URL_ERR_SPACE;
        if (!(flags & URL_F_ALLOW_CTRL)  && has_ctrl(s, len))  return URL_ERR_CTRL;
    }

    memset(out, 0, sizeof(*out));
    out->raw = s;
    out->raw_len = len;

    const char *p = s;
    size_t remaining = len;

    /* scheme */
    size_t scheme_len = scan_scheme(p, remaining);
    if (scheme_len > 0) {
        out->scheme = p;
        out->scheme_len = scheme_len;
        p += scheme_len + 1;
        remaining -= scheme_len + 1;
    } else {
        /* RFC 3986 §4.2 — no scheme means a relative reference. */
        out->scheme = NULL;
        out->scheme_len = 0;
    }

    /* strict-http gate */
    if (flags & URL_F_STRICT_HTTP) {
        int is_http  = (out->scheme_len == 4 && to_lower((unsigned char)out->scheme[0]) == 'h'
                        && to_lower((unsigned char)out->scheme[1]) == 't'
                        && to_lower((unsigned char)out->scheme[2]) == 't'
                        && to_lower((unsigned char)out->scheme[3]) == 'p');
        int is_https = (out->scheme_len == 5 && to_lower((unsigned char)out->scheme[0]) == 'h'
                        && to_lower((unsigned char)out->scheme[1]) == 't'
                        && to_lower((unsigned char)out->scheme[2]) == 't'
                        && to_lower((unsigned char)out->scheme[3]) == 'p'
                        && to_lower((unsigned char)out->scheme[4]) == 's');
        if (!is_http && !is_https) return URL_ERR_SCHEME_NOT_ALLOWED;


    }


    /* Pre-compute scheme info once. All later uses read from this pointer. */
    scheme_info si_local;
    const scheme_info *si = scheme_info_for(out, &si_local);

    /* authority */
    out->has_authority = 0;
    const char *authority = NULL;
    size_t authority_len = 0;
    if (starts_with_slashslash(p, remaining)) {
        out->has_authority = 1;
        p += 2;
        remaining -= 2;
        const char *end = p;
        while (end < p + remaining && *end != '/' && *end != '?' && *end != '#') end++;
        authority = p;
        authority_len = (size_t)(end - p);
        remaining -= authority_len;
        p = end;
    } else if (scheme_len > 0) {
        if (!(si->flags & SCHEME_NO_HOST)) {
            if (out->scheme_len == 4 || out->scheme_len == 5) return URL_ERR_HOST_MISSING;
        }
    } else {
        /* No scheme, no "//". Relative reference (path only). RFC 3986 §4.2. */
        out->has_authority = 0;
        /* p stays; path parsing below picks up from here. */
    }

    /* [userinfo@]host[:port] */
    if (authority) {
        const char *at = NULL;
        for (size_t i = 0; i < authority_len; i++) {
            if (authority[i] == '@') {
                if (at) return URL_ERR_HOST_INVALID;   /* second @ — reject */
                at = authority + i;
            }
        }
        const char *host_start;
        size_t host_area;
        if (at) {
            out->userinfo = authority;
            out->userinfo_len = (size_t)(at - authority);
            host_start = at + 1;
            host_area = authority_len - (size_t)(at - authority) - 1;
        } else {
            host_start = authority;
            host_area = authority_len;
        }

        if (host_area > 0 && host_start[0] == '[') {
            const char *close = NULL;
            for (size_t i = 0; i < host_area; i++) {
                if (host_start[i] == ']') { close = host_start + i; break; }
            }
            if (!close) return URL_ERR_HOST_INVALID;
            out->host = host_start + 1;
            out->host_len = (size_t)(close - host_start - 1);
            out->is_ipv6 = 1;
            if ((size_t)(close - host_start) + 1 < host_area && close[1] == ':') {
                out->port_str = close + 2;
                out->port_str_len = host_area - (size_t)(close - host_start) - 2;
            }
        } else {
            const char *colon = NULL;
            for (size_t i = 0; i < host_area; i++) {
                if (host_start[i] == ':') colon = host_start + i;
            }
            if (colon) {
                out->host = host_start;
                out->host_len = (size_t)(colon - host_start);
                out->port_str = colon + 1;
                out->port_str_len = host_area - (size_t)(colon - host_start) - 1;
            } else {
                out->host = host_start;
                out->host_len = host_area;
            }
        }

        if (out->host_len == 0) {
            if (!(si->flags & SCHEME_NO_HOST)) {
                return URL_ERR_HOST_MISSING;
            }
        }
    }

    /* IDNA: if host has non-ASCII bytes, encode to punycode into the view's
     * own idna_storage. This keeps *out self-contained: no pointer points
     * into thread-local or shared state, so *out survives across calls. */
    if (out->host_len > 0 && out->host_len < sizeof(out->idna_storage)) {
        int has_non_ascii = 0;
        for (size_t i = 0; i < out->host_len; i++) {
            if ((unsigned char)out->host[i] >= 0x80) { has_non_ascii = 1; break; }
        }
        if (has_non_ascii) {
            size_t idn_len = 0;
            int ir = url_idna_to_ascii(out->host, out->host_len,
                                       out->idna_storage, sizeof(out->idna_storage),
                                       &idn_len);
            if (ir == URLI_OK && idn_len > 0) {
                out->host = out->idna_storage;
                out->host_len = idn_len;
            }
        }
    }
    /* port */
    uint16_t port = 0;
    if (out->port_str && out->port_str_len > 0) {
        int r = parse_port(out->port_str, out->port_str_len, &port);
        if (r == -1) return URL_ERR_PORT_INVALID;
        if (r == -2) return URL_ERR_PORT_RANGE;
        out->port = port;
    }
    if (out->port == 0 && !(flags & URL_F_NO_DEFAULT)) {
        out->port = si->port;
    }
    out->is_default_port = (out->port != 0 &&
        out->port == si->port) ? 1 : 0;

    /* path / query / fragment */
    const char *rest = p;
    size_t rest_len = remaining;
    const char *qmark = NULL, *hash = NULL;
    for (size_t i = 0; i < rest_len; i++) {
        if (rest[i] == '?' && !qmark) { qmark = rest + i; break; }
        if (rest[i] == '#') { hash = rest + i; break; }
    }
    for (size_t i = 0; i < rest_len; i++) {
        if (rest[i] == '#') { hash = rest + i; break; }
    }
    const char *path_end = rest + rest_len;
    if (qmark && qmark < path_end) path_end = qmark;
    if (hash && hash < path_end)   path_end = hash;

    out->path = rest;
    out->path_len = (size_t)(path_end - rest);
    if (out->path_len == 0 && out->has_authority) {
        out->path = "/";
        out->path_len = 1;
    }

    if (qmark) {
        const char *qend = hash ? hash : rest + rest_len;
        out->query = qmark + 1;
        out->query_len = (size_t)(qend - qmark - 1);
    }
    if (hash) {
        out->fragment = hash + 1;
        out->fragment_len = rest_len - (size_t)(hash - rest) - 1;
    }

    return URL_OK;
}

url_err url_parse(const char *s, size_t len, url_view *out) {
    if (!out) return URL_ERR_EMPTY;
    return parse_impl(s, len, 0, out);
}

url_err url_parse_ex(const char *s, size_t len, uint32_t flags, url_view *out) {
    if (!out) return URL_ERR_EMPTY;
    return parse_impl(s, len, flags, out);
}

url_err url_parse_auto(const char *s, size_t len,
                       char *norm_buf, size_t norm_cap,
                       size_t *norm_len_out, url_view *out) {
    url_err e = url_parse(s, len, out);
    if (e == URL_OK) {
        if (norm_len_out) *norm_len_out = 0;
        return URL_OK;
    }
    return url_parse_whatwg_stable(s, len, norm_buf, norm_cap, norm_len_out, out);
}

/* Variant for the cache layer: caller already knows the scheme's port
 * and flags, so parse_impl can skip url_scheme_lookup entirely.
 * Behavior identical to url_parse when scheme_info is correct for the
 * scheme at the start of s. Pass NULL to behave exactly like url_parse. */
url_err url_parse_with_scheme(const char *s, size_t len,
                              const scheme_info *known,
                              url_view *out);

url_err url_parse_with_scheme(const char *s, size_t len,
                              const scheme_info *known,
                              url_view *out)
{
    g_known_scheme = known;
    url_err rc = parse_impl(s, len, 0, out);
    g_known_scheme = NULL;
    return rc;
}

/* Definition — added at end of file to keep top clean. */


/* Append src to out+*n, bounded by cap. 0 on success. */
static int append(char *out, size_t cap, size_t *n, const char *src, size_t slen) {
    if (*n + slen > cap) return -1;
    memcpy(out + *n, src, slen);
    *n += slen;
    return 0;
}

/* Append u16 as decimal. */
static int append_u16(char *out, size_t cap, size_t *n, uint16_t v) {
    char tmp[8]; int t = 0;
    if (v == 0) tmp[t++] = '0';
    while (v) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
    if (*n + (size_t)t > cap) return -1;
    while (t) out[(*n)++] = tmp[--t];
    return 0;
}

/* Append slice lowercased. */
static int append_lower(char *out, size_t cap, size_t *n, const char *src, size_t slen) {
    if (*n + slen > cap) return -1;
    for (size_t i = 0; i < slen; i++) out[*n + i] = (char)to_lower((unsigned char)src[i]);
    *n += slen;
    return 0;
}

/* Append path/query/fragment tail. */
static int append_tail(const url_view *u, char *out, size_t cap, size_t *w) {
    if (u->path_len == 0 && u->has_authority) {
        if (append(out, cap, w, "/", 1)) return -1;
    } else if (u->path_len) {
        if (append(out, cap, w, u->path, u->path_len)) return -1;
    }
    if (u->query_len) {
        if (append(out, cap, w, "?", 1)) return -1;
        if (append(out, cap, w, u->query, u->query_len)) return -1;
    }
    if (u->fragment_len) {
        if (append(out, cap, w, "#", 1)) return -1;
        if (append(out, cap, w, u->fragment, u->fragment_len)) return -1;
    }
    return 0;
}

url_err url_build_origin(const url_view *u, char *out, size_t cap, size_t *n) {
    size_t w = 0;
    if (u->scheme_len > 0) {
        if (append(out, cap, &w, u->scheme, u->scheme_len))
            return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w,
                   u->has_authority ? "://" : ":",
                   u->has_authority ? 3 : 1))
            return URL_ERR_BUFFER_TOO_SMALL;
    } else if (u->has_authority) {
        if (append(out, cap, &w, "//", 2))
            return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (u->is_ipv6 && append(out, cap, &w, "[", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (append(out, cap, &w, u->host, u->host_len)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->is_ipv6 && append(out, cap, &w, "]", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->port && !u->is_default_port) {
        if (append(out, cap, &w, ":", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append_u16(out, cap, &w, u->port)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (n) *n = w;
    if (w < cap) out[w] = '\0';
    return URL_OK;
}

url_err url_build_href(const url_view *u, char *out, size_t cap, size_t *n) {
    size_t w = 0;
    url_err e = url_build_origin(u, out, cap, &w);
    if (e) return e;
    if (append_tail(u, out, cap, &w)) return URL_ERR_BUFFER_TOO_SMALL;
    if (n) *n = w;
    if (w < cap) out[w] = '\0';
    return URL_OK;
}

url_err url_build_href_encoded(const url_view *u, char *out, size_t cap, size_t *n) {
    size_t w = 0;
    url_err e = url_build_origin(u, out, cap, &w);
    if (e) return e;

    /* path — percent-encode unsafe bytes */
    if (u->path_len == 0 && u->has_authority) {
        if (append(out, cap, &w, "/", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    } else if (u->path_len) {
        char enc[4096];
        size_t en = 0;
        if (url_percent_encode_path(u->path, u->path_len, enc, sizeof(enc), &en) != URLP_OK)
            return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, enc, en)) return URL_ERR_BUFFER_TOO_SMALL;
    }

    /* query */
    if (u->query_len) {
        if (append(out, cap, &w, "?", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        char enc[4096];
        size_t en = 0;
        if (url_percent_encode_query(u->query, u->query_len, enc, sizeof(enc), &en) != URLP_OK)
            return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, enc, en)) return URL_ERR_BUFFER_TOO_SMALL;
    }

    /* fragment — leave as-is (fragments can contain anything) */
    if (u->fragment_len) {
        if (append(out, cap, &w, "#", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, u->fragment, u->fragment_len)) return URL_ERR_BUFFER_TOO_SMALL;
    }

    if (n) *n = w;
    if (w < cap) out[w] = '\0';
    return URL_OK;
}

url_err url_build_full(const url_view *u, char *out, size_t cap, size_t *n) {
    size_t w = 0;
    if (u->scheme_len > 0) {
        if (append(out, cap, &w, u->scheme, u->scheme_len))
            return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w,
                   u->has_authority ? "://" : ":",
                   u->has_authority ? 3 : 1))
            return URL_ERR_BUFFER_TOO_SMALL;
    } else if (u->has_authority) {
        if (append(out, cap, &w, "//", 2))
            return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (u->userinfo_len) {
        if (append(out, cap, &w, u->userinfo, u->userinfo_len)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, "@", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (u->is_ipv6 && append(out, cap, &w, "[", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (append(out, cap, &w, u->host, u->host_len)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->is_ipv6 && append(out, cap, &w, "]", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->port && !u->is_default_port) {
        if (append(out, cap, &w, ":", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append_u16(out, cap, &w, u->port)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (append_tail(u, out, cap, &w)) return URL_ERR_BUFFER_TOO_SMALL;
    if (n) *n = w;
    if (w < cap) out[w] = '\0';
    return URL_OK;
}

int url_same_host(const url_view *a, const url_view *b) {
    const char *ah = a->host; size_t al = a->host_len;
    const char *bh = b->host; size_t bl = b->host_len;
    while (al > 0 && ah[al - 1] == '.') al--;
    while (bl > 0 && bh[bl - 1] == '.') bl--;
    return slice_ci_eq(ah, al, bh, bl);
}

int url_same_origin(const url_view *a, const url_view *b) {
    if (!slice_ci_eq(a->scheme, a->scheme_len, b->scheme, b->scheme_len)) return 0;
    if (!slice_ci_eq(a->host, a->host_len, b->host, b->host_len)) return 0;
    return a->port == b->port;
}

url_err url_join(const url_view *base, const char *rel, size_t rel_len,
                 char *out, size_t out_cap, size_t *out_len) {
    if (!rel || rel_len == 0) return url_build_href(base, out, out_cap, out_len);
    if (has_ctrl(rel, rel_len)) return URL_ERR_CTRL;

    size_t rscheme = scan_scheme(rel, rel_len);
    if (rscheme > 0) {
        url_view tmp;
        url_err e = parse_impl(rel, rel_len, 0, &tmp);
        if (e) return e;
        return url_build_href(&tmp, out, out_cap, out_len);
    }

    if (starts_with_slashslash(rel, rel_len)) {
        size_t w = 0;
        if (append(out, out_cap, &w, base->scheme, base->scheme_len)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, out_cap, &w, ":", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, out_cap, &w, rel, rel_len)) return URL_ERR_BUFFER_TOO_SMALL;
        if (w < out_cap) out[w] = '\0';
        if (out_len) *out_len = w;
        return URL_OK;
    }

    if (rel[0] == '#') {
        url_view tmp = *base;
        tmp.fragment = rel + 1;
        tmp.fragment_len = rel_len - 1;
        return url_build_href(&tmp, out, out_cap, out_len);
    }

    if (rel[0] == '?') {
        url_view tmp = *base;
        tmp.query = rel + 1;
        tmp.query_len = rel_len - 1;
        tmp.fragment = NULL;
        tmp.fragment_len = 0;
        return url_build_href(&tmp, out, out_cap, out_len);
    }

    if (rel[0] == '/') {
        url_view tmp = *base;
        tmp.path = rel;
        tmp.path_len = rel_len;
        tmp.query = NULL; tmp.query_len = 0;
        tmp.fragment = NULL; tmp.fragment_len = 0;
        return url_build_href(&tmp, out, out_cap, out_len);
    }

    const char *base_path = base->path;
    size_t base_path_len = base->path_len;
    size_t last_slash = 0;
    for (size_t i = 0; i < base_path_len; i++) {
        if (base_path[i] == '/') last_slash = i;
    }
    size_t prefix_len = last_slash + 1;

    /* Split rel at the first '?' or '#' — the tail (query+fragment)
     * is opaque and must not be normalized. Only the path portion
     * gets spliced into the base directory and dot-segment-collapsed. */
    const char *rel_path = rel;
    size_t rel_path_len = rel_len;
    const char *rel_tail = NULL;
    size_t rel_tail_len = 0;
    for (size_t i = 0; i < rel_len; i++) {
        if (rel[i] == '?' || rel[i] == '#') {
            rel_path_len = i;
            rel_tail = rel + i;
            rel_tail_len = rel_len - i;
            break;
        }
    }

    /* splice base directory + rel_path into a staging buffer */
    char spliced[2048];
    size_t splen = 0;
    if (prefix_len > sizeof(spliced)) return URL_ERR_JOIN_FAILED;
    memcpy(spliced, base_path, prefix_len);
    splen = prefix_len;
    if (rel_path_len > sizeof(spliced) - splen) return URL_ERR_JOIN_FAILED;
    memcpy(spliced + splen, rel_path, rel_path_len);
    splen += rel_path_len;

    /* normalize the path (not the tail) */
    char norm[2048];
    size_t nlen = normalize_path(spliced, splen, norm, sizeof(norm), 1);
    if (nlen == 0) { nlen = splen; memcpy(norm, spliced, splen); }

    /* build the output: origin + normalized path + verbatim tail */
    size_t w = 0;
    url_err e = url_build_origin(base, out, out_cap, &w);
    if (e) return e;
    if (append(out, out_cap, &w, norm, nlen)) return URL_ERR_BUFFER_TOO_SMALL;
    if (rel_tail && append(out, out_cap, &w, rel_tail, rel_tail_len))
        return URL_ERR_BUFFER_TOO_SMALL;
    if (w < out_cap) out[w] = '\0';
    if (out_len) *out_len = w;
    return URL_OK;
}

url_err url_canonicalize(const url_view *u, char *out, size_t cap, size_t *n) {
    size_t w = 0;
    if (u->scheme_len > 0) {
        if (append_lower(out, cap, &w, u->scheme, u->scheme_len))
            return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w,
                   u->has_authority ? "://" : ":",
                   u->has_authority ? 3 : 1))
            return URL_ERR_BUFFER_TOO_SMALL;
    } else if (u->has_authority) {
        if (append(out, cap, &w, "//", 2))
            return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (u->userinfo_len) {
        if (append(out, cap, &w, u->userinfo, u->userinfo_len)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, "@", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (u->is_ipv6 && append(out, cap, &w, "[", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (append_lower(out, cap, &w, u->host, u->host_len)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->is_ipv6 && append(out, cap, &w, "]", 1)) return URL_ERR_BUFFER_TOO_SMALL;
    if (u->port && !u->is_default_port) {
        if (append(out, cap, &w, ":", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append_u16(out, cap, &w, u->port)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    /* Path: normalize dot segments (RFC 3986 §6.2.2.3) */
    if (u->path_len > 0 || u->has_authority) {
        char norm[2048];
        const char *src = u->path;
        size_t src_len = u->path_len;
        if (src_len == 0 && u->has_authority) {
            if (append(out, cap, &w, "/", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        } else {
            size_t nlen = normalize_path(src, src_len, norm, sizeof norm, u->has_authority);
            if (nlen > 0) {
                if (append(out, cap, &w, norm, nlen)) return URL_ERR_BUFFER_TOO_SMALL;
            } else {
                if (append(out, cap, &w, src, src_len)) return URL_ERR_BUFFER_TOO_SMALL;
            }
        }
    }
    /* Query */
    if (u->query_len > 0) {
        if (append(out, cap, &w, "?", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, u->query, u->query_len)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    /* Fragment */
    if (u->fragment_len > 0) {
        if (append(out, cap, &w, "#", 1)) return URL_ERR_BUFFER_TOO_SMALL;
        if (append(out, cap, &w, u->fragment, u->fragment_len)) return URL_ERR_BUFFER_TOO_SMALL;
    }
    if (n) *n = w;
    if (w < cap) out[w] = '\0';
    return URL_OK;
}

const char *url_err_name(url_err e) {
    switch (e) {
        case URL_OK: return "ok";
        case URL_ERR_EMPTY: return "empty";
        case URL_ERR_CTRL: return "control-char";
        case URL_ERR_SPACE: return "whitespace";
        case URL_ERR_SCHEME: return "bad-scheme";
        case URL_ERR_SCHEME_NOT_ALLOWED: return "scheme-not-allowed";
        case URL_ERR_HOST_MISSING: return "host-missing";
        case URL_ERR_HOST_INVALID: return "host-invalid";
        case URL_ERR_PORT_INVALID: return "port-invalid";
        case URL_ERR_PORT_RANGE: return "port-range";
        case URL_ERR_TOO_LONG: return "too-long";
        case URL_ERR_JOIN_FAILED: return "join-failed";
        case URL_ERR_BUFFER_TOO_SMALL: return "buffer-too-small";
        case URL_ERR_USERINFO_INVALID: return "userinfo-invalid";
        case URL_ERR_PATH_INVALID:     return "path-invalid";
        case URL_ERR_QUERY_INVALID:    return "query-invalid";
        case URL_ERR_FRAGMENT_INVALID: return "fragment-invalid";
        case URL_ERR_IPV6_INVALID:     return "ipv6-invalid";
    }
    return "unknown";
}

/* Validate a parsed view: percent-encoding in each component,
 * IPv6 literal syntax. Returns URL_OK or the first error found. */
url_err url_validate(const url_view *u) {
    if (!u) return URL_ERR_EMPTY;

    for (size_t i = 0; i < u->userinfo_len; i++) {
        if (u->userinfo[i] == '%') {
            if (i + 2 >= u->userinfo_len ||
                !isxdigit((unsigned char)u->userinfo[i+1]) ||
                !isxdigit((unsigned char)u->userinfo[i+2]))
                return URL_ERR_USERINFO_INVALID;
            i += 2;
        }
    }
    for (size_t i = 0; i < u->path_len; i++) {
        if (u->path[i] == '%') {
            if (i + 2 >= u->path_len ||
                !isxdigit((unsigned char)u->path[i+1]) ||
                !isxdigit((unsigned char)u->path[i+2]))
                return URL_ERR_PATH_INVALID;
            i += 2;
        }
    }
    for (size_t i = 0; i < u->query_len; i++) {
        if (u->query[i] == '%') {
            if (i + 2 >= u->query_len ||
                !isxdigit((unsigned char)u->query[i+1]) ||
                !isxdigit((unsigned char)u->query[i+2]))
                return URL_ERR_QUERY_INVALID;
            i += 2;
        }
    }
    for (size_t i = 0; i < u->fragment_len; i++) {
        if (u->fragment[i] == '%') {
            if (i + 2 >= u->fragment_len ||
                !isxdigit((unsigned char)u->fragment[i+1]) ||
                !isxdigit((unsigned char)u->fragment[i+2]))
                return URL_ERR_FRAGMENT_INVALID;
            i += 2;
        }
    }

    if (u->is_ipv6 && u->host && u->host_len > 0) {
        char h[64];
        if (u->host_len >= sizeof h) return URL_ERR_IPV6_INVALID;
        memcpy(h, u->host, u->host_len);
        h[u->host_len] = 0;
        struct in6_addr a6;
        if (inet_pton(AF_INET6, h, &a6) != 1)
            return URL_ERR_IPV6_INVALID;
    }
    /* Non-IPv6 host: reject bytes that can't appear in a reg-name (RFC 3986 §3.2.2) */
    if (u->host && u->host_len > 0 && !u->is_ipv6) {
        for (size_t i = 0; i < u->host_len; i++) {
            unsigned char c = (unsigned char)u->host[i];
            if (c == '@') return URL_ERR_HOST_INVALID;
            if (!( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') ||
                   c == '-' || c == '.' || c == '_' || c == '~' ||
                   c == '!' || c == '$' || c == '&' || c == '\'' ||
                   c == '(' || c == ')' || c == '*' || c == '+' ||
                   c == ',' || c == ';' || c == '=' || c == '%' ))
                return URL_ERR_HOST_INVALID;
        }
    }


    return URL_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * WHATWG-compatible parse — browser behavior.
 *
 * Applies normalizations before handing off to url_parse:
 *   1. Strip ASCII tab, newline, CR from anywhere
 *   2. Strip leading/trailing spaces
 *   3. For special schemes (http, https, ws, wss, ftp, file):
 *        a. Replace every '\' with '/'
 *        b. Ensure "//" immediately after scheme colon
 *   4. Percent-decode the host portion only (not path/query/fragment)
 *   5. Expand integer IPv4 forms (0177.0.0.1, 0x7f.0.0.1, 127.1,
 *      2130706433) to dotted decimal
 *   6. Call url_parse on the cleaned string
 *
 * Not applied (WHATWG has more, out of scope for now):
 *   - Full Unicode host normalization / NFC before IDNA
 *   - file: on Windows (drive letters)
 *   - blob:, filesystem: special cases
 * ═══════════════════════════════════════════════════════════════════ */

#define WHATWG_BUF 8192

static int whatwg_is_special_scheme(const char *s, size_t len) {
    /* case-insensitive compare of a scheme slice */
    static const char *SPECIAL[] = {
        "http", "https", "ws", "wss", "ftp", "file", NULL
    };
    for (int i = 0; SPECIAL[i]; i++) {
        size_t sl = strlen(SPECIAL[i]);
        if (len != sl) continue;
        int eq = 1;
        for (size_t k = 0; k < sl; k++) {
            unsigned char c = (unsigned char)s[k];
            if (c >= 'A' && c <= 'Z') c += 32;
            if (c != (unsigned char)SPECIAL[i][k]) { eq = 0; break; }
        }
        if (eq) return 1;
    }
    return 0;
}

/* Parse one IPv4 component: decimal, octal (0…), or hex (0x…). */
static int whatwg_parse_ipv4_part(const char *s, size_t n, unsigned *out) {
    if (n == 0) return -1;
    unsigned base = 10;
    size_t i = 0;
    if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16; i = 2;
    } else if (n >= 2 && s[0] == '0') {
        /* was: octal. WHATWG deprecated; treat as decimal to match strict path */
        i = 0;
    }
    if (i >= n) { *out = 0; return 0; }   /* "0" or "0x" → 0 */
    unsigned v = 0;
    for (; i < n; i++) {
        int d;
        char c = s[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        if (d >= (int)base) return -1;
        v = v * base + (unsigned)d;
        if (v > 0xFFFFFFFFu) return -1;
    }
    *out = v;
    return 0;
}

/* Try to interpret [host_start, host_end) as an IPv4 in any of the
 * WHATWG-supported forms. On success, write dotted quad into out and
 * return the new length. On failure, return 0 and leave out alone. */
static size_t whatwg_expand_ipv4(const char *host, size_t hlen,
                                 char *out, size_t out_cap) {
    if (hlen == 0 || hlen > 15 + 8) return 0;   /* sanity: max dotted form */

    /* split on '.' */
    unsigned parts[4] = {0,0,0,0};
    size_t n_parts = 0;
    size_t i = 0;
    while (i < hlen) {
        if (n_parts >= 4) return 0;
        size_t j = i;
        while (j < hlen && host[j] != '.') j++;
        if (whatwg_parse_ipv4_part(host + i, j - i, &parts[n_parts]) != 0) return 0;
        n_parts++;
        i = (j < hlen) ? j + 1 : j;
        if (i == hlen && host[hlen-1] == '.') break;  /* trailing dot allowed */
    }
    if (n_parts == 0) return 0;

    /* WHATWG rule: last part fills the remaining bytes.
     * e.g. "127.1" means 127.0.0.1
     *      "10.1"  means 10.0.0.1
     *      "1.2.3.4" is 1.2.3.4
     *      "2130706433" means 127.0.0.1 */
    unsigned long long addr = 0;
    if (n_parts == 1) {
        addr = parts[0];
    } else {
        /* all but the last part: must fit in a byte (0..255) */
        for (size_t k = 0; k + 1 < n_parts; k++) {
            if (parts[k] > 255) return 0;
            addr = (addr << 8) | parts[k];
        }
        /* last part fills the rest */
        unsigned remaining_bits = (unsigned)((4 - (n_parts - 1)) * 8);
        if (remaining_bits == 0) remaining_bits = 8;
        unsigned long long max_last = (1ULL << remaining_bits) - 1;
        if (parts[n_parts-1] > max_last) return 0;
        addr = (addr << remaining_bits) | parts[n_parts-1];
    }
    if (addr > 0xFFFFFFFFull) return 0;

    unsigned char b[4];
    b[0] = (unsigned char)(addr >> 24);
    b[1] = (unsigned char)(addr >> 16);
    b[2] = (unsigned char)(addr >>  8);
    b[3] = (unsigned char)(addr      );
    int n = snprintf(out, out_cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    if (n <= 0 || (size_t)n >= out_cap) return 0;
    return (size_t)n;
}

/* Percent-encode unsafe bytes in buf[start..end), right-to-left so a
 * single memmove suffices. Path/fragment use path_safe (is_query=0),
 * query uses query_safe (is_query=1). Grows buf in place — callers
 * must re-fetch their bounds from the returned byte count.
 *
 * On success, updates *n and returns the number of bytes added.
 * Returns (size_t)-1 on overflow (does not modify buf in that case). */
static char whatwg_hexdig_(unsigned v) {
    return (char)(v < 10 ? '0' + v : 'a' + v - 10);
}

static int whatwg_is_safe_byte_(unsigned char c, int is_query) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.' || c == '~') return 1;
    switch (c) {
        case '/': case ':': case '@':
        case '!': case '$': case '&': case '\'':
        case '(': case ')': case '*': case '+':
        case ',': case ';': case '=':
            return 1;
    }
    if (is_query && c == '?') return 1;
    return 0;
}

static size_t whatwg_encode_region(char *buf, size_t cap, size_t *n,
                                    size_t start, size_t end, int is_query) {
    if (start > end || end > *n) return (size_t)-1;
    /* Count how many bytes need encoding (each costs +2 over the source byte) */
    size_t grown = 0;
    for (size_t i = start; i < end; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (!whatwg_is_safe_byte_(c, is_query)) grown += 2;
    }
    if (grown == 0) return 0;
    if (*n + grown >= cap) return (size_t)-1;
    /* Shift tail right (memmove right is safe; preserves NUL) */
    memmove(buf + end + grown, buf + end, *n - end + 1);
    /* Encode right-to-left */
    size_t r = end + grown;
    size_t i = end;
    while (i > start) {
        i--;
        unsigned char c = (unsigned char)buf[i];
        if (whatwg_is_safe_byte_(c, is_query)) {
            buf[--r] = (char)c;
        } else {
            buf[--r] = whatwg_hexdig_((unsigned)(c & 0x0F));
            buf[--r] = whatwg_hexdig_((unsigned)(c >> 4));
            buf[--r] = '%';
        }
    }
    *n += grown;
    return grown;
}

/* Canonicalize an IPv6 host in place: lowercase hex, compress the
 * longest run of zero groups to "::". Same length or shorter than
 * input — never grows. Returns number of bytes removed (0 if no
 * change). Bails (returns 0) on malformed input — the caller's
 * existing IPv6 parse already validated it, so this is best-effort
 * canonicalization, not a validator. */
static size_t whatwg_canonicalize_ipv6(char *host, size_t host_len) {
    /* Refuse input with more than one "::" — invalid IPv6 per RFC 4291.
     * Leave it unchanged; url_validate will reject via inet_pton. */
    {
        int dcolon_count = 0;
        for (size_t k = 0; k + 1 < host_len; k++) {
            if (host[k] == ':' && host[k + 1] == ':') {
                dcolon_count++;
                k++;
            }
        }
        if (dcolon_count > 1) return 0;
    }
    uint16_t g[8] = {0};
    int n = 0;
    size_t i = 0;
    /* Consume leading "::" if present */
    if (host_len >= 2 && host[0] == ':' && host[1] == ':') i = 2;
    while (i < host_len && n < 8) {
        if (host[i] == ':') { i++; continue; }
        unsigned v = 0;
        int digits = 0;
        while (i < host_len && host[i] != ':') {
            char c = host[i];
            unsigned h;
            if      (c >= '0' && c <= '9') h = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') h = (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') h = (unsigned)(c - 'A' + 10);
            else return 0;
            v = (v << 4) | h;
            i++;
            if (++digits > 4) return 0;
        }
        g[n++] = (uint16_t)v;
    }
    /* If fewer than 8 groups without a "::", this isn't a valid form */
    if (n < 8) {
        int has_dcolon = 0;
        for (size_t k = 0; k + 1 < host_len; k++) {
            if (host[k] == ':' && host[k + 1] == ':') { has_dcolon = 1; break; }
        }
        if (!has_dcolon) return 0;
    }
    /* Find longest run of zero groups (>= 2) */
    int best_start = -1, best_len = 0;
    for (int k = 0; k < 8; k++) {
        if (g[k] == 0) {
            int j = k;
            while (j < 8 && g[j] == 0) j++;
            int run = j - k;
            if (run >= 2 && run > best_len) { best_start = k; best_len = run; }
            k = j - 1;
        }
    }
    /* Emit canonical form into scratch */
    char buf[64];
    size_t w = 0;
    for (int k = 0; k < 8; k++) {
        if (k == best_start) {
            buf[w++] = ':';
            buf[w++] = ':';
            k += best_len - 1;
            continue;
        }
        if (w > 0 && buf[w - 1] != ':') buf[w++] = ':';
        unsigned short v = g[k];
        if (v == 0) {
            buf[w++] = '0';
        } else {
            char hb[4]; int hn = 0;
            while (v > 0) {
                int d = v & 0xF;
                hb[hn++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
                v >>= 4;
            }
            for (int j = hn - 1; j >= 0; j--) buf[w++] = hb[j];
        }
    }
    if (w >= host_len) return 0;   /* same length or grew — nothing to do */
    memcpy(host, buf, w);
    return host_len - w;
}

url_err url_parse_whatwg_stable(const char *s, size_t len,
                                char *norm_buf, size_t norm_cap,
                                size_t *norm_len_out, url_view *out) {
    if (!s || !out) return URL_ERR_EMPTY;
    if (len == 0)    return URL_ERR_EMPTY;

    /* 1. Copy to scratch, stripping \t \n \r wherever they appear. */
    char *buf = norm_buf;
    if (!buf || norm_cap < 32) return URL_ERR_BUFFER_TOO_SMALL;
    size_t w = 0;
    size_t i_consumed = 0;
    for (; i_consumed < len && w + 1 < norm_cap; i_consumed++) {
        char c = s[i_consumed];
        if (c == '\t' || c == '\n' || c == '\r') continue;
        buf[w++] = c;
    }
    if (i_consumed < len) {
        /* Loop stopped at norm_cap, not at end of input — truncated.
         * Refuse instead of silently parsing a truncated URL. */
        return URL_ERR_TOO_LONG;
    }
    buf[w] = 0;
    size_t n = w;

    /* 2. Strip leading and trailing ASCII spaces. */
    size_t lo = 0, hi = n;
    while (lo < hi && (buf[lo] == ' ' || buf[lo] == '\f' ||
                       buf[lo] == '\v')) lo++;
    while (hi > lo && (buf[hi-1] == ' ' || buf[hi-1] == '\f' ||
                       buf[hi-1] == '\v')) hi--;
    if (lo > 0 || hi < n) {
        memmove(buf, buf + lo, hi - lo);
        n = hi - lo;
        buf[n] = 0;
    }

    /* 3. Detect scheme: letters followed by ':' at position >= 1. */
    size_t scheme_end = 0;
    if (n >= 2 && buf[0] != ':' && buf[0] != '/') {
        size_t i = 1;
        while (i < n && (isalnum((unsigned char)buf[i]) ||
                         buf[i] == '+' || buf[i] == '-' || buf[i] == '.')) i++;
        if (i < n && buf[i] == ':') scheme_end = i;
    }
    int special = scheme_end > 0 && whatwg_is_special_scheme(buf, scheme_end);

    if (special) {
        /* 3a. Replace every '\' with '/'. */
        for (size_t i = 0; i < n; i++) if (buf[i] == '\\') buf[i] = '/';

        /* 3b. Ensure exactly "//" after scheme:. */
        size_t after = scheme_end + 1;
        /* Count how many '/' exist right after ':' */
        size_t slashes = 0;
        while (after + slashes < n && buf[after + slashes] == '/') slashes++;
        if (slashes != 2) {
            /* Want to insert/remove to make exactly two slashes.
             * Compute delta and shift. */
            size_t have = slashes;
            size_t want = 2;
            if (have < want) {
                size_t add = want - have;
                if (n + add + 1 >= norm_cap) return URL_ERR_TOO_LONG;
                memmove(buf + after + want, buf + after + have,
                        n - after - have + 1);
                for (size_t k = 0; k < add; k++) buf[after + have + k] = '/';
                n += add;
            } else if (have > want) {
                size_t rem = have - want;
                memmove(buf + after + want, buf + after + have,
                        n - after - have + 1);
                n -= rem;
            }
        }
    }

    /* 4. Percent-decode the host portion only.
     * Find host bounds: after "scheme://" (or "//" if no scheme).
     * Host ends at first '/', '?', '#', or end. */
    size_t host_start = 0;
    if (special) {
        host_start = scheme_end + 3;   /* past "://" */
    } else if (scheme_end > 0 && scheme_end + 1 < n && buf[scheme_end+1] == '/') {
        host_start = scheme_end + 1;
        if (host_start < n && buf[host_start] == '/') host_start++;
    }

    /* userinfo is part of authority but not host */
    size_t userinfo_at = SIZE_MAX;
    {
        for (size_t i = host_start; i < n; i++) {
            if (buf[i] == '/') break;
            if (buf[i] == '@') { userinfo_at = i; }
            if (buf[i] == '?' || buf[i] == '#') break;
        }
    }
    size_t userinfo_end = (userinfo_at == SIZE_MAX) ? host_start : userinfo_at + 1;

    size_t host_end = userinfo_end;
    if (buf[host_end] == '[') {
        /* IPv6 literal, find matching ']' */
        host_end++;
        while (host_end < n && buf[host_end] != ']' && buf[host_end] != '/'
               && buf[host_end] != '?' && buf[host_end] != '#') host_end++;
        if (host_end < n && buf[host_end] == ']') host_end++;
    } else {
        while (host_end < n && buf[host_end] != ':' && buf[host_end] != '/'
               && buf[host_end] != '?' && buf[host_end] != '#') host_end++;
    }

    /* percent-decode inside [userinfo_end, host_end) */
    if (host_end > userinfo_end) {
        char decoded[512];
        size_t dlen = 0;
        int has_pct = 0;
        for (size_t i = userinfo_end; i < host_end; i++) {
            if (buf[i] == '%') { has_pct = 1; break; }
        }
        if (has_pct) {
            int overflow = 0;
            for (size_t i = userinfo_end; i < host_end; i++) {
                if (dlen + 1 >= sizeof(decoded)) { overflow = 1; break; }
                if (buf[i] == '%' && i + 2 < host_end &&
                    isxdigit((unsigned char)buf[i+1]) && isxdigit((unsigned char)buf[i+2])) {
                    unsigned hi = (unsigned char)buf[i+1];
                    unsigned lo = (unsigned char)buf[i+2];
                    unsigned b = (hi <= '9' ? hi - '0' : (hi | 0x20) - 'a' + 10) << 4 |
                                 (lo <= '9' ? lo - '0' : (lo | 0x20) - 'a' + 10);
                    decoded[dlen++] = (char)b;
                    i += 2;
                } else {
                    decoded[dlen++] = buf[i];
                }
            }
            if (overflow) return URL_ERR_TOO_LONG;
            decoded[dlen] = 0;
            /* splice back: replace host bytes with decoded */
            size_t old_len = host_end - userinfo_end;
            if (dlen <= old_len) {
                memcpy(buf + userinfo_end, decoded, dlen);
                memmove(buf + userinfo_end + dlen, buf + host_end, n - host_end + 1);
                n -= (old_len - dlen);
                buf[n] = 0;
                host_end = userinfo_end + dlen;
            } else {
                if (n + (dlen - old_len) + 1 >= norm_cap) return URL_ERR_TOO_LONG;
                memmove(buf + userinfo_end + dlen, buf + host_end, n - host_end + 1);
                memcpy(buf + userinfo_end, decoded, dlen);
                n += (dlen - old_len);
                host_end = userinfo_end + dlen;
            }
        }
    }

    /* 5. IPv4 integer expansion. Only applies if the host has no ':' (not IPv6)
     * and is composed of digits/dots/hex-prefixes. */
    if (host_end > userinfo_end && buf[userinfo_end] != '[') {
        int maybe_ipv4 = 1;
        for (size_t i = userinfo_end; i < host_end; i++) {
            char c = buf[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F') || c == '.' || c == 'x' || c == 'X')) {
                maybe_ipv4 = 0; break;
            }
        }
        /* must have at least one digit */
        int has_digit = 0;
        for (size_t i = userinfo_end; i < host_end; i++)
            if (buf[i] >= '0' && buf[i] <= '9') { has_digit = 1; break; }

        if (maybe_ipv4 && has_digit) {
            char expanded[32];
            size_t el = whatwg_expand_ipv4(buf + userinfo_end,
                                           host_end - userinfo_end,
                                           expanded, sizeof(expanded));
            if (el > 0) {
                size_t old_len = host_end - userinfo_end;
                if (el <= old_len) {
                    memcpy(buf + userinfo_end, expanded, el);
                    memmove(buf + userinfo_end + el, buf + host_end, n - host_end + 1);
                    n -= (old_len - el);
                    buf[n] = 0;
                } else {
                    if (n + (el - old_len) + 1 >= norm_cap) return URL_ERR_TOO_LONG;
                    memmove(buf + userinfo_end + el, buf + host_end, n - host_end + 1);
                    memcpy(buf + userinfo_end, expanded, el);
                    n += (el - old_len);
                }
            }
        }
    }

    /* 6. WHATWG: lowercase scheme + host, strip trailing dots. */
    if (scheme_end > 0) {
        for (size_t i = 0; i < scheme_end; i++) {
            if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] = (char)(buf[i] + 32);
        }
    }
    {
        /* Recompute host bounds (previous rules shifted things). */
        size_t hs = 0;
        if (scheme_end > 0 && special) {
            hs = scheme_end + 3;
        } else if (scheme_end > 0 && scheme_end + 1 < n && buf[scheme_end + 1] == '/') {
            hs = scheme_end + 1;
            if (hs < n && buf[hs] == '/') hs++;
        }
        int seen_at = 0;
        for (size_t i = hs; i < n; i++) {
            if (buf[i] == '/' || buf[i] == '?' || buf[i] == '#') break;
            if (buf[i] == '@') {
                if (seen_at) return URL_ERR_HOST_INVALID;
                seen_at = 1;
                hs = i + 1;
            }
        }
        size_t he = hs;
        int is_ipv6 = (he < n && buf[he] == '[');
        if (is_ipv6) {
            while (he < n && buf[he] != ']') he++;
            if (he < n) he++;
        } else {
            while (he < n && buf[he] != ':' && buf[he] != '/' &&
                   buf[he] != '?' && buf[he] != '#') he++;
        }
        /* Lowercase host chars (safe for IPv6 too — hex becomes a-f) */
        for (size_t i = hs; i < he; i++) {
            if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] = (char)(buf[i] + 32);
        }
        /* Strip ALL trailing dots from hostname (not IPv6) */
        if (!is_ipv6 && he > hs) {
            size_t trimmed = he;
            while (trimmed > hs && buf[trimmed - 1] == '.') trimmed--;
            size_t removed = he - trimmed;
            if (removed > 0) {
                memmove(buf + trimmed, buf + he, n - he + 1);
                n -= removed;
                buf[n] = 0;
            }
        }
    }

    /* 6b. Percent-encode unsafe bytes in path, query, fragment. */
    {
        size_t scan = 0;
        if (scheme_end > 0) scan = scheme_end + 1;
        if (special && scan + 1 < n && buf[scan] == '/' && buf[scan + 1] == '/') scan += 2;
        else if (scan < n && buf[scan] == '/') scan++;
        if (scan < n && buf[scan] == '/') scan++;
        /* Skip userinfo */
        for (size_t i = scan; i < n; i++) {
            if (buf[i] == '/' || buf[i] == '?' || buf[i] == '#') break;
            if (buf[i] == '@') { scan = i + 1; break; }
        }
        /* Skip host */
        if (scan < n && buf[scan] == '[') {
            while (scan < n && buf[scan] != ']') scan++;
            if (scan < n) scan++;
        } else {
            while (scan < n && buf[scan] != ':' && buf[scan] != '/' &&
                   buf[scan] != '?' && buf[scan] != '#') scan++;
        }
        /* Skip :port */
        if (scan < n && buf[scan] == ':') {
            scan++;
            while (scan < n && buf[scan] >= '0' && buf[scan] <= '9') scan++;
        }
        if (scan < n && (buf[scan] == '/' || buf[scan] == '?' || buf[scan] == '#')) {
            size_t p_start = scan, p_end = scan;
            if (buf[scan] == '/') {
                while (p_end < n && buf[p_end] != '?' && buf[p_end] != '#' && buf[p_end] != '\0') p_end++;
            }
            size_t q_start = 0, q_end = 0, f_start = 0, f_end = 0;
            int has_q = 0, has_f = 0;
            if (p_end < n && buf[p_end] == '?') {
                has_q = 1; q_start = p_end + 1;
                size_t qe = q_start;
                while (qe < n && buf[qe] != '#' && buf[qe] != '\0') qe++;
                q_end = qe;
                if (qe < n && buf[qe] == '#') { has_f = 1; f_start = qe + 1; f_end = n; }
            } else if (p_end < n && buf[p_end] == '#') {
                has_f = 1; f_start = p_end + 1; f_end = n;
            }
            /* Encode right-to-left: fragment, then query, then path. */
            if (has_f && f_end > f_start) {
                if (whatwg_encode_region(buf, norm_cap, &n, f_start, f_end, 0) == (size_t)-1)
                    return URL_ERR_TOO_LONG;
            }
            if (has_q && q_end > q_start) {
                if (whatwg_encode_region(buf, norm_cap, &n, q_start, q_end, 1) == (size_t)-1)
                    return URL_ERR_TOO_LONG;
            }
            if (p_end > p_start) {
                if (whatwg_encode_region(buf, norm_cap, &n, p_start, p_end, 0) == (size_t)-1)
                    return URL_ERR_TOO_LONG;
            }
        }
    }

    /* 7. Hand off to the strict parser, then normalize empty components. */
    url_err e = url_parse(norm_buf, n, out);
    if (e == URL_OK) {
        if (out->query_len == 0)    out->query = NULL;
        if (out->fragment_len == 0) out->fragment = NULL;
        /* IPv6 canonicalization (compress zero runs, lowercase hex).
         * Only shrinks — never grows — so pointer adjustment is a
         * memmove-left of everything after host, plus left-shift of
         * subsequent view fields. */
        if (out->is_ipv6 && out->host && out->host_len > 0) {
            size_t removed = whatwg_canonicalize_ipv6((char *)out->host,
                                                       out->host_len);
            if (removed > 0) {
                size_t host_off = (size_t)(out->host - norm_buf);
                memmove(norm_buf + host_off + (out->host_len - removed),
                        norm_buf + host_off + out->host_len,
                        n - host_off - out->host_len);
                n -= removed;
                norm_buf[n] = 0;
                out->host_len -= removed;
                if (out->path     && out->path     > out->host) out->path     -= removed;
                if (out->query    && out->query    > out->host) out->query    -= removed;
                if (out->fragment && out->fragment > out->host) out->fragment -= removed;
            }
            /* After canonicalization shrinks n, memmove left stale bytes
             * past the new end. Re-NUL-terminate so callers reading
             * norm_buf as a C string see the correct length. */
            norm_buf[n] = 0;
        }
    }
    if (norm_len_out) *norm_len_out = n;
    return e;
}

/* Deprecated: use url_parse_whatwg_stable for stable lifetime.
 * Kept for backward compatibility with existing callers (tests,
 * external code). The returned url_view points into a stack-local
 * buffer that is dead when this function returns — callers that need
 * the view to outlive this function must switch to _stable with
 * their own buffer. */
url_err url_parse_whatwg(const char *s, size_t len, url_view *out) {
    char local_buf[WHATWG_BUF];
    return url_parse_whatwg_stable(s, len, local_buf, sizeof local_buf, NULL, out);
}
