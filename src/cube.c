#ifdef _WIN32
    #define _WIN32_WINNT 0x0600
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <io.h>
    #include <time.h>
    #include <sys/stat.h>
    #include <sys/time.h>
    typedef SSIZE_T ssize_t;
    #define close _close
    #define read  _read
    #define write _write
    #define isatty _isatty
#else
    #include <poll.h>
    #include <time.h>
    #include <sys/stat.h>
    #include <sys/time.h>
#endif
/** cube.c — the cube orchestrator.
 *
 * Pipeline:
 *   URL parse  ->  DNS  ->  TCP  ->  [TLS]  ->  HTTP  ->  output
 *
 * Each stage lives in its own module:
 *   flywheel/url           parse URL into scheme/host/port/path
 *   net/dns                resolve host -> IP
 *   net/crisptls           TLS 1.3 handshake
 *   net/http_client        HTTP/1.x wire protocol
 *
 * This file glues them together and provides the CLI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

#include "url_parser.h"
#include "url_schemes.h"
#include "tcp.h"
#include "dns.h"
#include "crisptls.h"
#include "crisptls_policy.h"
#include "crisptls_fingerprint.h"
#include "http_client.h"
#include "http_protocol.h"
#include "http2.h"
#include "proxy.h"
#include "dom.h"
#include "dom_style.h"
#include "css.h"
#include "color.h"
#include "trace.h"
#include "html.h"
#include "json.h"
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#include <fcntl.h>
#include <sys/time.h>

static const char *g_argv0 = "cube";

/* CLI options */
typedef struct {
    const char *url;
    const char *output;      /* NULL = stdout */
    const char *profile;     /* TLS profile: chrome-120, firefox-121, curl-8 */
    const char *method;
    const char *data;        /* request body */
    const char *content_type;
    const char *user_agent;

    int         verbose;
    int         quiet;
    int         no_warnings;  /* --no-warnings: suppress library warnings */
    int         debug;       /* --debug: library traces on stderr */
    int         trace;       /* --trace: full byte-level trace */
    int         retries;      /* --retries N: default 3 */
    const char *urls[256];    /* positional URL/domain args + imported targets */
    int         n_urls;
    const char *input_file;   /* --input FILE: URL list, HAR, or curl command */
    const char *har_path;     /* --har/--intercept FILE */
    int         intercept;    /* --intercept: print capture events to stderr */
    int         no_decode;    /* --no-decode: leave Content-Encoding bodies raw */
    const char *proxy;        /* --proxy URL (http/socks5/socks5h) */
    const char *no_proxy;     /* --no-proxy LIST */
    int         body_only;   /* -b: print only the body */
    int         show_headers;
    int         show_cert;
    int         show_ja3;
    int         show_ja4;
    int         follow;      /* follow redirects */
    int         insecure;    /* skip cert verification */
    int         advisory;    /* warn on cert failure, do not abort */
    int         no_tls;      /* force plain HTTP */
    int         force_http1; /* force ALPN=http/1.1 */
    int         color_mode;  /* 0=auto, 1=force (--color), 2=never (--no-color) */
    int         head_lines;  /* 0=full, N=first N lines (--head N) */
    int         raw;         /* --raw: print body bytes as-is (no formatting) */
    const char *lines_spec;  /* --lines SPEC: "N", "N-M", ":N" (head), "-N:" (tail) */
    long        line_start;  /* 0 = unbounded, N = from start */
    long        line_end;    /* -1 = unbounded, N = up to N */
    int         debug_styles;  /* 1 = dump computed styles to stderr */
    int         ipv6_only;
    int         ipv4_only;

    int         cache;        /* --cache: enable response caching */
    int         no_reuse;    /* --no-reuse: disable connection reuse (default: reuse on) */
    int         cache_max_age; /* --cache-max-age N seconds (default 3600) */
    int         timeout_ms;
    size_t      max_url_len;    /* 0 = library default (8 MB) */
    size_t      max_norm_buf;   /* 0 = default 8192, capped at 1 MB */
    int         check_json;   /* 0=off, 1=JSON, 2=JSONC */
    int         interactive;  /* -I/--interactive: read commands from stdin */
} cube_opts_t;
/* Forward decl for repo-relative path resolution (defined near main). */
static const char *cube_repo_path(const char *rel, char *buf, size_t cap);
static void usage(const char *argv0) {
    fprintf(stderr,
"usage: %s [options] <url>\n"
"\n"
"Request:\n"
"  -X, --method M        HTTP method (default: GET)\n"
"  -d, --data DATA       request body\n"
"  -H, --header \"K: V\"   extra request header (repeatable, up to 16)\n"
"  -A, --user-agent UA   User-Agent header\n"
"  -L, --follow          follow redirects (default: on)\n"
"  --no-follow           do not follow redirects\n"
"\n"
"TLS:\n"
"  --profile NAME        chrome-120|firefox-121|curl-8|chrome-131|firefox-133|edge-120|safari-17\n"
"  --insecure            skip certificate verification\n"
"  --no-tls              force plain HTTP even for https:// URLs\n"
"  --proxy URL           HTTP/SOCKS5 proxy (http://, socks5://, socks5h://)\n"
"  --no-proxy LIST       comma/space separated hosts that bypass the proxy\n"
"  --input FILE          import targets from URL list, HAR, or curl command (- = stdin)\n"
"  --har FILE            write captured requests/responses as HAR 1.2\n"
"  --intercept [FILE]    print capture events; FILE defaults to cube.har\n"
"  --no-decode           do not decode gzip/deflate response bodies\n"
"  --http1               force ALPN=http/1.1 (no HTTP/2)\n"
"  --show-cert           print peer cert chain info\n"
"  --ja3                 print JA3 fingerprint\n"
"  --ja4                 print JA4 fingerprint\n"
"\n"
"Network:\n"
"  -4                    IPv4 only\n"
"  -6                    IPv6 only\n"
"  --timeout MS          per-stage timeout (default 15000)\n"
"  --max-url-len BYTES   max URL input length (default 8MB)\n"
"  --max-norm-buf BYTES  max normalized-URL buffer (default 8192, cap 1MB)\n"
"\n"
"Output:\n"
"  -o, --output FILE     write body to FILE (default: stdout)\n"
"  -i, --headers         print response headers only (no body)\n"
"  -v, --verbose         verbose: show each stage (URL, DNS, TCP, TLS, request)\n"
"  -q, --quiet           suppress all diagnostics\n"
"  -b, --body-only       print only the body (no headers)\n"
"  --head N              print only the first N lines of the body\n"
"  --color, --no-color   force / disable ANSI colors\n"
"  --debug               verbose + library traces (TLS, HTTP/2) on stderr\n"
"  --trace               debug + full byte-level tracing\n"
"  --retries N           network/HTTP retry attempts (default 3)\n"
"  --raw                 write body bytes as-is (no formatting/color)\n"
"  --lines SPEC          select body lines: N, N-M, :N, -N:\n"
"\n"
"Interactive:\n"
"  -I, --interactive     read commands from stdin (REPL; URL optional)\n"
"                        commands: help, get <url>, set <key> <value>,\n"
"                        unset <key>, show, quit/exit\n"
"\n"
"Validation:\n"
"  --check-json [FILE]   validate JSON from FILE (default: stdin)\n"
"  --check-jsonc [FILE]  validate JSON with comments/trailing commas\n"
"  -h, --help            this help\n"
"\n", argv0);
}

/* TLS wrappers for http_io_t */
static const char *tls_ver_str(int v) {
    static char buf[12];
    switch (v) {
        case 0x0304: return "TLS1.3";
        case 0x0303: return "TLS1.2";
        case 0x0302: return "TLS1.1";
        case 0x0301: return "TLS1.0";
        case 0x0300: return "SSL3";
    }
    snprintf(buf, sizeof buf, "0x%04x", (unsigned)v);
    return buf;
}

static ssize_t tls_read_fn(void *ctx, void *buf, size_t n) {
    TRACE_ENTER("io->read", "want=%zu", n);
    ssize_t r = crisptls_read((crisptls_conn_t *)ctx, buf, n);
    return r;
}
static ssize_t tls_write_fn(void *ctx, const void *buf, size_t n) {
    TRACE_ENTER("io->write", "want=%zu", n);
    ssize_t r = crisptls_write((crisptls_conn_t *)ctx, buf, n);
    return r;
}


/* DNS resolution */
/* Validate a hostname per RFC 1034/1123 before DNS resolution:
 *  - total 1..253 bytes
 *  - each label 1..63 bytes
 *  - labels contain only [A-Za-z0-9-]
 *  - labels don't start or end with '-'
 *  - no empty labels (leading/trailing dot, consecutive dots)
 * IP literals are handled by the inet_pton fast path before this. */
static int is_valid_dns_hostname(const char *host, size_t len) {
    if (len == 0 || len > 253) return 0;
    size_t label_start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || host[i] == '.') {
            size_t label_len = i - label_start;
            if (label_len == 0 || label_len > 63) return 0;
            if (host[label_start] == '-' || host[i - 1] == '-') return 0;
            for (size_t j = label_start; j < i; j++) {
                char c = host[j];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-'))
                    return 0;
            }
            label_start = i + 1;
        }
    }
    return 1;
}
static int ip_list_has(char ips[][64], size_t n, const char *ip) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(ips[i], ip) == 0) return 1;
    return 0;
}

/* Portable OS-resolver fallback. Used when the built-in resolver fails or
 * yields only one address family (common on networks where one family is
 * unreachable, or when an upstream silently drops a query). */
static int resolve_host_system(const char *host, int want4, int want6,
                               char ips[][64], int fams[], size_t max_n,
                               size_t *n_out, int verbose) {
    if (!want4 && !want6) return 0;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;

    int added = 0;
    for (int pass = 0; pass < 2; pass++) {
        int want = (pass == 0) ? AF_INET : AF_INET6;
        if ((want == AF_INET && !want4) || (want == AF_INET6 && !want6)) continue;
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            if (ai->ai_family != want) continue;
            char tmp[64];
            const void *src = (want == AF_INET)
                ? (const void *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr
                : (const void *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
            if (!inet_ntop(want, src, tmp, sizeof tmp)) continue;
            if (ip_list_has(ips, *n_out, tmp)) continue;
            if (*n_out >= max_n) { freeaddrinfo(res); return added ? 0 : -1; }
            snprintf(ips[*n_out], 64, "%.63s", tmp);
            fams[*n_out] = want;
            (*n_out)++;
            added++;
            if (verbose)
                fprintf(stderr, "%s[dns]%s %s: system %s\n",
                        col_cyan(), col_reset(), host, tmp);
        }
    }
    freeaddrinfo(res);
    return added ? 0 : -1;
}

static int g_dns_last_err = 0;
static int resolve_host_all(const char *host, int fam_pref,
                            char ips[][64], int fams[], size_t max_n, size_t *n_out,
                            int verbose) {
    TRACE_ENTER("DNS lookup", "host=%s", host);
    *n_out = 0;
    if (max_n == 0) { g_dns_last_err = DNS_ERR_ARGS; return -1; }

    /* Fast path: host is already an IP literal, no DNS needed. */
    {
        struct in_addr  a4;
        struct in6_addr a6;
        if (inet_pton(AF_INET, host, &a4) == 1) {
            snprintf(ips[0], 64, "%.63s", host);
            fams[0] = AF_INET;
            *n_out = 1;
            if (verbose) fprintf(stderr, "%s[dns]%s %s: literal IPv4\n", col_cyan(), col_reset(), host);
            return 0;
        }
        if (inet_pton(AF_INET6, host, &a6) == 1) {
            snprintf(ips[0], 64, "%.63s", host);
            fams[0] = AF_INET6;
            *n_out = 1;
            if (verbose) fprintf(stderr, "%s[dns]%s %s: literal IPv6\n", col_cyan(), col_reset(), host);
            return 0;
        }
    }

    /* Validate hostname shape before DNS. The literal-IP fast path
     * above already handled "1.2.3.4" and "[::1]"; this rejects
     * malformed DNS names ("example..com", "-example.com",
     * overlong labels) before they hit the resolver. */
    if (!is_valid_dns_hostname(host, strlen(host))) {
        if (verbose)
            fprintf(stderr, "%s[dns]%s %s: invalid hostname (DNS rules)\n", col_cyan(), col_reset(), host);
        g_dns_last_err = DNS_ERR_ARGS;
        return -1;
    }

    dns_resolver_t *r = dns_resolver_new_default();
    if (r) {
        dns_resolver_set_persist(r, "net/dns/cache/upstream_scores.txt");
        dns_resolver_set_cache_path(r, "net/dns/cache/hostname_cache.txt");
    }
    if (!r) { g_dns_last_err = DNS_ERR_NOMEM; return -1; }

    dns_answer_t ans;
    memset(&ans, 0, sizeof(ans));
    int rc = dns_resolve_dual(r, host, &ans);
    if (rc != DNS_OK) {
        if (verbose)
            fprintf(stderr, "%s[dns]%s %s: %s (trying system resolver)\n",
                    col_cyan(), col_reset(), host, dns_err_name(rc));
        dns_resolver_free(r);
        g_dns_last_err = rc;
        int want4 = (fam_pref != AF_INET6);
        int want6 = (fam_pref != AF_INET);
        if (resolve_host_system(host, want4, want6, ips, fams, max_n, n_out, verbose) == 0 && *n_out > 0)
            return 0;
        return -1;
    }

    if (verbose) fprintf(stderr, "%s[dns]%s dual returned %zu records\n", col_cyan(), col_reset(), ans.count);

    for (size_t i = 0; i < ans.count && *n_out < max_n; i++) {
        const dns_record_t *rec = &ans.records[i];
        if (fam_pref == AF_INET6) continue;
        if (rec->type != DNS_TYPE_A) continue;
        inet_ntop(AF_INET, rec->u.a.addr, ips[*n_out], 64);
        fams[*n_out] = AF_INET;
        (*n_out)++;
        if (verbose) fprintf(stderr, "%s[dns]%s A: %s\n", col_cyan(), col_reset(), ips[*n_out - 1]);
    }
    for (size_t i = 0; i < ans.count && *n_out < max_n; i++) {
        const dns_record_t *rec = &ans.records[i];
        if (fam_pref == AF_INET) continue;
        if (rec->type != DNS_TYPE_AAAA) continue;
        inet_ntop(AF_INET6, rec->u.aaaa.addr, ips[*n_out], 64);
        fams[*n_out] = AF_INET6;
        (*n_out)++;
        if (verbose) fprintf(stderr, "%s[dns]%s AAAA: %s\n", col_cyan(), col_reset(), ips[*n_out - 1]);
    }

    int has4 = 0, has6 = 0;
    for (size_t i = 0; i < *n_out; i++) {
        if (fams[i] == AF_INET) has4 = 1;
        else if (fams[i] == AF_INET6) has6 = 1;
    }
    int want4 = (fam_pref != AF_INET6) && !has4;
    int want6 = (fam_pref != AF_INET) && !has6;
    if (want4 || want6) {
        /* Supplements a dropped/blocked family. AI_ADDRCONFIG stops the
         * system from returning IPv6 addresses on IPv4-only networks. */
        resolve_host_system(host, want4, want6, ips, fams, max_n, n_out, verbose);
    }

    /* Stable IPv4-first ordering unless the caller asked for IPv6. */
    if (fam_pref != AF_INET6) {
        size_t w = 0;
        for (int pass = 0; pass < 2; pass++) {
            int want = (pass == 0) ? AF_INET : AF_INET6;
            for (size_t i = w; i < *n_out; i++) {
                if (fams[i] != want) continue;
                char t[64]; memcpy(t, ips[i], sizeof t);
                memcpy(ips[i], ips[w], sizeof t);
                memcpy(ips[w], t, sizeof t);
                int f = fams[i]; fams[i] = fams[w]; fams[w] = f;
                w++;
            }
        }
    }

    dns_answer_free(&ans);
    dns_resolver_free(r);
    if (*n_out == 0) {
        g_dns_last_err = DNS_ERR_NO_RECORDS;
        return -1;
    }
    return 0;
}

/* Output helpers */
static const char *http_version_str(http_version_t v) {
    switch (v) {
        case HTTP_09: return "HTTP/0.9";
        case HTTP_10: return "HTTP/1.0";
        case HTTP_11: return "HTTP/1.1";
        case HTTP_2:  return "HTTP/2";
    }
    return "HTTP/?";
}

static void dump_response_headers(const http_response_t *r) {
    /* Status line: bold + green if 2xx, yellow if 3xx, red otherwise */
    const char *sc = (r->status_code >= 200 && r->status_code < 300) ? col_green()
                   : (r->status_code >= 300 && r->status_code < 400) ? col_yellow()
                   :                                                    col_red();
    printf("%s%s%s %s%d%s %s%s%s\n",
           col_bold(), http_version_str(r->version), col_reset(),
           sc, r->status_code, col_reset(),
           col_bold(), r->reason ? r->reason : "", col_reset());
    /* Headers: name in cyan, colon, value in default */
    for (size_t i = 0; i < r->headers.count; i++) {
        printf("%s%s%s: %s\n",
               col_cyan(), r->headers.items[i].name, col_reset(),
               r->headers.items[i].value);
    }
    printf("\n");
}

/* Byte length of the first n lines of s (all of it if n <= 0 or fewer lines exist). */
/* Apply a line slice to a buffer in place. start: 0=unbounded. end: -1=unbounded.
 * Negative start means "last N lines" (start = -(len-N)+1). */
static size_t apply_line_slice(char *s, size_t len, long start, long end) {
    if (start == 0 && end == -1) return len;
    /* Count total lines */
    size_t total = 0;
    for (size_t i = 0; i < len; i++) if (s[i] == '\n') total++;
    if (len > 0 && s[len-1] != '\n') total++;  /* last partial line */

    long s_line = start;
    if (s_line < 0) {
        /* last N lines: start = -N means last N */
        s_line = (long)total + s_line + 1;
        if (s_line < 1) s_line = 1;
    }
    if (s_line == 0) s_line = 1;

    long e_line = (end == -1) ? (long)total : end;
    if (e_line > (long)total) e_line = (long)total;
    if (s_line > e_line) return 0;

    /* Walk to line s_line */
    size_t pos = 0;
    long cur = 1;
    while (pos < len && cur < s_line) {
        if (s[pos] == '\n') cur++;
        pos++;
    }
    size_t start_pos = pos;

    /* Walk to end of line e_line */
    cur = s_line;
    while (pos < len && cur <= e_line) {
        if (s[pos] == '\n') cur++;
        pos++;
    }
    size_t end_pos = pos;

    /* Shift */
    size_t new_len = end_pos - start_pos;
    if (start_pos > 0) memmove(s, s + start_pos, new_len);
    return new_len;
}


static size_t cube_cap_lines(const char *s, size_t len, int n) {
    if (n <= 0) return len;
    int count = 0;
    for (size_t i = 0; i < len; i++)
        if (s[i] == '\n' && ++count == n) return i + 1;
    return len;
}

/* Dump computed style summary for each element in the DOM to stderr.
 * Called from write_body when --debug-styles is set on an HTML response.
 * Does not affect stdout — the normal formatted body still goes there. */
static void debug_styles_dump(const char *src, size_t len) {
    html_document_t *doc = html_parse(src, len);
    if (!doc) { fprintf(stderr, "[style] html_parse failed\n"); return; }

    const html_node_t *style = html_find_tag(doc->root, "style");
    int clen = 0;
    char css_buf[65536];
    if (style) clen = html_raw_text(style, css_buf, sizeof(css_buf));

    css_stylesheet_t *ss = NULL;
    if (clen > 0) {
        ss = css_parse(css_buf, (size_t)clen);
    }
    fprintf(stderr, "[style] html_parse ok, %d nodes, %d bytes css, %d rules\n",
            doc->n_nodes, clen, ss ? ss->n_rules : 0);

    if (ss) {
        int n = dom_apply_stylesheet(doc, ss);
        fprintf(stderr, "[style] dom_apply_stylesheet: %d elements styled\n", n);

        /* Walk the tree, print per-element computed style. */
        html_node_t *stack[1024];
        int top = 0;
        stack[top++] = doc->root;
        int printed = 0;
        while (top > 0 && printed < 50) {
            html_node_t *node = stack[--top];
            if (node->kind == HTML_NODE_ELEMENT) {
                computed_style_t cs;
                if (dom_compute_style(ss, node, &cs) == 0) {
                    if (cs.display[0] || cs.font_size[0] ||
                        cs.has_color || cs.has_bg) {
                        fputs("[style] <", stderr);
                        if (node->tag && node->tag_len > 0)
                            fwrite(node->tag, 1, (size_t)node->tag_len, stderr);
                        fputs(">", stderr);
                        fprintf(stderr, "> display=%s font-size=%s font-family=%s",
                                cs.display[0] ? cs.display : "-",
                                cs.font_size[0] ? cs.font_size : "-",
                                cs.font_family[0] ? cs.font_family : "-");
                        if (cs.has_color) fprintf(stderr, " color=#%06x", cs.color_rgb);
                        if (cs.has_bg)    fprintf(stderr, " bg=#%06x", cs.bg_rgb);
                        fprintf(stderr, "\n");
                        printed++;
                    }
                }
            }
            html_node_t *kids[64];
            int nk = 0;
            for (html_node_t *c = node->first_child; c && nk < 64; c = c->next_sibling)
                kids[nk++] = c;
            for (int i = nk - 1; i >= 0; i--)
                if (top < 1024) stack[top++] = kids[i];
        }
        css_free(ss);
    }
    html_free(doc);
}

/* Reformat compact <style>...</style> blocks with line breaks so
 * CSS rules appear on separate lines. Text-level, no parser needed:
 *   "html{a:b;c:d}" -> "html {\n  a: b;\n  c: d;\n}"
 * Does not change meaning, only whitespace. */
/* Reformat compact <style>...</style> blocks with line breaks and
 * indentation matching the <style> tag's depth in the HTML. */
/* Reformat compact <style>...</style> CSS with line breaks and
 * indentation matching the <style> tag's depth in the HTML.
 * Preserves internal spaces in values (font: 16px/1.6 system-ui). */
/* Reformat compact <style>...</style> CSS with line breaks and
 * consistent 2-space indent for rules, 4-space for declarations.
 * Fixed indent (not source-derived) because caller invokes this on
 * compact HTML before html_format runs — no source indentation
 * exists at this point. html_format will not re-indent <style>
 * contents (verbatim), so this layout sticks. */
static char *prettify_styles(const char *src, size_t len, size_t *out_len) {
    size_t cap = len * 4 + 1024;
    char *out = malloc(cap);
    if (!out) return NULL;
    size_t o = 0;
    int in_style = 0;
    int depth = 0;
    int at_line_start = 1;

#define EMIT(ch) do { if (o + 1 < cap) out[o++] = (ch); } while (0)
#define EMIT_N(s_, n_) do { if (o + (n_) < cap) { memcpy(out + o, (s_), (n_)); o += (n_); } } while (0)

    for (size_t i = 0; i < len; i++) {
        char c = src[i];

        /* <style ...> open */
        if (!in_style && i + 5 < len && src[i] == '<' &&
            (src[i+1] == 's' || src[i+1] == 'S') &&
            src[i+2] == 't' && src[i+3] == 'y' &&
            src[i+4] == 'l' && src[i+5] == 'e') {
            size_t tag_end = i;
            while (tag_end < len && src[tag_end] != '>') tag_end++;
            if (tag_end < len) tag_end++;
            EMIT_N(src + i, tag_end - i);
            EMIT('\n');
            in_style = 1;
            at_line_start = 1;
            depth = 0;
            i = tag_end - 1;
            continue;
        }

        /* </style> close */
        if (in_style && i + 7 < len && src[i] == '<' && src[i+1] == '/') {
            if (!at_line_start) EMIT('\n');
            EMIT_N("</style>", 8);
            in_style = 0;
            i += 7;
            continue;
        }

        if (!in_style) { EMIT(c); continue; }

        /* CSS mode — collapse whitespace, structure by tokens */
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (!at_line_start) {
                size_t k = i + 1;
                while (k < len && (src[k]==' '||src[k]=='\t'||src[k]=='\n'||src[k]=='\r')) k++;
                if (k < len && src[k] != '}' && src[k] != '{' && src[k] != ';')
                    EMIT(' ');
                while (i + 1 < len && (src[i+1]==' '||src[i+1]=='\t'||src[i+1]=='\n'||src[i+1]=='\r')) i++;
            } else {
                while (i + 1 < len && (src[i+1]==' '||src[i+1]=='\t'||src[i+1]=='\n'||src[i+1]=='\r')) i++;
            }
            continue;
        }

        if (at_line_start) {
            if (depth == 1) EMIT_N("    ", 4);   /* declarations at 4 */
            else            EMIT_N("  ", 2);     /* rules at 2 */
            at_line_start = 0;
        }

        if (c == '{') { EMIT(' '); EMIT('{'); EMIT('\n'); depth = 1; at_line_start = 1; continue; }
        if (c == '}') {
            if (!at_line_start) EMIT('\n');
            EMIT_N("  ", 2); EMIT('}'); EMIT('\n');
            depth = 0; at_line_start = 1;
            continue;
        }
        if (c == ';') { EMIT(';'); EMIT('\n'); at_line_start = 1; continue; }
        EMIT(c);
    }
    out[o] = 0;
    *out_len = o;
    return out;
}
static int write_body(const http_response_t *r, const char *path,
                      const cube_opts_t *o) {
    FILE *fp = path ? fopen(path, "wb") : stdout;
    if (!fp) {
        fprintf(stderr, "%s[!] cannot open %s: %s%s\n", col_red(), path, strerror(errno), col_reset());
        return -1;
    }

    /* --head N: cap to first N lines of body */
    size_t blen_all = r->body_len;   /* HTML is capped after formatting, other types by raw lines */
    size_t blen = cube_cap_lines((const char *)r->body, blen_all, o->head_lines);

    /* Color decision: colors are on by default, but never contaminate a
     * file written with -o and never when --raw/--no-color is used. */
    int to_file = (path != NULL);
    int want_color = !to_file && !o->raw && (o->color_mode != 2);
    const char *ct = http_headers_get((http_headers_t *)&r->headers, "Content-Type");
    int is_html = ct && strstr(ct, "html");
    int is_json = ct && strstr(ct, "json");
    int is_css  = ct && strstr(ct, "css");
    int is_xml  = ct && strstr(ct, "xml") && !is_html;

    if (to_file || o->raw) {
        fwrite(r->body, 1, blen, fp);
    }
    else if (is_html) {
        if (o->debug_styles) debug_styles_dump((const char *)r->body, blen_all);
        /* Format HTML into a temp file, cap to --head N lines of the FORMATTED text,
         * then colorize only if want_color. Raw fallback if formatting fails. */
        FILE *tmp = tmpfile();
        char *fmt = NULL; size_t flen = 0;
        size_t pretty_len = 0;
        char *pretty = prettify_styles((const char *)r->body, blen_all, &pretty_len);
        if (tmp && html_format(pretty ? pretty : (const char *)r->body,
                               pretty ? pretty_len : blen_all, tmp) == 0) {
            long sz = -1;
            if (fflush(tmp) == 0 && fseek(tmp, 0, SEEK_END) == 0 &&
                (sz = ftell(tmp)) >= 0 && fseek(tmp, 0, SEEK_SET) == 0) {
                fmt = malloc((size_t)sz + 1);
                if (fmt) flen = fread(fmt, 1, (size_t)sz, tmp);
            }
        }
        if (tmp) fclose(tmp);
        if (fmt) {
            if (o->lines_spec) flen = apply_line_slice(fmt, flen, o->line_start, o->line_end);
            else               flen = cube_cap_lines(fmt, flen, o->head_lines);
            if (want_color) html_colorize(fmt, flen, fp);
            else            fwrite(fmt, 1, flen, fp);
            free(fmt);
            free(pretty);
        } else {
            fwrite(r->body, 1, blen, fp);
        }
    }
    else if (want_color && is_json) json_colorize((const char *)r->body, blen, fp);
    else if (want_color && is_css)  css_colorize((const char *)r->body, blen, fp);
    else if (want_color && is_xml)  html_colorize((const char *)r->body, blen, fp);
    else                            fwrite(r->body, 1, blen, fp);

    if (path) fclose(fp);
    return 0;
}

static void apply_runtime_opts(const cube_opts_t *o) {
    int dbg = o->debug || o->trace;
    crisptls_set_trace(o->trace ? 1 : 0);
    http_client_set_trace(dbg ? 1 : 0);
    crisptls_set_color(o->color_mode != 2);
    crisptls_set_quiet((o->quiet || o->no_warnings || !dbg) ? 1 : 0);
    if (o->color_mode == 2) col_disable();
    else                    col_force(1);
}

/* Main */
/* ---- Target import, HAR capture, content decoding ---------------------- */

static int cube_ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++, cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

static int add_url(cube_opts_t *o, const char *s, size_t len) {
    while (len && isspace((unsigned char)*s)) { s++; len--; }
    while (len && isspace((unsigned char)s[len - 1])) len--;
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
                     (s[0] == '\'' && s[len - 1] == '\''))) { s++; len -= 2; }
    if (!len || s[0] == '#') return 0;
    if (o->n_urls >= (int)(sizeof(o->urls) / sizeof(o->urls[0]))) return -1;
    char *p = (char *)malloc(len + 1);
    if (!p) return -1;
    memcpy(p, s, len); p[len] = 0;
    o->urls[o->n_urls++] = p;
    if (!o->url) o->url = p;
    return 0;
}

static void add_targets_text(cube_opts_t *o, const char *text) {
    const char *p = text;
    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',' || *p == ';')) p++;
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && *p != ',' && *p != ';') p++;
        if (p > start && add_url(o, start, (size_t)(p - start)) != 0)
            fprintf(stderr, "%scube: target list full (max %zu)%s\n",
                    col_red(), sizeof(o->urls) / sizeof(o->urls[0]), col_reset());
    }
}

static int har_extract_urls(cube_opts_t *o, const char *buf) {
    const char *p = buf;
    int found = 0;
    while ((p = strstr(p, "\"url\"")) != NULL) {
        p += 5;
        while (*p && *p != ':' && *p != '}') p++;
        if (*p != ':') continue;
        p++;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p != '"') continue;
        p++;
        char tmp[4096]; size_t n = 0;
        while (*p && *p != '"' && n + 1 < sizeof tmp) {
            if (*p == '\\' && p[1]) {
                p++;
                switch (*p) {
                case 'n': tmp[n++] = ' '; break;
                case 't': tmp[n++] = ' '; break;
                case 'r': tmp[n++] = ' '; break;
                case '/': tmp[n++] = '/'; break;
                case '"': tmp[n++] = '"'; break;
                case '\\': tmp[n++] = '\\'; break;
                case 'u':
                    if (p[1] && p[2] && p[3] && p[4]) p += 4;
                    tmp[n++] = '?';
                    break;
                default: tmp[n++] = *p; break;
                }
                p++;
            } else tmp[n++] = *p++;
        }
        tmp[n] = 0;
        if (n) { add_url(o, tmp, n); found = 1; }
    }
    return found;
}

static int curl_extract_urls(cube_opts_t *o, const char *buf) {
    const char *p = buf;
    int found = 0;
    while (*p) {
        const char *h = strstr(p, "http://");
        const char *s = strstr(p, "https://");
        if (!h || (s && s < h)) h = s;
        if (!h) break;
        const char *e = h;
        while (*e && !isspace((unsigned char)*e) && *e != '\'' && *e != '"') e++;
        if (add_url(o, h, (size_t)(e - h)) == 0) found = 1;
        p = e;
    }
    if (!found) {
        /* curl bare-domain form: take first token after "curl" that is not a flag */
        p = strstr(buf, "curl");
        p = p ? p + 4 : buf;
        while (*p) {
            while (*p && isspace((unsigned char)*p)) p++;
            const char *st = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            if (p > st && *st != '-') { add_url(o, st, (size_t)(p - st)); found = 1; break; }
        }
    }
    return found;
}

static int load_targets_file(cube_opts_t *o, const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "rb") : stdin;
    if (!f) {
        fprintf(stderr, "%scube: cannot open %s: %s%s\n",
                col_red(), path, strerror(errno), col_reset());
        return -1;
    }
    size_t cap = 1 << 16, len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) { if (f != stdin) fclose(f); return -1; }
    for (;;) {
        if (len == cap) {
            if (cap >= 64u * 1024u * 1024u) break;
            char *nb = (char *)realloc(buf, cap * 2 + 1);
            if (!nb) { free(buf); if (f != stdin) fclose(f); return -1; }
            buf = nb; cap *= 2;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    if (f != stdin) fclose(f);
    buf[len] = 0;
    if (strstr(buf, "\"entries\"") && strstr(buf, "\"url\""))
        har_extract_urls(o, buf);
    else if (strstr(buf, "curl") && (strstr(buf, "--url") || strstr(buf, "://")))
        curl_extract_urls(o, buf);
    else
        add_targets_text(o, buf);
    free(buf);
    if (o->n_urls == 0) {
        fprintf(stderr, "%scube: no targets found in %s%s\n", col_red(), path, col_reset());
        return -1;
    }
    return 0;
}

/* ---- HAR 1.2 writer (streaming) ---- */
static FILE *g_har = NULL;
static int   g_har_first = 1;

static void har_str(FILE *f, const char *s, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

static void har_begin(const char *path) {
    g_har = fopen(path, "wb");
    if (!g_har) {
        fprintf(stderr, "%scube: cannot write %s: %s%s\n",
                col_red(), path, strerror(errno), col_reset());
        return;
    }
    g_har_first = 1;
    fputs("{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"cube\",\"version\":\"1.0\"},"
          "\"entries\":[\n", g_har);
}

static void har_end(void) {
    if (!g_har) return;
    fputs("\n]}}\n", g_har);
    fclose(g_har);
    g_har = NULL;
}

static int header_is(const char *name, const char *want) { return cube_ci_eq(name, want); }

static const char *header_ci(const http_response_t *r, const char *name) {
    for (size_t i = 0; i < r->headers.count; i++)
        if (header_is(r->headers.items[i].name, name)) return r->headers.items[i].value;
    return NULL;
}

#ifdef HAVE_ZLIB
static void header_remove(http_headers_t *h, const char *name) {
    for (size_t i = 0; i < h->count; i++) {
        if (!header_is(h->items[i].name, name)) continue;
        free(h->items[i].name);
        free(h->items[i].value);
        memmove(&h->items[i], &h->items[i + 1], (h->count - i - 1) * sizeof(h->items[0]));
        h->count--;
        return;
    }
}
#endif /* HAVE_ZLIB */

#ifdef HAVE_ZLIB
static int inflate_buffer(const unsigned char *in, size_t in_len, int wbits,
                          unsigned char **out, size_t *out_len) {
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, wbits) != Z_OK) return -1;
    size_t cap = in_len * 4 + 1024, len = 0;
    if (cap < 4096) cap = 4096;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) { inflateEnd(&zs); return -1; }
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        if (len == cap) {
            if (cap >= 256u * 1024u * 1024u) { rc = Z_MEM_ERROR; break; }
            unsigned char *nb = (unsigned char *)realloc(buf, cap * 2);
            if (!nb) { rc = Z_MEM_ERROR; break; }
            buf = nb; cap *= 2;
        }
        zs.next_out = buf + len;
        zs.avail_out = (uInt)(cap - len);
        rc = inflate(&zs, Z_NO_FLUSH);
        len = cap - zs.avail_out;
        if (rc != Z_OK && rc != Z_STREAM_END) break;
        if (zs.avail_in == 0 && rc == Z_OK) break;
    }
    inflateEnd(&zs);
    if (rc != Z_STREAM_END || len == 0) { free(buf); return -1; }
    *out = buf; *out_len = len;
    return 0;
}
#endif /* HAVE_ZLIB */

static int decode_response(http_response_t *r) {
#ifdef HAVE_ZLIB
    const char *ce = header_ci(r, "Content-Encoding");
    if (!ce || !r->body || r->body_len == 0) return 0;
    int gz = strstr(ce, "gzip") != NULL || strstr(ce, "x-gzip") != NULL;
    int df = strstr(ce, "deflate") != NULL;
    if (!gz && !df) return 0;
    unsigned char *out = NULL; size_t out_len = 0;
    int ok = -1;
    if (gz) ok = inflate_buffer(r->body, r->body_len, 16 + MAX_WBITS, &out, &out_len);
    else {
        ok = inflate_buffer(r->body, r->body_len, MAX_WBITS, &out, &out_len);
        if (ok != 0) ok = inflate_buffer(r->body, r->body_len, -MAX_WBITS, &out, &out_len);
    }
    if (ok != 0) return -1;
    free(r->body);
    r->body = out;
    r->body_len = out_len;
    header_remove(&r->headers, "Content-Encoding");
    header_remove(&r->headers, "Content-Length");
    return 1;
#else
    (void)r;
    return 0;   /* zlib not available at build time */
#endif
}

static void har_record(const char *url, const char *method,
                       const http_response_t *r, long elapsed_ms) {
    if (!g_har) return;
    if (!g_har_first) fputs(",\n", g_har);
    g_har_first = 0;

    char date[64] = "";
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &now);
#else
    gmtime_r(&now, &tmv);
#endif
    strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%SZ", &tmv);

    const char *mime = header_ci(r, "Content-Type");
    fputs("{\"startedDateTime\":", g_har);
    har_str(g_har, date, strlen(date));
    fprintf(g_har, ",\"time\":%ld,\"request\":{\"method\":", elapsed_ms);
    har_str(g_har, method ? method : "GET", strlen(method ? method : "GET"));
    fputs(",\"url\":", g_har);
    har_str(g_har, url, strlen(url));
    fputs(",\"httpVersion\":\"HTTP/1.1\",\"headers\":[],\"queryString\":[],"
          "\"cookies\":[],\"headersSize\":-1,\"bodySize\":0},", g_har);
    fprintf(g_har, "\"response\":{\"status\":%d,\"statusText\":", r->status_code);
    har_str(g_har, r->reason ? r->reason : "", r->reason ? strlen(r->reason) : 0);
    fputs(",\"httpVersion\":\"HTTP/1.1\",\"headers\":[", g_har);
    for (size_t i = 0; i < r->headers.count; i++) {
        if (i) fputc(',', g_har);
        fputs("{\"name\":", g_har);
        har_str(g_har, r->headers.items[i].name, strlen(r->headers.items[i].name));
        fputs(",\"value\":", g_har);
        har_str(g_har, r->headers.items[i].value, strlen(r->headers.items[i].value));
        fputc('}', g_har);
    }
    fputs("],\"content\":{\"size\":", g_har);
    fprintf(g_har, "%zu,\"mimeType\":", r->body_len);
    har_str(g_har, mime ? mime : "", mime ? strlen(mime) : 0);
    int textual = mime && (strstr(mime, "text/") || strstr(mime, "json") ||
                           strstr(mime, "xml") || strstr(mime, "javascript"));
    if (textual && r->body && r->body_len <= 65536) {
        fputs(",\"text\":", g_har);
        har_str(g_har, (const char *)r->body, r->body_len);
    }
    fputs("},\"redirectURL\":\"\",\"headersSize\":-1,\"bodySize\":", g_har);
    fprintf(g_har, "%zu},", r->body_len);
    fprintf(g_har, "\"cache\":{},\"timings\":{\"send\":0,\"wait\":%ld,\"receive\":0}}",
            elapsed_ms);
}

static int parse_args(int argc, char **argv, cube_opts_t *o,
                     const char **extra_headers, int *n_extra) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-H") && i + 1 >= argc) { fprintf(stderr, "%scube: -H requires a value%s\n", col_red(), col_reset()); return -1; }
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); exit(0); }
        if (!strcmp(a, "--protocols")) {
            const http_protocol_t *const *pp = http_protocol_all();
            for (int k = 0; pp[k]; k++)
                printf("%-8s transport=%-4s %s%s\n", pp[k]->name, pp[k]->transport,
                       http_protocol_available(pp[k]->name) ? "available" : "registered (not wired)",
                       (pp[k]->caps & HTTP_PCAP_EXPERIMENTAL) ? " [experimental]" : "");
            exit(0);
        }
        if (!strcmp(a, "-I") || !strcmp(a, "--interactive")) { o->interactive = 1; continue; }
        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) { o->verbose = 1; continue; }
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))   { o->quiet = 1; continue; }
        if (!strcmp(a, "--no-warnings"))  { o->no_warnings = 1; continue; }
        if (!strcmp(a, "-i") || !strcmp(a, "--headers")) { o->show_headers = 1; continue; }
        if (!strcmp(a, "--debug"))        { o->debug = 1; continue; }
        if (!strcmp(a, "--trace"))        { o->trace = 1; continue; }
        if (!strcmp(a, "--retries") && i + 1 < argc) { o->retries = atoi(argv[++i]); continue; }
        if (!strcmp(a, "-b") || !strcmp(a, "--body-only")) { o->body_only = 1; continue; }
        if (!strcmp(a, "-L") || !strcmp(a, "--follow"))  { o->follow = 1; continue; }
        if (!strcmp(a, "--no-follow"))    { o->follow = 0; continue; }
        if (!strcmp(a, "--insecure"))     { o->insecure = 1; continue; }
        if (!strcmp(a, "--advisory"))     { o->advisory = 1; continue; }
        if (!strcmp(a, "--no-tls"))       { o->no_tls = 1; continue; }
        if (!strcmp(a, "--no-decode"))    { o->no_decode = 1; continue; }
        if (!strcmp(a, "--proxy")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: --proxy requires a value%s\n", col_red(), col_reset()); return -1; }
            o->proxy = argv[++i]; continue;
        }
        if (!strcmp(a, "--no-proxy")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: --no-proxy requires a value%s\n", col_red(), col_reset()); return -1; }
            o->no_proxy = argv[++i]; continue;
        }
        if (!strcmp(a, "--input")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: --input requires a value%s\n", col_red(), col_reset()); return -1; }
            o->input_file = argv[++i]; continue;
        }
        if (!strcmp(a, "--har")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: --har requires a value%s\n", col_red(), col_reset()); return -1; }
            o->har_path = argv[++i]; continue;
        }
        if (!strcmp(a, "--intercept")) {
            o->intercept = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-' &&
                (strstr(argv[i + 1], ".har") || strstr(argv[i + 1], ".json")))
                o->har_path = argv[++i];
            else if (!o->har_path)
                o->har_path = "cube.har";
            continue;
        }
        if (!strcmp(a, "--http1"))        { o->force_http1 = 1; continue; }
        if (!strcmp(a, "--show-cert"))    { o->show_cert = 1; continue; }
        if (!strcmp(a, "--ja3"))          { o->show_ja3 = 1; continue; }
        if (!strcmp(a, "--ja4"))          { o->show_ja4 = 1; continue; }
        if (!strcmp(a, "-4"))             { o->ipv4_only = 1; continue; }
        if (!strcmp(a, "-6"))             { o->ipv6_only = 1; continue; }
        if (!strcmp(a, "--color"))        { o->color_mode = 1; continue; }
        if (!strcmp(a, "--no-color"))     { o->color_mode = 2; continue; }

        /* Every value-taking flag MUST have an argument. */
        if (!strcmp(a, "-X") || !strcmp(a, "--method")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->method = argv[++i]; continue;
        }
        if (!strcmp(a, "-d") || !strcmp(a, "--data")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->data = argv[++i]; continue;
        }
        if (!strcmp(a, "-A") || !strcmp(a, "--user-agent")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->user_agent = argv[++i]; continue;
        }
        if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->output = argv[++i]; continue;
        }
        if (!strcmp(a, "--profile")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->profile = argv[++i]; continue;
        }
        if (!strcmp(a, "--timeout")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->timeout_ms = atoi(argv[++i]); continue;
        }
        if (!strcmp(a, "--max-url-len")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->max_url_len = (size_t)atol(argv[++i]); continue;
        }
        if (!strcmp(a, "--max-norm-buf")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->max_norm_buf = (size_t)atol(argv[++i]); continue;
        }
        if (!strcmp(a, "--content-type")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->content_type = argv[++i]; continue;
        }
        if (!strcmp(a, "--head")) {
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            o->head_lines = atoi(argv[++i]); continue;
        }
        if (!strcmp(a, "--debug-styles"))  { o->debug_styles = 1; continue; }
        if (!strcmp(a, "--lines") && i + 1 < argc) {
            const char *spec = argv[++i];
            o->lines_spec = spec;
            /* Parse SPEC: N | N-M | :N | -N: */
            long s = 0, e = -1;
            const char *p = spec;
            if (*p == ':') {
                s = 1; e = atol(p + 1);
            } else if (*p == '-') {
                long back = atol(p + 1);
                s = -back; e = -1;
            } else {
                s = atol(p);
                const char *dash = strchr(p, '-');
                if (dash) e = atol(dash + 1);
                else      e = s;
            }
            o->line_start = s;
            o->line_end   = e;
            continue;
        }
        if (!strcmp(a, "--check-json"))    { o->check_json = 1; continue; }
        if (!strcmp(a, "--check-jsonc"))   { o->check_json = 2; continue; }
        if (!strcmp(a, "--raw"))           { o->raw = 1; continue; }
        if (!strcmp(a, "--cache"))         { o->cache = 1; continue; }
        if (!strcmp(a, "--cache-max-age") && i + 1 < argc) { o->cache_max_age = atoi(argv[++i]); continue; }
        if (!strcmp(a, "--no-reuse"))      { o->no_reuse = 1; continue; }
        if (!strcmp(a, "-H") || !strcmp(a, "--header")) {
            if (*n_extra >= 16) { fprintf(stderr, "%stoo many -H%s\n", col_red(), col_reset()); return -1; }
            if (i + 1 >= argc) { fprintf(stderr, "%scube: %s requires a value%s\n", col_red(), a, col_reset()); return -1; }

            extra_headers[(*n_extra)++] = argv[++i]; continue;
        }
        if (a[0] == '-') { fprintf(stderr, "%sunknown option %s%s\n", col_red(), a, col_reset()); return -1; }
        add_targets_text(o, a);
        continue;
        fprintf(stderr, "%sunexpected argument: %s%s\n", col_red(), a, col_reset());
        return -1;
    }
    if (o->input_file && load_targets_file(o, o->input_file) != 0) return -1;
    if (!o->url && !o->check_json && !o->interactive) { usage(argv[0]); return -1; }
    return 0;
}

/* One fetch: URL parse → DNS → TCP → TLS → HTTP send.
 * Fills *resp with the response (body in memory).
 * Returns 0 on success, or one of 2/3/4/5/7 on failure.
 * On success, *tls_out and *fd_out are the connection handles; caller
 * is responsible for closing them (via print_response or redirect cleanup). */
/* ---- Response cache (--cache) ---- */

static void cache_dir(char *out, size_t cap) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(out, cap, "%s/.cache/cube", home);
}

/* Simple FNV-1a hash of the URL → hex filename */
static void cache_path(const char *url, char *out, size_t cap) {
    uint64_t h = 1469598103934665603ULL;
    for (const char *p = url; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    char dir[512];
    cache_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/%016llx.bin", dir, (unsigned long long)h);
}

/* Save response to cache file. Returns 0 on success. */
static int cache_save(const char *url, const http_response_t *resp, int max_age) {
    char dir[512];
    cache_dir(dir, sizeof dir);
    mkdir(dir, 0700);
    char path[1024];
    cache_path(url, path, sizeof path);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* Magic + version */
    fwrite("CUBE1\0", 1, 6, f);
    /* Status + version */
    uint16_t st = (uint16_t)resp->status_code;
    uint16_t ver = (uint16_t)resp->version;
    fwrite(&st, 2, 1, f);
    fwrite(&ver, 2, 1, f);
    /* Header count */
    uint16_t nh = (uint16_t)resp->headers.count;
    fwrite(&nh, 2, 1, f);
    /* Each header */
    for (size_t i = 0; i < resp->headers.count; i++) {
        const http_header_t *h = &resp->headers.items[i];
        uint16_t nl = (uint16_t)strlen(h->name ? h->name : "");
        uint16_t vl = (uint16_t)strlen(h->value ? h->value : "");
        fwrite(&nl, 2, 1, f);
        if (nl) fwrite(h->name, 1, nl, f);
        fwrite(&vl, 2, 1, f);
        if (vl) fwrite(h->value, 1, vl, f);
    }
    /* Body */
    uint32_t bl = (uint32_t)resp->body_len;
    fwrite(&bl, 4, 1, f);
    if (bl) fwrite(resp->body, 1, bl, f);
    fclose(f);

    /* Set mtime (informational) — actual freshness uses Cache-Control or max_age */
    (void)max_age;
    return 0;
}

/* Load response from cache. Returns 0 if hit and fresh, -1 if miss or stale. */
static int cache_load(const char *url, http_response_t *resp, int max_age) {
    char path[1024];
    cache_path(url, path, sizeof path);

    struct stat sb;
    if (stat(path, &sb) != 0) return -1;

    /* Freshness: file mtime + max_age > now */
    time_t now = time(NULL);
    if (now > sb.st_mtime + max_age) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char magic[6];
    if (fread(magic, 1, 6, f) != 6 || memcmp(magic, "CUBE1\0", 6) != 0) {
        fclose(f); return -1;
    }
    uint16_t st, ver, nh;
    if (fread(&st, 2, 1, f) != 1) { fclose(f); return -1; }
    if (fread(&ver, 2, 1, f) != 1) { fclose(f); return -1; }
    if (fread(&nh, 2, 1, f) != 1) { fclose(f); return -1; }

    memset(resp, 0, sizeof(*resp));
    resp->status_code = st;
    resp->version = (http_version_t)ver;
    http_headers_init(&resp->headers);

    for (uint16_t i = 0; i < nh; i++) {
        uint16_t nl, vl;
        char name[256], value[4096];
        if (fread(&nl, 2, 1, f) != 1 || nl >= sizeof(name)) { http_response_free(resp); fclose(f); return -1; }
        if (nl) fread(name, 1, nl, f);
        name[nl] = 0;
        if (fread(&vl, 2, 1, f) != 1 || vl >= sizeof(value)) { http_response_free(resp); fclose(f); return -1; }
        if (vl) fread(value, 1, vl, f);
        value[vl] = 0;
        http_headers_add(&resp->headers, name, value);
    }
    uint32_t bl;
    if (fread(&bl, 4, 1, f) != 1) { http_response_free(resp); fclose(f); return -1; }
    resp->body = malloc(bl ? bl : 1);
    if (!resp->body) { http_response_free(resp); fclose(f); return -1; }
    if (bl) fread(resp->body, 1, bl, f);
    resp->body_len = bl;
    fclose(f);
    return 0;
}

/* ---- End cache ---- */


/* ---- Connection reuse cache (--no-reuse disables) ---- */

#define REUSE_MAX 8

typedef struct {
    char           host[256];
    uint16_t       port;
    int            is_tls;
    int            fd;
    crisptls_conn_t *tls;
    time_t         last_used;
} reuse_entry_t;

static reuse_entry_t g_reuse[REUSE_MAX];
static int g_reuse_count = 0;
static int g_reuse_atexit_installed = 0;

static void reuse_cleanup(void) {
    for (int i = 0; i < g_reuse_count; i++) {
        if (g_reuse[i].tls) { crisptls_close(g_reuse[i].tls); g_reuse[i].tls = NULL; }
        if (g_reuse[i].fd >= 0) { close(g_reuse[i].fd); g_reuse[i].fd = -1; }
    }
    g_reuse_count = 0;
}

static void reuse_install_atexit(void) {
    if (!g_reuse_atexit_installed) {
        atexit(reuse_cleanup);
        g_reuse_atexit_installed = 1;
    }
}

static long cube_now_ms(void) {
#ifdef _WIN32
    return (long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)(ts.tv_nsec / 1000000L);
#endif
}

static int reuse_is_alive(int fd) {
    if (fd < 0) return 0;
#ifdef _WIN32
    WSAPOLLFD pfd = { .fd = (SOCKET)fd, .events = POLLRDNORM, .revents = 0 };
    return WSAPoll(&pfd, 1, 0) == 0;
#else
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    return poll(&pfd, 1, 0) == 0;
#endif
}

static int reuse_lookup(const char *host, uint16_t port, int is_tls,
                        crisptls_conn_t **tls_out) {
    *tls_out = NULL;
    for (int i = 0; i < g_reuse_count; i++) {
        reuse_entry_t *e = &g_reuse[i];
        if (e->port != port) continue;
        if (e->is_tls != is_tls) continue;
        if (strcmp(e->host, host) != 0) continue;
        if (!reuse_is_alive(e->fd)) {
            if (e->tls) crisptls_close(e->tls);
            if (e->fd >= 0) close(e->fd);
            e->fd = -1; e->tls = NULL;
            g_reuse[i] = g_reuse[g_reuse_count - 1];
            g_reuse_count--;
            return -1;
        }
        *tls_out = e->tls;
        e->last_used = time(NULL);
        return e->fd;
    }
    return -1;
}

static void reuse_store(const char *host, uint16_t port, int is_tls,
                        int fd, crisptls_conn_t *tls) {
    if (fd < 0) return;
    for (int i = 0; i < g_reuse_count; i++) {
        reuse_entry_t *e = &g_reuse[i];
        if (e->port == port && e->is_tls == is_tls && strcmp(e->host, host) == 0) {
            if (e->tls) crisptls_close(e->tls);
            if (e->fd >= 0) close(e->fd);
            e->fd = fd;
            e->tls = tls;
            e->last_used = time(NULL);
            return;
        }
    }
    if (g_reuse_count >= REUSE_MAX) {
        int oldest = 0;
        for (int i = 1; i < g_reuse_count; i++)
            if (g_reuse[i].last_used < g_reuse[oldest].last_used) oldest = i;
        if (g_reuse[oldest].tls) crisptls_close(g_reuse[oldest].tls);
        if (g_reuse[oldest].fd >= 0) close(g_reuse[oldest].fd);
        g_reuse[oldest] = g_reuse[g_reuse_count - 1];
        g_reuse_count--;
    }
    reuse_entry_t *e = &g_reuse[g_reuse_count++];
    snprintf(e->host, sizeof e->host, "%s", host);
    e->port = port;
    e->is_tls = is_tls;
    e->fd = fd;
    e->tls = tls;
    e->last_used = time(NULL);
}

/* ---- End reuse ---- */


static int fetch_response(const cube_opts_t *o, const char *url,
                          const char **extra_headers, int n_extra,
                          http_response_t *resp,
                          crisptls_conn_t **tls_out,
                          int *fd_out) {
    *tls_out = NULL;
    *fd_out = -1;

    /* Cache lookup (skip network on hit) */
    if (o->cache) {
        int ma = o->cache_max_age > 0 ? o->cache_max_age : 3600;
        if (cache_load(url, resp, ma) == 0) {
            if (o->verbose) fprintf(stderr, "%s[http]%s cache hit: %s\n", col_magenta(), col_reset(), url);
            return 0;
        }
        if (o->verbose) fprintf(stderr, "%s[http]%s cache miss: %s\n", col_magenta(), col_reset(), url);
    }

    /* ---- 1. URL parse ---- */
    size_t norm_buf_size = o->max_norm_buf ? o->max_norm_buf : 8192;
    if (norm_buf_size > 1024 * 1024) norm_buf_size = 1024 * 1024;
    if (norm_buf_size < 64) norm_buf_size = 64;
    char norm_buf_vla[norm_buf_size];
    char *norm_buf = norm_buf_vla;
    size_t norm_len = 0;
    url_view urlv;
    if (o->max_url_len) url_set_max_len(o->max_url_len);
    url_err ue = url_parse_auto(url, strlen(url),
                                 norm_buf, norm_buf_size, &norm_len, &urlv);
    if (ue != URL_OK) {
        if (!o->quiet)
            fprintf(stderr, "%s[!] url: %s (code %d)%s\n",
                    col_red(), url_err_name(ue), (int)ue, col_reset());
        if (o->verbose) {
            fprintf(stderr, "    input: \"%s\"\n", url);
            fprintf(stderr, "    parser: url_parse_auto (strict-then-whatwg)\n");
            fprintf(stderr, "    norm_len: %zu bytes\n", norm_len);
        }
        return 2;
    }
    url_err ve = url_validate(&urlv);
    if (ve != URL_OK) {
        if (!o->quiet)
            fprintf(stderr, "%s[!] url: %s (code %d)%s\n",
                    col_red(), url_err_name(ve), (int)ve, col_reset());
        if (o->verbose) {
            fprintf(stderr, "    input: \"%s\"\n", url);
            fprintf(stderr, "    validator: url_validate\n");
        }
        return 2;
    }

    char host[256];
    if (urlv.host_len >= sizeof(host)) {
        if (!o->quiet) fprintf(stderr, "%shost too long%s\n", col_red(), col_reset());
        return 2;
    }
    memcpy(host, urlv.host, urlv.host_len);
    host[urlv.host_len] = 0;

    char path[2048];
    size_t path_len = 0;
    if (urlv.path_len < sizeof(path)) {
        memcpy(path, urlv.path, urlv.path_len);
        path_len = urlv.path_len;
    }
    if (urlv.query_len > 0 && path_len + 1 + urlv.query_len < sizeof(path)) {
        path[path_len++] = '?';
        memcpy(path + path_len, urlv.query, urlv.query_len);
        path_len += urlv.query_len;
    }
    path[path_len] = 0;

    uint16_t port = urlv.port;
    if (port == 0) port = url_scheme_default_port(urlv.scheme, urlv.scheme_len);
    int is_tls = url_scheme_is_tls(urlv.scheme, urlv.scheme_len);
    if (o->no_tls) is_tls = 0;

    proxy_config_t px;
    memset(&px, 0, sizeof px);
    int use_proxy = 0;
    if (o->proxy) {
        if (proxy_parse(&px, o->proxy) != 0) {
            if (!o->quiet) fprintf(stderr, "%s[!] invalid proxy URL: %s%s\n",
                                   col_red(), o->proxy, col_reset());
            return 2;
        }
        proxy_set_no_proxy(&px, o->no_proxy);
        use_proxy = !proxy_bypass(&px, host);
        if (o->verbose)
            fprintf(stderr, "%s[proxy]%s %s -> %s:%u%s\n", col_green(), col_reset(),
                    use_proxy ? "using" : "bypassing", px.host, (unsigned)px.port, "");
    }
    if (o->verbose)
        fprintf(stderr, "%s[url]%s host=%s port=%u path=%s scheme=%.*s\n",
                col_bold(), col_reset(), host, port, path,
                (int)urlv.scheme_len, urlv.scheme);

    /* ---- Reuse lookup (before DNS/TCP/TLS) ---- */
    crisptls_conn_t *tls = NULL;
    int fd = -1;
    http_io_t io;
    memset(&io, 0, sizeof(io));

    if (!o->no_reuse && !use_proxy) {
        fd = reuse_lookup(host, port, is_tls, &tls);
        if (fd >= 0 && o->verbose)
            fprintf(stderr, "%s[tcp]%s reuse: hit %s:%u\n", col_green(), col_reset(), host, port);
    }

    if (fd < 0) {
        const char *conn_host = use_proxy ? px.host : host;
        uint16_t conn_port = use_proxy ? px.port : port;
        /* ---- 2. DNS ---- */
        if (o->verbose) fprintf(stderr, "%s[dns]%s resolving %s ...\n", col_cyan(), col_reset(), conn_host);
        char ips[16][64];
        int  fams[16];
        size_t n_ips = 0;
        int  fam_pref = o->ipv4_only ? AF_INET : (o->ipv6_only ? AF_INET6 : AF_UNSPEC);
        if (resolve_host_all(conn_host, fam_pref, ips, fams, 16, &n_ips, o->debug) != 0 || n_ips == 0) {
            if (!o->quiet)
                fprintf(stderr, "%s[!] dns: %s for '%s'%s\n",
                        col_red(), dns_err_name(g_dns_last_err), conn_host, col_reset());
            if (o->verbose) fprintf(stderr, "    (dns error code %d)\n", g_dns_last_err);
            return 3;
        }
        if (o->verbose) {
            for (size_t _i = 0; _i < n_ips; _i++)
                fprintf(stderr, "%s[dns]%s %s -> %s\n", col_cyan(), col_reset(), conn_host, ips[_i]);
        }

        /* ---- 3. TCP connect ---- */
        uint32_t per_attempt = o->timeout_ms / (uint32_t)n_ips;
        if (per_attempt < 1000) per_attempt = 1000;
        if (per_attempt > (uint32_t)o->timeout_ms) per_attempt = (uint32_t)o->timeout_ms;
        char tcp_err[256] = {0};
        for (size_t _i = 0; _i < n_ips; _i++) {
            if (o->verbose && _i > 0)
                fprintf(stderr, "%s[dns]%s retrying %s (attempt %zu/%zu)\n", col_cyan(), col_reset(), ips[_i], _i + 1, n_ips);
            if (o->verbose)
                fprintf(stderr, "%s[tcp]%s connecting %s:%u\n", col_green(), col_reset(), ips[_i], (unsigned)conn_port);
            long _t0 = cube_now_ms();
            fd = tcp_connect(ips[_i], fams[_i], conn_port, per_attempt, tcp_err, sizeof tcp_err);
            if (fd >= 0) {
                long _ms = cube_now_ms() - _t0;
                if (o->verbose)
                    fprintf(stderr, "%s[tcp]%s connected in %ldms\n", col_green(), col_reset(), _ms);
                break;
            }
        }
        if (fd < 0) {
            if (!o->quiet)
                fprintf(stderr, "%s[!] tcp connect failed: %s%s\n",
                        col_red(),
                    tcp_err[0] ? tcp_err : strerror(errno),
                    col_reset());
            return 4;
        }
        if (use_proxy) {
            char perr[256] = {0};
            if (proxy_tunnel(&px, fd, host, port, (uint32_t)o->timeout_ms,
                             perr, sizeof perr) != 0) {
                if (!o->quiet)
                    fprintf(stderr, "%s[!] %s%s\n", col_red(),
                            perr[0] ? perr : "proxy tunnel failed", col_reset());
                close(fd);
                return 4;
            }
            if (o->verbose)
                fprintf(stderr, "%s[proxy]%s tunnel established to %s:%u\n",
                        col_green(), col_reset(), host, (unsigned)port);
        }
        {
            struct timeval tv;
            tv.tv_sec  = o->timeout_ms / 1000;
            tv.tv_usec = (o->timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
        {
            uint32_t _to = o->timeout_ms ? o->timeout_ms : 15000;
            struct timeval _tv = { (time_t)(_to / 1000), (suseconds_t)((_to % 1000) * 1000) };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &_tv, sizeof _tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &_tv, sizeof _tv);
        }

        /* ---- 4. TLS handshake ---- */
        if (is_tls) {
            crisptls_policy_t pol;
            if (o->profile) {
                if (crisptls_policy_from_profile(&pol, o->profile) != CRISPTLS_OK) {
                    if (!o->quiet)
                        fprintf(stderr, "%s[!] unknown TLS profile: %s%s\n",
                                col_red(), o->profile, col_reset());
                    close(fd);
                    return 5;
                }
            } else {
                crisptls_policy_default(&pol);
            }
            pol.verify_peer = 2;
            if (o->insecure) { pol.verify_peer = 0; pol.verify_hostname = 0; }
            else if (o->advisory) { pol.verify_peer = 1; }
            if (o->force_http1) { pol.alpn = "http/1.1"; pol.strict_alpn = 0; }

            crisptls_ctx_t *tls_ctx = crisptls_ctx_new(&pol);
            if (!tls_ctx) { close(fd); return 5; }

            if (o->verbose) fprintf(stderr, "%s[tls]%s handshake starting\n", col_yellow(), col_reset());
            tls = crisptls_connect(tls_ctx, fd, host);
            if (!tls) {
                if (!o->quiet)
                    fprintf(stderr, "%s[!] tls handshake failed: %s%s\n",
                            col_red(),
                        crisptls_last_error() ? crisptls_last_error() : "(no detail)",
                        col_reset());
                crisptls_ctx_free(tls_ctx);
                close(fd);
                return 5;
            }
            if (o->verbose) {
                fprintf(stderr, "%s[tls]%s ok: %s / %s / alpn=%s\n",
                        col_yellow(), col_reset(),
                        tls_ver_str(crisptls_get_version(tls)),
                        crisptls_get_cipher(tls) ? crisptls_get_cipher(tls) : "?",
                        crisptls_get_alpn(tls) ? crisptls_get_alpn(tls) : "-");
            }
            /* Policy copied into tls at crisptls_connect; ctx not needed by close. */
            crisptls_ctx_free(tls_ctx);
        }

        /* Store for future reuse (proxied tunnels are single-use) */
        if (!o->no_reuse && !use_proxy) reuse_store(host, port, is_tls, fd, tls);
    }

    if (is_tls) {
        io.ctx   = tls;
        io.read  = tls_read_fn;
        io.write = tls_write_fn;
    } else {
        http_io_from_fd(&io, fd);
    }

    /* ---- 5. HTTP request ---- */
    http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method    = o->method;
    req.path      = path;
    req.version   = HTTP_11;
    req.body      = o->data;
    req.body_len  = o->data ? strlen(o->data) : 0;
    http_headers_init(&req.headers);
    http_headers_set(&req.headers, "User-Agent", o->user_agent ? o->user_agent : "cube/1.0");
    http_headers_set(&req.headers, "Accept-Encoding",
                     o->no_decode ? "identity" : "gzip, deflate");
    if (o->content_type)
        http_headers_set(&req.headers, "Content-Type", o->content_type);
    /* -H extra headers */
    for (int i = 0; i < n_extra; i++) {
        const char *h = extra_headers[i];
        const char *colon = strchr(h, ':');
        if (!colon) continue;
        char name[128];
        size_t nl = (size_t)(colon - h);
        if (nl >= sizeof(name)) nl = sizeof(name) - 1;
        memcpy(name, h, nl);
        name[nl] = 0;
        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        http_headers_set(&req.headers, name, val);
    }
    if (o->verbose) fprintf(stderr, "%s[http]%s sending %s %s\n", col_magenta(), col_reset(), req.method, req.path);

    memset(resp, 0, sizeof(*resp));
    const char *alpn = tls ? crisptls_get_alpn(tls) : NULL;
    int rc = http_send_io(&io, host, port, is_tls ? "https" : "http", alpn, &req, resp);
    http_headers_free(&req.headers);

    if (rc == 0 && !o->no_decode) decode_response(resp);
    if (rc != 0) {
        if (!o->quiet)
            fprintf(stderr, "%s[!] http failed: rc=%d%s\n", col_red(), rc, col_reset());
        /* Don't close fd/tls — cache owns them if reuse is on */
        return 7;
    }
    if (o->verbose)
        fprintf(stderr, "%s[http]%s response %d (%zu bytes)\n",
                col_magenta(), col_reset(), resp->status_code, resp->body_len);

    *tls_out = tls;
    *fd_out  = fd;
    return 0;
}

/* Print one response (headers + body) per o's flags.
 * Handles -o, -b, -i, -q, --show-cert, --ja3, --ja4, --head, --lines.
 * Closes tls + fd when done. */
static void print_response(const cube_opts_t *o, const http_response_t *resp,
                           crisptls_conn_t *tls, int fd, int keep_conn) {
    /* ---- 6. Output ---- */
    if (o->output) {
        /* -o: no headers on stdout; write_body writes file; [*] saved printed after */
    } else if (o->body_only) {
        /* -b: body only, no headers */
    } else if (o->quiet) {
        dump_response_headers((http_response_t *)resp);
    } else {
        dump_response_headers((http_response_t *)resp);
    }

    if (o->show_cert && tls) {
        uint8_t der[16384];
        size_t  der_len = 0;
        int crc = crisptls_get_peer_cert_der(tls, der, sizeof(der), &der_len);
        if (crc == CRISPTLS_OK) {
            fprintf(stderr, "%s[tls]%s leaf cert: %zu bytes\n", col_yellow(), col_reset(), der_len);
        } else {
            if (!o->quiet)
                fprintf(stderr, "%s[!] --show-cert: no peer certificate (rc=%d)%s\n",
                        col_red(), crc, col_reset());
        }
        for (int ci = 0; ci < 16; ci++) {
            size_t cl = 0;
            if (crisptls_get_peer_chain_der(tls, ci, der, sizeof(der), &cl) != CRISPTLS_OK) break;
            fprintf(stderr, "%s[tls]%s chain[%d]: %zu bytes\n", col_yellow(), col_reset(), ci, cl);
        }
    }
    if (o->show_ja3 && tls) {
        char b[64];
        crisptls_conn_ja3_hash(tls, b, sizeof(b));
        fprintf(stderr, "%s[tls]%s ja3: %s\n", col_yellow(), col_reset(), b);
    }
    if (o->show_ja4 && tls) {
        char b[64];
        crisptls_conn_ja4_hash(tls, b, sizeof(b));
        fprintf(stderr, "%s[tls]%s ja4: %s\n", col_yellow(), col_reset(), b);
    }

    int wrc = (o->show_headers && !o->body_only && !o->output)
              ? 0 : write_body(resp, o->output, o);
    if (wrc == 0 && o->output)
        fprintf(stderr, "%s[http]%s saved %zu bytes to %s\n",
                col_magenta(), col_reset(), resp->body_len, o->output);
    if (!keep_conn) {
        if (tls) crisptls_close(tls);
        if (fd >= 0) close(fd);
    }
}

static int run_one(const cube_opts_t *o_in,
                   const char **extra_headers, int n_extra) {
    cube_opts_t o = *o_in;
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    if (o.trace) { o.debug = 1; o.verbose = 1; }
    if (o.debug) o.verbose = 1;
    apply_runtime_opts(&o);
    { char _sp[1024]; url_schemes_load(cube_repo_path("flywheel/url/data/scheme_ports.conf", _sp, sizeof _sp)); }

    char url_buf[2048];
    snprintf(url_buf, sizeof url_buf, "%s", o.url);
    o.url = url_buf;

    http_response_t resp = {0};
    crisptls_conn_t *tls = NULL;
    int fd = -1;
    int rc = 0;

    for (int hop = 0; hop <= 10; hop++) {
        long t0 = cube_now_ms();
        rc = fetch_response(&o, o.url, extra_headers, n_extra, &resp, &tls, &fd);
        if (rc != 0) {
            /* fetch_response closed fd/tls on failure; just return */
            return rc;
        }
        long elapsed = cube_now_ms() - t0;
        if (g_har) har_record(o.url, o.method ? o.method : "GET", &resp, elapsed);
        if (o.intercept)
            fprintf(stderr, "%s[intercept]%s %s %s -> %d (%zu bytes, %ldms)\n",
                    col_magenta(), col_reset(), o.method ? o.method : "GET",
                    o.url, resp.status_code, resp.body_len, elapsed);
        /* Cache save on successful fetch */
        if (o.cache && resp.status_code >= 200 && resp.status_code < 300) {
            int ma = o.cache_max_age > 0 ? o.cache_max_age : 3600;
            cache_save(o.url, &resp, ma);
        }
        if (!o.follow || resp.status_code < 300 || resp.status_code >= 400)
            break;  /* final response */
        const char *loc = http_headers_get((http_headers_t *)&resp.headers, "Location");
        if (!loc) break;
        if (o.verbose)
            fprintf(stderr, "%s[http]%s redirect %d -> %s\n", col_magenta(), col_reset(), resp.status_code, loc);

        url_view base;
        char norm_buf[2048];
        size_t norm_len = 0;
        char joined[2048];
        size_t jlen = 0;
        if (url_parse_whatwg_stable(o.url, strlen(o.url),
                                    norm_buf, sizeof norm_buf, &norm_len,
                                    &base) != URL_OK) break;
        if (url_join(&base, loc, strlen(loc), joined, sizeof joined, &jlen) != URL_OK) break;

        http_response_free(&resp);

        snprintf(url_buf, sizeof url_buf, "%s", joined);
        o.url = url_buf;
    }

    print_response(&o, &resp, tls, fd, !o.no_reuse);
    http_response_free(&resp);
    return 0;
}

/* Prepend https:// if the URL has no scheme (no "://" and no "scheme:" pattern).
 * Handles "google.com", "google.com/path", "192.168.1.1", "1.1.1.1:443".
 * Returns pointer into a static thread-local buffer, valid until next call.
 * Not thread-safe, but cube is single-threaded. */
static const char *normalize_url(const char *in) {
    static char buf[2048];
    if (!in || !*in) return in;

    /* Look for "://" in the first 16 chars (scheme max reasonable length) */
    const char *p = in;
    int has_scheme = 0;
    for (int i = 0; i < 16 && *p; i++, p++) {
        if (*p == ':') {
            /* Check: followed by //? */
            if (p[1] == '/' && p[2] == '/') { has_scheme = 1; }
            /* Or valid scheme chars before ':' — treat as scheme (e.g. "mailto:") */
            else if (i > 0) { has_scheme = 1; }
            break;
        }
        /* Valid scheme char? */
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '+' || *p == '-' || *p == '.'))
            break;
    }

    if (has_scheme) {
        snprintf(buf, sizeof buf, "%s", in);
    } else {
        snprintf(buf, sizeof buf, "https://%s", in);
    }
    return buf;
}


/* Resolve a path relative to the cube repo root. Falls back to CWD-relative. */
static const char *cube_repo_path(const char *rel, char *buf, size_t cap) {
    /* Try CWD first (running from repo root) */
    FILE *f = fopen(rel, "r");
    if (f) { fclose(f); snprintf(buf, cap, "%s", rel); return buf; }

    /* Walk up from the executable path (portable: argv[0], no /proc). */
    char exe[1024];
    snprintf(exe, sizeof exe, "%s", g_argv0 ? g_argv0 : "");
    for (int depth = 0; depth < 6; depth++) {
        char *slash = strrchr(exe, '/');
#ifdef _WIN32
        char *bslash = strrchr(exe, '\\');
        if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
        if (!slash) break;
        *slash = 0;
        snprintf(buf, cap, "%s/%s", exe, rel);
        f = fopen(buf, "r");
        if (f) { fclose(f); return buf; }
        snprintf(buf, cap, "%s/../%s", exe, rel);
        f = fopen(buf, "r");
        if (f) { fclose(f); return buf; }
    }

    /* Give up — return the relative path (caller will handle fopen failure) */
    snprintf(buf, cap, "%s", rel);
    return buf;
}
static int run_json_check(const cube_opts_t *o) {
    const char *path = o->n_urls > 0 ? o->urls[0] : NULL;
    FILE *f = path ? fopen(path, "rb") : stdin;
    if (!f) {
        fprintf(stderr, "%scube: cannot open %s: %s%s\n",
                col_red(), path, strerror(errno), col_reset());
        return 1;
    }
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { if (f != stdin) fclose(f); return 1; }
    for (;;) {
        if (len + 4096 + 1 > cap) {
            if (cap >= 256u * 1024u * 1024u) {
                fprintf(stderr, "%scube: input too large%s\n", col_red(), col_reset());
                free(buf); if (f != stdin) fclose(f); return 1;
            }
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); if (f != stdin) fclose(f); return 1; }
            buf = nb; cap = ncap;
        }
        size_t n = fread(buf + len, 1, cap - len - 1, f);
        len += n;
        if (n == 0) break;
    }
    int bad = ferror(f);
    if (f != stdin) fclose(f);
    if (bad) { free(buf); fprintf(stderr, "%scube: read error%s\n", col_red(), col_reset()); return 1; }

    json_error_t e;
    int ok = json_validate(buf, len, o->check_json == 2, &e);
    if (ok == 0) {
        printf("%s: valid %s\n", path ? path : "<stdin>",
               o->check_json == 2 ? "JSONC" : "JSON");
    } else {
        fprintf(stderr, "%s:%d:%d: %s (byte %zu)\n",
                path ? path : "<stdin>", e.line, e.column, e.message, e.offset);
    }
    free(buf);
    return ok == 0 ? 0 : 1;
}

/* ---- Interactive REPL ---- */

#define CUBE_REPL_MAX_HEADERS 16
#define CUBE_REPL_HEADER_MAX  1024

typedef struct {
    cube_opts_t opts;
    char profile[128];
    char method[32];
    char user_agent[512];
    char header_store[CUBE_REPL_MAX_HEADERS][CUBE_REPL_HEADER_MAX];
    const char *headers[CUBE_REPL_MAX_HEADERS];
    int n_headers;
} cube_repl_t;

static int repl_ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

static char *repl_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static char *repl_split(char *s, char **rest) {
    s = repl_trim(s);
    if (!*s) { *rest = s; return s; }
    char *tok = s;
    while (*s && !isspace((unsigned char)*s)) s++;
    if (*s) *s++ = '\0';
    *rest = repl_trim(s);
    return tok;
}

static int repl_bool(const char *v, int *out) {
    if (!v || !*v) { *out = 1; return 0; }
    if (repl_ci_eq(v, "1") || repl_ci_eq(v, "on") ||
        repl_ci_eq(v, "true") || repl_ci_eq(v, "yes")) {
        *out = 1;
        return 0;
    }
    if (repl_ci_eq(v, "0") || repl_ci_eq(v, "off") ||
        repl_ci_eq(v, "false") || repl_ci_eq(v, "no")) {
        *out = 0;
        return 0;
    }
    return -1;
}

static void repl_print_help(void) {
    printf("commands:\n"
           "  help                    show this help\n"
           "  get <url>               fetch a URL with the current settings\n"
           "  set <key> <value>       change a setting\n"
           "  unset <key>             reset raw, color, quiet, or verbose\n"
           "  show                    print current settings\n"
           "  quit | exit             leave interactive mode\n"
           "\n"
           "set keys: profile, timeout, method, user-agent, header,\n"
           "          raw, color, follow, quiet, verbose\n"
           "  header takes a value like \"Name: value\"\n"
           "  booleans accept on/off, true/false, yes/no, 1/0\n"
           "  color accepts auto, on/force, off/never\n");
}

static const char *repl_onoff(int v) {
    return v ? "on" : "off";
}

static void repl_show(const cube_repl_t *st) {
    const cube_opts_t *o = &st->opts;
    const char *color = o->color_mode == 1 ? "on"
                      : o->color_mode == 2 ? "off" : "auto";
    printf("profile: %s\n", o->profile ? o->profile : "(default)");
    printf("timeout: %d ms\n", o->timeout_ms);
    printf("method: %s\n", o->method ? o->method : "(default)");
    printf("user-agent: %s\n", o->user_agent ? o->user_agent : "(default)");
    for (int i = 0; i < st->n_headers; i++)
        printf("header: %s\n", st->headers[i]);
    printf("raw: %s\n", repl_onoff(o->raw));
    printf("color: %s\n", color);
    printf("follow: %s\n", repl_onoff(o->follow));
    printf("quiet: %s\n", repl_onoff(o->quiet));
    printf("verbose: %s\n", repl_onoff(o->verbose));
}

static int repl_set(cube_repl_t *st, char *rest) {
    char *value = NULL;
    char *key = repl_split(rest, &value);
    cube_opts_t *o = &st->opts;

    if (!*key) {
        fprintf(stderr, "%scube: set requires a key and value%s\n", col_red(), col_reset());
        return 1;
    }
    if (repl_ci_eq(key, "profile")) {
        if (!*value) goto missing;
        snprintf(st->profile, sizeof st->profile, "%s", value);
        o->profile = st->profile;
        return 0;
    }
    if (repl_ci_eq(key, "timeout")) {
        if (!*value) goto missing;
        char *end = NULL;
        long n = strtol(value, &end, 10);
        if (!end || *end || n < 0 || n > 2147483647L) {
            fprintf(stderr, "%scube: timeout must be a non-negative integer (ms)%s\n",
                    col_red(), col_reset());
            return 1;
        }
        o->timeout_ms = (int)n;
        return 0;
    }
    if (repl_ci_eq(key, "method")) {
        if (!*value) goto missing;
        snprintf(st->method, sizeof st->method, "%s", value);
        o->method = st->method;
        return 0;
    }
    if (repl_ci_eq(key, "user-agent")) {
        if (!*value) goto missing;
        snprintf(st->user_agent, sizeof st->user_agent, "%s", value);
        o->user_agent = st->user_agent;
        return 0;
    }
    if (repl_ci_eq(key, "header")) {
        if (!*value) goto missing;
        if (!strchr(value, ':')) {
            fprintf(stderr, "%scube: header must be \"Name: value\"%s\n",
                    col_red(), col_reset());
            return 1;
        }
        if (st->n_headers >= CUBE_REPL_MAX_HEADERS) {
            fprintf(stderr, "%scube: too many headers (max %d)%s\n",
                    col_red(), CUBE_REPL_MAX_HEADERS, col_reset());
            return 1;
        }
        if (strlen(value) >= sizeof st->header_store[0]) {
            fprintf(stderr, "%scube: header too long%s\n", col_red(), col_reset());
            return 1;
        }
        snprintf(st->header_store[st->n_headers], sizeof st->header_store[0], "%s", value);
        st->headers[st->n_headers] = st->header_store[st->n_headers];
        st->n_headers++;
        return 0;
    }
    if (repl_ci_eq(key, "raw")) {
        int v;
        if (repl_bool(value, &v) != 0) goto badbool;
        o->raw = v;
        return 0;
    }
    if (repl_ci_eq(key, "follow")) {
        int v;
        if (repl_bool(value, &v) != 0) goto badbool;
        o->follow = v;
        return 0;
    }
    if (repl_ci_eq(key, "quiet")) {
        int v;
        if (repl_bool(value, &v) != 0) goto badbool;
        o->quiet = v;
        return 0;
    }
    if (repl_ci_eq(key, "verbose")) {
        int v;
        if (repl_bool(value, &v) != 0) goto badbool;
        o->verbose = v;
        return 0;
    }
    if (repl_ci_eq(key, "color")) {
        if (!*value) { o->color_mode = 1; return 0; }
        if (repl_ci_eq(value, "auto")) { o->color_mode = 0; return 0; }
        if (repl_ci_eq(value, "on") || repl_ci_eq(value, "force") ||
            repl_ci_eq(value, "true") || repl_ci_eq(value, "yes") ||
            repl_ci_eq(value, "1")) {
            o->color_mode = 1;
            return 0;
        }
        if (repl_ci_eq(value, "off") || repl_ci_eq(value, "never") ||
            repl_ci_eq(value, "false") || repl_ci_eq(value, "no") ||
            repl_ci_eq(value, "0")) {
            o->color_mode = 2;
            return 0;
        }
        goto badbool;
    }

    fprintf(stderr, "%scube: unknown set key '%s' (try 'help')%s\n",
            col_red(), key, col_reset());
    return 1;

missing:
    fprintf(stderr, "%scube: set %s requires a value%s\n", col_red(), key, col_reset());
    return 1;
badbool:
    fprintf(stderr, "%scube: invalid boolean value for %s%s\n", col_red(), key, col_reset());
    return 1;
}

static int repl_unset(cube_repl_t *st, char *rest) {
    char *value = NULL;
    char *key = repl_split(rest, &value);
    (void)value;
    cube_opts_t *o = &st->opts;

    if (!*key) {
        fprintf(stderr, "%scube: unset requires a key%s\n", col_red(), col_reset());
        return 1;
    }
    if (repl_ci_eq(key, "raw")) { o->raw = 0; return 0; }
    if (repl_ci_eq(key, "color")) { o->color_mode = 0; return 0; }
    if (repl_ci_eq(key, "quiet")) { o->quiet = 0; return 0; }
    if (repl_ci_eq(key, "verbose")) { o->verbose = 0; return 0; }
    fprintf(stderr, "%scube: cannot unset '%s' (try raw, color, quiet, verbose)%s\n",
            col_red(), key, col_reset());
    return 1;
}

static int run_interactive(cube_opts_t *o_in,
                           const char **initial_headers, int n_initial) {
    cube_repl_t st;
    memset(&st, 0, sizeof st);
    st.opts = *o_in;
    for (int i = 0; i < n_initial && i < CUBE_REPL_MAX_HEADERS; i++) {
        snprintf(st.header_store[st.n_headers], sizeof st.header_store[0],
                 "%s", initial_headers[i]);
        st.headers[st.n_headers] = st.header_store[st.n_headers];
        st.n_headers++;
    }

    int status = 0;
    int tty = isatty(0);
    char line[8192];

    for (;;) {
        if (tty) {
            fputs("cube> ", stdout);
            fflush(stdout);
        }
        if (!fgets(line, sizeof line, stdin)) {
            if (tty) fputc('\n', stdout);
            break;
        }
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        char *s = repl_trim(line);
        if (!*s || *s == '#') continue;

        char *rest = NULL;
        char *cmd = repl_split(s, &rest);

        if (repl_ci_eq(cmd, "help")) {
            repl_print_help();
            status = 0;
        } else if (repl_ci_eq(cmd, "show")) {
            repl_show(&st);
            status = 0;
        } else if (repl_ci_eq(cmd, "get")) {
            if (!*rest) {
                fprintf(stderr, "%scube: get requires a URL%s\n", col_red(), col_reset());
                status = 1;
            } else {
                st.opts.url = normalize_url(rest);
                status = run_one(&st.opts, st.headers, st.n_headers);
                reuse_cleanup();
                fflush(stdout);
                fflush(stderr);
            }
        } else if (repl_ci_eq(cmd, "set")) {
            status = repl_set(&st, rest);
        } else if (repl_ci_eq(cmd, "unset")) {
            status = repl_unset(&st, rest);
        } else if (repl_ci_eq(cmd, "quit") || repl_ci_eq(cmd, "exit")) {
            break;
        } else {
            fprintf(stderr, "%scube: unknown command '%s' (try 'help')%s\n",
                    col_red(), cmd, col_reset());
            status = 1;
        }
    }
    return status;
}

int main(int argc, char **argv) {
    g_argv0 = argc > 0 ? argv[0] : "cube";
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
#endif
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    reuse_install_atexit();

    cube_opts_t o;
    memset(&o, 0, sizeof(o));
    o.method     = "GET";
    o.follow     = 1;
    o.timeout_ms = 15000;
    o.retries    = 3;

    const char *extra_headers[16];
    int n_extra = 0;

    if (parse_args(argc, argv, &o, extra_headers, &n_extra) != 0) return 1;

    if (o.trace) { o.debug = 1; o.verbose = 1; }
    if (o.debug) o.verbose = 1;
    apply_runtime_opts(&o);
    if (o.check_json) return run_json_check(&o);
    { char _sp[1024]; url_schemes_load(cube_repo_path("flywheel/url/data/scheme_ports.conf", _sp, sizeof _sp)); }
    { char _pp[1024]; crisptls_profile_load_file(cube_repo_path("net/crisptls/data/profiles.conf", _pp, sizeof _pp)); }
    if (o.interactive) return run_interactive(&o, extra_headers, n_extra);

    if (o.n_urls == 0) {
        usage(argv[0]);
        return 1;
    }
    if (o.output && o.n_urls > 1) {
        fprintf(stderr, "%s[!] -o requires exactly one URL (got %d)%s\n",
                col_red(), o.n_urls, col_reset());
        return 1;
    }

    if (o.har_path) har_begin(o.har_path);
    int final_rc = 0;
    for (int i = 0; i < o.n_urls; i++) {
        const char *norm = normalize_url(o.urls[i]);
        o.url = norm;
        if (o.n_urls > 1) {
            printf("%s=== %s ===%s\n", col_bold(), norm, col_reset());
            fflush(stdout);
        }
        int rc = -1;
        int max_attempts = 1 + (o.retries > 0 ? o.retries : 0);
        for (int a = 0; a < max_attempts; a++) {
            if (a > 0 && (o.verbose || o.debug))
                fprintf(stderr, "%s[http]%s retry %d/%d\n", col_magenta(), col_reset(), a, o.retries);
            rc = run_one(&o, extra_headers, n_extra);
            if (rc == 0) break;
            /* Retry only transient HTTP-layer failures. DNS/TCP/TLS
             * failures (3/4/5) are usually deterministic; retrying them
             * just multiplies timeouts. */
            if (rc != 7) break;
        }
        fflush(stdout);
        fflush(stderr);
        if (rc != 0 && final_rc == 0) final_rc = rc;
    }
    har_end();
    return final_rc;
}
