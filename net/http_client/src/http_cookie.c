/** http_cookie.c — RFC 6265 cookie jar (minimal but correct).
 *
 * Stores cookies with Domain, Path, Secure, HttpOnly, Expires/Max-Age.
 * Matches a request by host, path, secure flag.
 * Netscape-format save/load.
 */

#define _GNU_SOURCE
#include "http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- lifecycle ---- */

void http_cookie_jar_init(http_cookie_jar_t *j) {
    if (j) memset(j, 0, sizeof(*j));
}

static void cookie_free(http_cookie_t *c) {
    if (!c) return;
    free(c->name);
    free(c->value);
    free(c->domain);
    free(c->path);
    memset(c, 0, sizeof(*c));
}

void http_cookie_jar_free(http_cookie_jar_t *j) {
    if (!j) return;
    for (size_t i = 0; i < j->count; i++) cookie_free(&j->items[i]);
    free(j->items);
    memset(j, 0, sizeof(*j));
}

static int jar_grow(http_cookie_jar_t *j) {
    if (j->count < j->cap) return 0;
    size_t ncap = j->cap ? j->cap * 2 : 16;
    http_cookie_t *ni = realloc(j->items, ncap * sizeof(*ni));
    if (!ni) return -1;
    memset(ni + j->cap, 0, (ncap - j->cap) * sizeof(*ni));
    j->items = ni;
    j->cap   = ncap;
    return 0;
}

/* ---- helpers ---- */

static char *xstrdup_n(const char *s, size_t n) {
    char *r = malloc(n + 1);
    if (!r) return NULL;
    memcpy(r, s, n);
    r[n] = 0;
    return r;
}

static char *xstrdup(const char *s) {
    return s ? xstrdup_n(s, strlen(s)) : NULL;
}

/* Find existing cookie for (name, domain, path). Returns index or -1. */
static int jar_find(const http_cookie_jar_t *j, const char *name,
                    const char *domain, const char *path) {
    for (size_t i = 0; i < j->count; i++) {
        const http_cookie_t *c = &j->items[i];
        if (strcmp(c->name, name) == 0 &&
            strcmp(c->domain, domain) == 0 &&
            strcmp(c->path, path) == 0) return (int)i;
    }
    return -1;
}

/* ---- Set-Cookie parser ---- */

void http_cookie_jar_set(http_cookie_jar_t *j, const char *set_cookie,
                         const char *default_domain) {
    if (!j || !set_cookie || !default_domain) return;

    /* Parse "name=value; attr; attr; ..." */
    const char *p = set_cookie;
    while (*p == ' ' || *p == '\t') p++;

    const char *eq = strchr(p, '=');
    if (!eq) return;
    const char *name_end = eq;
    while (name_end > p && (name_end[-1] == ' ' || name_end[-1] == '\t')) name_end--;
    size_t name_len = (size_t)(name_end - p);
    if (name_len == 0) return;

    const char *val_start = eq + 1;
    const char *semi = strchr(val_start, ';');
    const char *val_end = semi ? semi : val_start + strlen(val_start);
    while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) val_end--;
    size_t val_len = (size_t)(val_end - val_start);

    http_cookie_t nc;
    memset(&nc, 0, sizeof(nc));
    nc.name  = xstrdup_n(p, name_len);
    nc.value = xstrdup_n(val_start, val_len);
    nc.domain = xstrdup(default_domain);
    nc.path   = xstrdup("/");

    /* Attributes */
    const char *attr = semi ? semi + 1 : NULL;
    while (attr && *attr) {
        while (*attr == ' ' || *attr == '\t' || *attr == ';') attr++;
        if (!*attr) break;
        const char *end = strchr(attr, ';');
        if (!end) end = attr + strlen(attr);

        const char *aeq = memchr(attr, '=', (size_t)(end - attr));
        if (aeq) {
            /* attr = value */
            const char *akey_e = aeq;
            while (akey_e > attr && (akey_e[-1] == ' ' || akey_e[-1] == '\t')) akey_e--;
            size_t aklen = (size_t)(akey_e - attr);
            const char *aval = aeq + 1;
            while (aval < end && (*aval == ' ' || *aval == '\t')) aval++;
            const char *aval_e = end;
            while (aval_e > aval && (aval_e[-1] == ' ' || aval_e[-1] == '\t')) aval_e--;
            size_t avlen = (size_t)(aval_e - aval);

            if (aklen == 6 && !strncasecmp(attr, "Domain", 6)) {
                free(nc.domain);
                /* strip leading dot */
                const char *d = aval;
                if (d < aval_e && *d == '.') d++;
                nc.domain = xstrdup_n(d, (size_t)(aval_e - d));
            } else if (aklen == 4 && !strncasecmp(attr, "Path", 4)) {
                free(nc.path);
                nc.path = xstrdup_n(aval, avlen);
            } else if (aklen == 7 && !strncasecmp(attr, "Expires", 7)) {
                /* parse RFC 1123 date — best-effort, ignore on failure */
                char datebuf[64];
                size_t l = avlen < sizeof(datebuf) - 1 ? avlen : sizeof(datebuf) - 1;
                memcpy(datebuf, aval, l);
                datebuf[l] = 0;
                struct tm tm;
                memset(&tm, 0, sizeof(tm));
                if (strptime(datebuf, "%a, %d %b %Y %H:%M:%S", &tm) != NULL) {
                    nc.expires = (long)timegm(&tm);
                }
            } else if (aklen == 7 && !strncasecmp(attr, "Max-Age", 7)) {
                char nb[32];
                size_t l = avlen < sizeof(nb) - 1 ? avlen : sizeof(nb) - 1;
                memcpy(nb, aval, l);
                nb[l] = 0;
                nc.expires = (long)time(NULL) + atol(nb);
            }
        } else {
            size_t aklen = (size_t)(end - attr);
            if (aklen == 6 && !strncasecmp(attr, "Secure", 6)) nc.secure = 1;
            else if (aklen == 8 && !strncasecmp(attr, "HttpOnly", 8)) nc.httponly = 1;
        }
        attr = end;
    }

    /* Expired? Remove. */
    if (nc.expires > 0 && nc.expires < (long)time(NULL)) {
        int idx = jar_find(j, nc.name, nc.domain, nc.path);
        if (idx >= 0) {
            cookie_free(&j->items[idx]);
        }
        cookie_free(&nc);
        return;
    }

    /* Replace existing or append */
    int idx = jar_find(j, nc.name, nc.domain, nc.path);
    if (idx >= 0) {
        cookie_free(&j->items[idx]);
        j->items[idx] = nc;
    } else {
        if (jar_grow(j) != 0) { cookie_free(&nc); return; }
        j->items[j->count++] = nc;
    }
}

/* ---- Request matching ---- */

/* Domain match: cookie domain "example.com" matches host "www.example.com"
 * (or "example.com"). Cookie domain must not be a public suffix in
 * real RFC 6265 — we skip that check. */
static int domain_matches(const char *cookie_domain, const char *host) {
    size_t dl = strlen(cookie_domain);
    size_t hl = strlen(host);
    if (dl == hl && !strcasecmp(cookie_domain, host)) return 1;
    if (hl > dl && host[hl - dl - 1] == '.' &&
        !strcasecmp(host + hl - dl, cookie_domain)) return 1;
    return 0;
}

/* Path match per RFC 6265 §5.1.4 */
static int path_matches(const char *cookie_path, const char *req_path) {
    size_t cl = strlen(cookie_path);
    size_t rl = strlen(req_path);
    if (cl == 0) return 1;
    if (cl == 1 && cookie_path[0] == '/') return 1;
    if (rl < cl) return 0;
    if (strncmp(cookie_path, req_path, cl) != 0) return 0;
    if (cl == rl) return 1;
    if (cookie_path[cl - 1] == '/') return 1;
    if (req_path[cl] == '/') return 1;
    return 0;
}

size_t http_cookie_jar_header(const http_cookie_jar_t *j,
                              const char *host, const char *path, int secure,
                              char *out, size_t cap) {
    if (!j || !host || !path || !out) return 0;
    size_t w = 0;
    int first = 1;
    for (size_t i = 0; i < j->count; i++) {
        const http_cookie_t *c = &j->items[i];
        if (c->secure && !secure) continue;
        if (c->expires > 0 && c->expires < (long)time(NULL)) continue;
        if (!domain_matches(c->domain, host)) continue;
        if (!path_matches(c->path, path)) continue;

        size_t need = (first ? 0 : 2) + strlen(c->name) + 1 + strlen(c->value);
        if (w + need + 1 > cap) break;
        if (!first) { memcpy(out + w, "; ", 2); w += 2; }
        memcpy(out + w, c->name, strlen(c->name)); w += strlen(c->name);
        out[w++] = '=';
        memcpy(out + w, c->value, strlen(c->value)); w += strlen(c->value);
        first = 0;
    }
    out[w] = 0;
    return w;
}

/* ---- Netscape cookie file format ---- */

int http_cookie_jar_save(const http_cookie_jar_t *j, const char *path) {
    if (!j || !path) return -1;
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "# Netscape HTTP Cookie File\n");
    for (size_t i = 0; i < j->count; i++) {
        const http_cookie_t *c = &j->items[i];
        int tailmatch = (c->domain && c->domain[0] == '.') ? 1 : 0;
        long expiry = c->expires > 0 ? c->expires : 0;
        fprintf(fp, "%s\t%s\t%s\t%s\t%ld\t%s\t%s\n",
                c->domain ? c->domain : "",
                tailmatch ? "TRUE" : "FALSE",
                c->path ? c->path : "/",
                c->secure ? "TRUE" : "FALSE",
                expiry,
                c->name ? c->name : "",
                c->value ? c->value : "");
    }
    fclose(fp);
    return 0;
}

int http_cookie_jar_load(http_cookie_jar_t *j, const char *path) {
    if (!j || !path) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        if (l && line[l-1] == '\n') line[--l] = 0;
        if (l == 0 || line[0] == '#') continue;

        /* domain \t tailmatch \t path \t secure \t expires \t name \t value */
        char *save = NULL;
        char *domain = strtok_r(line, "\t", &save);
        char *tail   = strtok_r(NULL, "\t", &save);
        char *cpath  = strtok_r(NULL, "\t", &save);
        char *sec    = strtok_r(NULL, "\t", &save);
        char *exp    = strtok_r(NULL, "\t", &save);
        char *name   = strtok_r(NULL, "\t", &save);
        char *value  = strtok_r(NULL, "\r\n", &save);
        (void)tail;
        if (!domain || !cpath || !name) continue;

        http_cookie_t nc;
        memset(&nc, 0, sizeof(nc));
        nc.domain = xstrdup(domain);
        nc.path   = xstrdup(cpath);
        nc.name   = xstrdup(name);
        nc.value  = xstrdup(value ? value : "");
        nc.secure = (sec && !strcasecmp(sec, "TRUE")) ? 1 : 0;
        nc.expires = exp ? atol(exp) : 0;

        if (jar_grow(j) != 0) { cookie_free(&nc); break; }
        j->items[j->count++] = nc;
    }
    fclose(fp);
    return 0;
}
