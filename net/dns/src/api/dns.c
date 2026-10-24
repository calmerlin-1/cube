/** dns.c — public resolver API. Racing, fallback, caching. */

#include "../include/dns.h"
#include "../include/dns_cache.h"
#include "dns_wire.h"
#include "dns_arena.h"
#include "dns_upstream.h"
#include "dns_pin.h"
#include "dns_transport.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

uint64_t dns_now_ns(void);

struct dns_resolver {
    dns_config_t      cfg;
    dns_upstream_pool_t *up;
    dns_cache_t       *cache;
    dns_stats_t        stats;
    uint32_t           queries_since_save;
    dns_pin_store_t   *pins;
};

/** resolver lifecycle */

dns_resolver_t *dns_resolver_new(const dns_config_t *cfg) {
    dns_resolver_t *r = (dns_resolver_t *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    if (cfg) r->cfg = *cfg;
    else {
        r->cfg.timeout_ms = 5000;
        r->cfg.retry_count = 2;
        r->cfg.cache_max = 4096;
        r->cfg.cache_max_bytes = 0;
        r->cfg.edns_udp_size = 4096;
    }
    r->up = dns_upstream_pool_new();
    if (!r->up) { free(r); return NULL; }
    if (r->cfg.cache_max) r->cache = dns_cache_new(r->cfg.cache_max);
    if (r->cache && r->cfg.cache_path) dns_cache_load(r->cache, r->cfg.cache_path);
    r->pins = dns_pin_new(4096);
    /* load persisted scores if configured */
    if (r->cfg.persist_path) {
        dns_upstream_load(r->up, r->cfg.persist_path);
    }
    return r;
}

dns_resolver_t *dns_resolver_new_default(void) {
    dns_resolver_t *r = dns_resolver_new(NULL);
    if (!r) return NULL;

    /* Try the shipped config first — it lists UDP, DoH, and DoT
     * upstreams. Falls back to a broader hardcoded list if the file
     * can't be found (e.g. cube run outside the repo root). */
    int loaded = dns_resolver_load_conf(r, "net/dns/data/resolvers.conf");
    if (loaded <= 0) {
        /* Wide seed list — the racer picks whichever responds first.
         * Spread across providers reduces correlated failure. */
        static const char *udp_seeds[] = {
            "1.1.1.1", "1.0.0.1",           /* Cloudflare */
            "8.8.8.8", "8.8.4.4",           /* Google */
            "9.9.9.9",                      /* Quad9 */
            "208.67.222.222", "208.67.220.220",  /* OpenDNS */
            "185.222.222.222",              /* DNS.SB */
            "94.140.14.14",                 /* AdGuard */
            "194.242.2.2",                  /* Mullvad */
            "76.76.2.0",                    /* ControlD */
            "45.90.28.0",                   /* NextDNS */
        };
        for (size_t i = 0; i < sizeof(udp_seeds)/sizeof(udp_seeds[0]); i++)
            dns_upstream_add(r->up, udp_seeds[i], 53, UP_PROTO_UDP, NULL);
    }
    return r;
}

void dns_resolver_free(dns_resolver_t *r) {
    if (!r) return;
    if (r->up && r->cfg.persist_path) {
        dns_upstream_save(r->up, r->cfg.persist_path);
    }
    if (r->up) dns_upstream_pool_free(r->up);
    if (r->cache && r->cfg.cache_path) dns_cache_save(r->cache, r->cfg.cache_path);
    if (r->cache) dns_cache_free(r->cache);
    if (r->pins) dns_pin_free(r->pins);
    free(r);
}

int dns_resolver_load_conf(dns_resolver_t *r, const char *path) {
    if (!r || !path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#') continue;
        char cmd[32] = {0}, a[256] = {0}, b[256] = {0};
        unsigned port = 0;
        int n = sscanf(p, "%31s %255s %u %255s", cmd, a, &port, b);
        if (n < 2) continue;
        if (strcmp(cmd, "upstream") == 0) {
            dns_upstream_add(r->up, a, port ? (uint16_t)port : 53, UP_PROTO_UDP, NULL);
            loaded++;
        } else if (strcmp(cmd, "doh") == 0) {
            /* a holds the URL */
            dns_upstream_add(r->up, a, 443, UP_PROTO_DOH, a);
            loaded++;
        } else if (strcmp(cmd, "dot") == 0) {
            dns_upstream_add(r->up, a, port ? (uint16_t)port : 853, UP_PROTO_DOT, NULL);
            loaded++;
        } else if (strcmp(cmd, "timeout") == 0) {
            r->cfg.timeout_ms = (uint32_t)atoi(a);
        } else if (strcmp(cmd, "retry") == 0) {
            r->cfg.retry_count = (uint32_t)atoi(a);
        } else if (strcmp(cmd, "cache") == 0) {
            r->cfg.cache_max = (size_t)atoi(a);
        } else if (strcmp(cmd, "edns-size") == 0) {
            r->cfg.edns_udp_size = atoi(a);
        } else if (strcmp(cmd, "dnssec") == 0) {
            r->cfg.require_dnssec = (strcmp(a, "on") == 0);
        }
    }
    fclose(f);
    return loaded;
}

/** resolution */

static int do_one_query(dns_resolver_t *r, size_t up_idx,
                        const char *name, size_t namelen,
                        uint16_t type, uint16_t cls, uint32_t flags,
                        dns_answer_t *out) {
    dns_upstream_t *u = &r->up->items[up_idx];
    uint16_t id = dns_random_id();
    uint8_t query[1024];
    size_t qlen = dns_wire_build_query(id, name, namelen, type, cls,
                                       flags, r->cfg.edns_udp_size,
                                       query, sizeof(query));
    if (qlen == 0) return DNS_ERR_WIRE;

    uint8_t resp[65536];
    uint64_t lat = 0;
    int n = -1;

    if (u->proto == UP_PROTO_DOH) {
        n = dns_transport_doh(u->doh_url, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
    } else if (u->proto == UP_PROTO_DOT) {
        n = dns_transport_dot(u->addr, u->port, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
    } else if (u->proto == UP_PROTO_UDP && !(flags & DNS_F_TCP_ONLY)) {
        n = dns_transport_udp(u->addr, u->port, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
    } else if (u->proto == UP_PROTO_TCP || (flags & DNS_F_TCP_ONLY)) {
        n = dns_transport_tcp(u->addr, u->port, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
    } else {
        n = dns_transport_udp(u->addr, u->port, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
    }

    if (n == 0) {
        dns_upstream_record_timeout(r->up, up_idx);
        return DNS_ERR_TIMEOUT;
    }
    if (n < 0) {
        dns_upstream_record_failure(r->up, up_idx, 0);
        return DNS_ERR_NETWORK;
    }
    if (u->proto == UP_PROTO_DOH)       r->stats.queries_doh++;
    else if (u->proto == UP_PROTO_DOT)  r->stats.queries_dot++;
    else if (u->proto == UP_PROTO_TCP ||
             (flags & DNS_F_TCP_ONLY))  r->stats.queries_tcp++;
    else                                r->stats.queries_udp++;

    int pr = dns_wire_parse_response(resp, (size_t)n, id, name, type, out);
    if (pr == DNS_ERR_TRUNCATED) {
        /* retry over TCP */
        n = dns_transport_tcp(u->addr, u->port, query, qlen, resp, sizeof(resp),
                              r->cfg.timeout_ms, &lat);
        if (n > 0) {
            pr = dns_wire_parse_response(resp, (size_t)n, id, name, type, out);
        }
    }
    if (pr == DNS_OK) dns_upstream_record_ok(r->up, up_idx, lat, out->rcode);
    else              dns_upstream_record_failure(r->up, up_idx, (uint8_t)pr);

    return pr;
}

/* Monotonic clock helper — local to dns.c. */
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Forward decl for the wrapper below. */
static int dns_resolve_inner(dns_resolver_t *r, const char *name, uint16_t type,
                             uint32_t flags, dns_answer_t *out);

/* Public API — times the inner resolve and fills out->elapsed_ns. */
int dns_resolve(dns_resolver_t *r, const char *name, uint16_t type,
                uint32_t flags, dns_answer_t *out) {
    uint64_t t0 = now_ns();
    int rc = dns_resolve_inner(r, name, type, flags, out);
    if (out) out->elapsed_ns = now_ns() - t0;
    return rc;
}

/* Original dns_resolve body, renamed. */
static int dns_resolve_inner(dns_resolver_t *r, const char *name, uint16_t type,
                             uint32_t flags, dns_answer_t *out) {
    if (!r || !name || !out) return DNS_ERR_ARGS;
    size_t nlen = strlen(name);
    if (nlen == 0 || nlen > DNS_MAX_NAME) return DNS_ERR_ARGS;

    /* lower-case name for cache key consistency */
    char lname[DNS_MAX_NAME];
    for (size_t i = 0; i < nlen; i++) lname[i] = (char)tolower((unsigned char)name[i]);
    lname[nlen] = '\0';

    r->stats.queries_total++;
    r->queries_since_save++;
    if (r->cfg.persist_every && r->queries_since_save >= r->cfg.persist_every
        && r->up && r->cfg.persist_path) {
        dns_upstream_save(r->up, r->cfg.persist_path);
        r->queries_since_save = 0;
    }

    if (r->cache && !(flags & DNS_F_NO_CACHE)) {
        int cr = dns_cache_get(r->cache, lname, type, DNS_CLASS_IN, out);
        if (cr == DNS_OK) { r->stats.queries_cached++; return DNS_OK; }
        /* negative cache also returns error, propagate */
        if (cr == DNS_ERR_NXDOMAIN || cr == DNS_ERR_RCODE) {
            r->stats.queries_cached++;
            return cr;
        }
    }

    if (r->up->count == 0) return DNS_ERR_NO_UPSTREAM;

    size_t top[8];
    size_t ntop = dns_upstream_top(r->up, top, sizeof(top)/sizeof(top[0]));
    if (ntop == 0) return DNS_ERR_NO_UPSTREAM;

    /* per-domain pin: if we've resolved this name+type before, put the
     * winning upstream first, so phase-1 of staged racing hits it. */
    if (r->pins) {
        size_t pinned = dns_pin_get(r->pins, lname, type);
        if (pinned != SIZE_MAX) {
            for (size_t i = 0; i < ntop; i++) {
                if (top[i] == pinned) {
                    /* swap to front */
                    size_t tmp = top[0];
                    top[0] = top[i];
                    top[i] = tmp;
                    break;
                }
            }
        }
    }

    /* If the caller forced a specific transport, drop non-matching
     * upstreams before racing. Otherwise the race sees all upstreams
     * and UDP always wins on speed — the flag would be ignored. */
    if (flags & (DNS_F_DOT_ONLY | DNS_F_DOH_ONLY |
                 DNS_F_TCP_ONLY | DNS_F_UDP_ONLY)) {
        size_t filtered[8];
        size_t nf = 0;
        for (size_t i = 0; i < ntop && nf < 8; i++) {
            uint8_t p = r->up->items[top[i]].proto;
            int want = 0;
            if ((flags & DNS_F_DOT_ONLY) && p == UP_PROTO_DOT) want = 1;
            if ((flags & DNS_F_DOH_ONLY) && p == UP_PROTO_DOH) want = 1;
            if ((flags & DNS_F_TCP_ONLY) && p == UP_PROTO_TCP) want = 1;
            if ((flags & DNS_F_UDP_ONLY) && p == UP_PROTO_UDP) want = 1;
            if (want) filtered[nf++] = top[i];
        }
        if (nf > 0) {
            memcpy(top, filtered, nf * sizeof(size_t));
            ntop = nf;
        }
    }
    int last_err = DNS_ERR_TIMEOUT;

    /* Fast path: single query to top upstream (short window) */
    if (!(flags & DNS_F_NO_RETRY) && ntop >= 2) {
        /* build query once, race top-K in parallel */
        uint16_t id = dns_random_id();
        uint8_t query[1024];
        size_t qlen = dns_wire_build_query(id, lname, nlen, type, DNS_CLASS_IN,
                                           flags, r->cfg.edns_udp_size,
                                           query, sizeof(query));
        if (qlen > 0) {
            uint8_t resp[65536];
            size_t win_idx = 0;
            uint64_t win_lat = 0;
            uint32_t window_ms = r->cfg.timeout_ms ? (r->cfg.timeout_ms / 4) : 50;
            int n = dns_race_query(r->up, top, ntop, query, qlen,
                                   resp, sizeof(resp),
                                   window_ms, r->cfg.timeout_ms,
                                   &win_idx, &win_lat);
            if (n > 0) {
                if (win_idx < r->up->count) {
                    up_proto_t wp = (up_proto_t)r->up->items[win_idx].proto;
                    if      (wp == UP_PROTO_DOH) r->stats.queries_doh++;
                    else if (wp == UP_PROTO_DOT) r->stats.queries_dot++;
                    else if (wp == UP_PROTO_TCP) r->stats.queries_tcp++;
                    else                         r->stats.queries_udp++;
                }
                int pr = dns_wire_parse_response(resp, (size_t)n, id, lname, type, out);
                if (pr == DNS_OK) {
                    dns_upstream_record_ok(r->up, win_idx, win_lat, out->rcode);
                    if (r->pins) dns_pin_set(r->pins, lname, type, win_idx);
                    if (r->cache && !(flags & DNS_F_NO_CACHE))
                        dns_cache_put(r->cache, lname, type, DNS_CLASS_IN, out, 0);
                    return DNS_OK;
                }
                if (pr == DNS_ERR_NXDOMAIN || pr == DNS_ERR_RCODE) {
                    dns_upstream_record_ok(r->up, win_idx, win_lat, out->rcode);
                    if (r->cache && !(flags & DNS_F_NO_CACHE))
                        dns_cache_put_negative(r->cache, lname, type, DNS_CLASS_IN,
                                               (uint8_t)out->rcode, 30);
                    return pr;
                }
                last_err = pr;
            }
        }
    }

    /* Fallback: sequential retry through ranked upstreams */
    uint32_t retries = r->cfg.retry_count ? r->cfg.retry_count : 1;
    if (flags & DNS_F_NO_RETRY) retries = 1;
    for (uint32_t attempt = 0; attempt < retries; attempt++) {
        size_t idx = top[attempt % ntop];
        int pr = do_one_query(r, idx, lname, nlen, type, DNS_CLASS_IN, flags, out);
        if (pr == DNS_OK || pr == DNS_ERR_NXDOMAIN || pr == DNS_ERR_RCODE) {
            if (r->cache && !(flags & DNS_F_NO_CACHE)) {
                if (pr == DNS_OK) dns_cache_put(r->cache, lname, type, DNS_CLASS_IN, out, 0);
                else              dns_cache_put_negative(r->cache, lname, type, DNS_CLASS_IN, (uint8_t)out->rcode, 30);
            }
            return pr;
        }
        last_err = pr;
    }
    r->stats.queries_failed++;
    return last_err;
}

/** convenience */

int dns_resolve_a    (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_A, 0, o); }
int dns_resolve_aaaa (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_AAAA, 0, o); }
int dns_resolve_mx   (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_MX, 0, o); }
int dns_resolve_txt  (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_TXT, 0, o); }
int dns_resolve_ns   (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_NS, 0, o); }
int dns_resolve_cname(dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_CNAME, 0, o); }
int dns_resolve_srv  (dns_resolver_t *r, const char *n, dns_answer_t *o) { return dns_resolve(r, n, DNS_TYPE_SRV, 0, o); }

/** Build reverse name for IPv4 in-addr.arpa and IPv6 ip6.arpa. */
int dns_resolve_reverse(dns_resolver_t *r, const char *ip, dns_answer_t *out) {
    if (!r || !ip || !out) return DNS_ERR_ARGS;
    char rev[DNS_MAX_NAME];
    if (strchr(ip, ':')) {
        /* IPv6: expand to 8 groups of 16-bit words, then to 32 hex nibbles,
         * reverse them dot-separated, append ip6.arpa */
        unsigned short words[8] = {0};
        int nw = 0, dcolon = -1;
        const char *p = ip;
        while (*p && nw < 8) {
            if (p[0] == ':' && p[1] == ':') { dcolon = nw; p += 2; continue; }
            if (p[0] == ':') { p++; continue; }
            unsigned v = 0;
            int digits = 0;
            while (*p && *p != ':' && digits < 4) {
                int h = -1;
                char c = *p;
                if (c >= '0' && c <= '9') h = c - '0';
                else if (c >= 'a' && c <= 'f') h = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') h = c - 'A' + 10;
                if (h < 0) break;
                v = (v << 4) | (unsigned)h;
                p++; digits++;
            }
            if (digits > 0) words[nw++] = (unsigned short)v;
            if (*p == '.') {
                /* embedded IPv4 — should not happen if caller passed pure v6 */
                return DNS_ERR_ARGS;
            }
        }
        if (dcolon >= 0) {
            int move = nw - dcolon;
            for (int i = move - 1; i >= 0; i--)
                words[7 - (move - 1 - i)] = words[dcolon + i];
            for (int i = dcolon; i < 8 - move; i++)
                words[i] = 0;
        }
        /* build reversed nibble string */
        int w = 0;
        for (int i = 7; i >= 0; i--) {
            for (int nib = 0; nib < 4; nib++) {
                int shift = (3 - nib) * 4;
                int h = (words[i] >> shift) & 0xF;
                w += snprintf(rev + w, sizeof(rev) - w, "%x.", h);
            }
        }
        if (w + 9 >= (int)sizeof(rev)) return DNS_ERR_ARGS;
        memcpy(rev + w, "ip6.arpa", 9);
        return dns_resolve(r, rev, DNS_TYPE_PTR, 0, out);
    }
    int a1,a2,a3,a4;
    if (sscanf(ip, "%d.%d.%d.%d", &a1,&a2,&a3,&a4) != 4) return DNS_ERR_ARGS;
    snprintf(rev, sizeof(rev), "%d.%d.%d.%d.in-addr.arpa", a4,a3,a2,a1);
    return dns_resolve(r, rev, DNS_TYPE_PTR, 0, out);
}

int dns_resolve_dual(dns_resolver_t *r, const char *name, dns_answer_t *out) {
    if (!r || !name || !out) return DNS_ERR_ARGS;
    dns_answer_t a4, a6;
    memset(&a4, 0, sizeof(a4));
    memset(&a6, 0, sizeof(a6));
    int r4 = dns_resolve_a(r, name, &a4);
    int r6 = dns_resolve_aaaa(r, name, &a6);
    if (r4 != DNS_OK && r6 != DNS_OK) { dns_answer_free(&a4); dns_answer_free(&a6); return r4; }

    dns_arena_t *ar = dns_arena_new(4096);
    if (!ar) { dns_answer_free(&a4); dns_answer_free(&a6); return DNS_ERR_NOMEM; }
    size_t total = (r4 == DNS_OK ? a4.count : 0) + (r6 == DNS_OK ? a6.count : 0);
    memset(out, 0, sizeof(*out));
    out->arena = ar;
    out->records = (dns_record_t *)dns_arena_alloc(ar, total * sizeof(dns_record_t));
    if (!out->records) { dns_arena_free(ar); out->arena = NULL; dns_answer_free(&a4); dns_answer_free(&a6); return DNS_ERR_NOMEM; }
    size_t w = 0;
    if (r4 == DNS_OK) for (size_t i = 0; i < a4.count; i++) out->records[w++] = a4.records[i];
    if (r6 == DNS_OK) for (size_t i = 0; i < a6.count; i++) out->records[w++] = a6.records[i];
    out->count = w;
    out->capacity = total;
    snprintf(out->qname, sizeof(out->qname), "%s", name);
    dns_answer_free(&a4);
    dns_answer_free(&a6);
    return DNS_OK;
}

void dns_answer_free(dns_answer_t *a) {
    if (!a || !a->arena) return;
    dns_arena_free((dns_arena_t *)a->arena);
    a->arena = NULL;
    a->records = NULL;
    a->count = 0;
}

const dns_record_t *dns_answer_first(const dns_answer_t *a, uint16_t type) {
    if (!a) return NULL;
    for (size_t i = 0; i < a->count; i++)
        if (a->records[i].type == type) return &a->records[i];
    return NULL;
}

void dns_resolver_set_persist(dns_resolver_t *r, const char *path) {
    if (!r) return;
    r->cfg.persist_path = path;
    if (path) {
        r->cfg.persist_every = 100;
        if (r->up) dns_upstream_load(r->up, path);
    }
}

void dns_resolver_set_cache_path(dns_resolver_t *r, const char *path) {
    if (!r) return;
    r->cfg.cache_path = path;
    if (r->cache && path) dns_cache_load(r->cache, path);
}

int dns_resolver_save_scores(dns_resolver_t *r) {
    if (!r || !r->up || !r->cfg.persist_path) return -1;
    int rc = dns_upstream_save(r->up, r->cfg.persist_path);
    if (rc == 0) r->queries_since_save = 0;
    return rc;
}

void dns_resolver_cache_clear(dns_resolver_t *r) { if (r && r->cache) dns_cache_clear(r->cache); }
void dns_resolver_cache_set_max(dns_resolver_t *r, size_t n) { if (r && r->cache) dns_cache_set_max(r->cache, n); }

size_t dns_upstream_count(dns_resolver_t *r) {
    return (r && r->up) ? r->up->count : 0;
}
void dns_stats(dns_resolver_t *r, dns_stats_t *out) {
    if (!r || !out) return;
    *out = r->stats;
    if (r->cache) {
        dns_cache_stats_t cs;
        dns_cache_stats(r->cache, &cs);
        out->cache_entries = cs.entries;
        out->cache_bytes = cs.bytes;
        out->cache_evictions = cs.evictions;
    }
}

/** names */

const char *dns_type_name(uint16_t t) {
    switch (t) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_DS: return "DS";
        case DNS_TYPE_RRSIG: return "RRSIG";
        case DNS_TYPE_DNSKEY: return "DNSKEY";
        case DNS_TYPE_CAA: return "CAA";
        case DNS_TYPE_SVCB: return "SVCB";
        case DNS_TYPE_HTTPS: return "HTTPS";
        case DNS_TYPE_OPT: return "OPT";
        default: return "?";
    }
}

const char *dns_rcode_name(uint8_t c) {
    switch (c) {
        case DNS_RCODE_NOERROR: return "NOERROR";
        case DNS_RCODE_FORMERR: return "FORMERR";
        case DNS_RCODE_SERVFAIL: return "SERVFAIL";
        case DNS_RCODE_NXDOMAIN: return "NXDOMAIN";
        case DNS_RCODE_NOTIMP: return "NOTIMP";
        case DNS_RCODE_REFUSED: return "REFUSED";
        default: return "?";
    }
}

const char *dns_err_name(int e) {
    switch (e) {
        case DNS_OK: return "ok";
        case DNS_ERR_ARGS: return "args";
        case DNS_ERR_NOMEM: return "nomem";
        case DNS_ERR_WIRE: return "wire";
        case DNS_ERR_TIMEOUT: return "timeout";
        case DNS_ERR_NETWORK: return "network";
        case DNS_ERR_RCODE: return "rcode";
        case DNS_ERR_NXDOMAIN: return "nxdomain";
        case DNS_ERR_TRUNCATED: return "truncated";
        case DNS_ERR_CACHE_MISS: return "cache-miss";
        case DNS_ERR_NO_UPSTREAM: return "no-upstream";
        case DNS_ERR_TOO_LARGE: return "too-large";
        case DNS_ERR_COMPRESSION: return "compression";
        case DNS_ERR_LOOP: return "loop";
        case DNS_ERR_NO_RECORDS: return "no-records";
    }
    return "unknown";
}

int dns_record_format(const dns_record_t *rec, char *out, size_t cap) {
    if (!rec || !out) return -1;
    switch (rec->type) {
        case DNS_TYPE_A:
            return snprintf(out, cap, "%s A %u.%u.%u.%u", rec->name, rec->u.a.addr[0],
                            rec->u.a.addr[1], rec->u.a.addr[2], rec->u.a.addr[3]);
        case DNS_TYPE_AAAA: {
            int w = snprintf(out, cap, "%s AAAA ", rec->name);
            for (int i = 0; i < 16; i += 2) {
                w += snprintf(out + w, cap - w, "%s%02x%02x",
                              i ? ":" : "", rec->u.aaaa.addr[i], rec->u.aaaa.addr[i+1]);
            }
            return w;
        }
        case DNS_TYPE_CNAME: return snprintf(out, cap, "%s CNAME %s", rec->name, rec->u.cname.target);
        case DNS_TYPE_NS:    return snprintf(out, cap, "%s NS %s", rec->name, rec->u.ns.target);
        case DNS_TYPE_PTR:   return snprintf(out, cap, "%s PTR %s", rec->name, rec->u.ptr.target);
        case DNS_TYPE_MX:    return snprintf(out, cap, "%s MX %u %s", rec->name, rec->u.mx.preference, rec->u.mx.target);
        case DNS_TYPE_TXT:   return snprintf(out, cap, "%s TXT \"%s\"", rec->name, rec->u.txt.text);
        case DNS_TYPE_SRV:   return snprintf(out, cap, "%s SRV %u %u %u %s", rec->name, rec->u.srv.priority, rec->u.srv.weight, rec->u.srv.port, rec->u.srv.target);
        case DNS_TYPE_SOA:
            return snprintf(out, cap, "%s SOA %s %s %u %u %u %u %u",
                            rec->name,
                            rec->u.soa.mname, rec->u.soa.rname,
                            rec->u.soa.serial, rec->u.soa.refresh,
                            rec->u.soa.retry, rec->u.soa.expire,
                            rec->u.soa.minimum);
        case DNS_TYPE_CAA: {
            char tag[64] = {0}, val[256] = {0};
            size_t tl = rec->u.caa.taglen;
            size_t vl = rec->u.caa.valuelen;
            if (tl > sizeof(tag) - 1) tl = sizeof(tag) - 1;
            if (vl > sizeof(val) - 1) vl = sizeof(val) - 1;
            memcpy(tag, rec->u.caa.tag, tl);
            memcpy(val, rec->u.caa.value, vl);
            return snprintf(out, cap, "%s CAA %u %s \"%s\"",
                            rec->name, rec->u.caa.flags, tag, val);
        }
        case DNS_TYPE_DS:
            return snprintf(out, cap, "%s DS %u %u %u",
                            rec->name, rec->u.ds.keytag,
                            rec->u.ds.algorithm, rec->u.ds.digesttype);
        case DNS_TYPE_DNSKEY:
            return snprintf(out, cap, "%s DNSKEY %u %u %u [%u bytes]",
                            rec->name, rec->u.dnskey.flags,
                            rec->u.dnskey.protocol, rec->u.dnskey.algorithm,
                            rec->u.dnskey.keylen);
        case DNS_TYPE_RRSIG:
            return snprintf(out, cap,
                            "%s RRSIG %s/%u/%u/%u %s keytag %u [%u bytes sig]",
                            rec->name,
                            dns_type_name(rec->u.rrsig.typecovered),
                            rec->u.rrsig.algorithm, rec->u.rrsig.labels,
                            rec->u.rrsig.origttl,
                            rec->u.rrsig.signer,
                            rec->u.rrsig.keytag,
                            rec->u.rrsig.siglen);
        case DNS_TYPE_SVCB:
        case DNS_TYPE_HTTPS:
            return snprintf(out, cap, "%s %s %u %s [%u bytes params]",
                            rec->name, dns_type_name(rec->type),
                            rec->u.svcb.priority, rec->u.svcb.target,
                            rec->u.svcb.paramslen);
        default:             return snprintf(out, cap, "%s %s (raw)", rec->name, dns_type_name(rec->type));
    }
}
