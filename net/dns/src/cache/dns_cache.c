/** dns_cache.c — LRU + TTL cache. Per-type keys, negative entries, upstream pin. */

#include "../include/dns_cache.h"
#include "../include/dns.h"
#include "dns_arena.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>

typedef struct entry {
    char            name[DNS_MAX_NAME];
    uint16_t        type;
    uint16_t        cls;
    uint8_t         is_negative;
    uint8_t         rcode;         /* if negative */
    uint32_t        ttl;           /* seconds */
    uint64_t        expires_ns;
    uint64_t        last_hit_ns;
    size_t          pinned_upstream;   /* SIZE_MAX if none */
    dns_record_t   *records;
    size_t          count;
    dns_arena_t    *arena;
    struct entry   *prev, *next;   /* LRU list */
} entry_t;

struct dns_cache {
    entry_t *head;                 /* most recent */
    entry_t *tail;                 /* least recent */
    size_t   count;
    size_t   max;
    size_t   bytes;
    uint64_t hits, misses, evictions, expired;
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void unlink_lru(dns_cache_t *c, entry_t *e) {
    if (e->prev) e->prev->next = e->next; else c->head = e->next;
    if (e->next) e->next->prev = e->prev; else c->tail = e->prev;
    e->prev = e->next = NULL;
}

static void link_front(dns_cache_t *c, entry_t *e) {
    e->prev = NULL;
    e->next = c->head;
    if (c->head) c->head->prev = e;
    c->head = e;
    if (!c->tail) c->tail = e;
}

static void free_entry(dns_cache_t *c, entry_t *e) {
    if (e->arena) dns_arena_free(e->arena);
    unlink_lru(c, e);
    c->bytes -= sizeof(*e) + (e->count * sizeof(dns_record_t));
    free(e);
    c->count--;
}

dns_cache_t *dns_cache_new(size_t max_entries) {
    dns_cache_t *c = (dns_cache_t *)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->max = max_entries ? max_entries : 1024;
    return c;
}

void dns_cache_free(dns_cache_t *c) {
    if (!c) return;
    entry_t *e = c->head;
    while (e) {
        entry_t *nx = e->next;
        if (e->arena) dns_arena_free(e->arena);
        free(e);
        e = nx;
    }
    free(c);
}

void dns_cache_clear(dns_cache_t *c) {
    if (!c) return;
    entry_t *e = c->head;
    while (e) {
        entry_t *nx = e->next;
        if (e->arena) dns_arena_free(e->arena);
        free(e);
        e = nx;
    }
    c->head = c->tail = NULL;
    c->count = 0;
    c->bytes = 0;
}

void dns_cache_set_max(dns_cache_t *c, size_t max) {
    if (!c) return;
    c->max = max ? max : 1;
    while (c->count > c->max && c->tail) {
        c->evictions++;
        free_entry(c, c->tail);
    }
}

static entry_t *find(dns_cache_t *c, const char *name, uint16_t type, uint16_t cls) {
    for (entry_t *e = c->head; e; e = e->next) {
        if (e->type == type && e->cls == cls && strcmp(e->name, name) == 0)
            return e;
    }
    return NULL;
}

int dns_cache_get(dns_cache_t *c, const char *name, uint16_t type, uint16_t cls,
                  dns_answer_t *out) {
    if (!c || !name || !out) return DNS_ERR_ARGS;
    entry_t *e = find(c, name, type, cls);
    if (!e) { c->misses++; return DNS_ERR_CACHE_MISS; }
    uint64_t now = now_ns();
    if (now >= e->expires_ns) {
        c->expired++;
        free_entry(c, e);
        c->misses++;
        return DNS_ERR_CACHE_MISS;
    }
    e->last_hit_ns = now;
    unlink_lru(c, e);
    link_front(c, e);
    c->hits++;

    memset(out, 0, sizeof(*out));
    if (e->is_negative) {
        out->rcode = e->rcode;
        out->qtype = type;
        out->qclass = cls;
        memcpy(out->qname, name, strlen(name) + 1);
        if (e->rcode == DNS_RCODE_NXDOMAIN) return DNS_ERR_NXDOMAIN;
        return DNS_ERR_RCODE;
    }
    /* copy records into a new arena for caller ownership */
    dns_arena_t *ar = dns_arena_new(e->count * sizeof(dns_record_t) + 256);
    if (!ar) return DNS_ERR_NOMEM;
    dns_record_t *cp = (dns_record_t *)dns_arena_alloc(ar, e->count * sizeof(dns_record_t));
    if (!cp) { dns_arena_free(ar); return DNS_ERR_NOMEM; }
    memcpy(cp, e->records, e->count * sizeof(dns_record_t));
    out->records = cp;
    out->count = e->count;
    out->capacity = e->count;
    out->arena = ar;
    out->qtype = type;
    out->qclass = cls;
    memcpy(out->qname, name, strlen(name) + 1);
    return DNS_OK;
}

void dns_cache_put(dns_cache_t *c, const char *name, uint16_t type, uint16_t cls,
                   const dns_answer_t *answer, uint32_t ttl_override) {
    if (!c || !name || !answer) return;
    entry_t *old = find(c, name, type, cls);
    if (old) free_entry(c, old);

    while (c->count >= c->max && c->tail) {
        c->evictions++;
        free_entry(c, c->tail);
    }

    entry_t *e = (entry_t *)calloc(1, sizeof(*e));
    if (!e) return;
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->type = type;
    e->cls = cls;

    /* TTL: min of record TTLs, or override */
    uint32_t ttl = ttl_override;
    if (ttl == 0) {
        ttl = 3600;
        for (size_t i = 0; i < answer->count; i++) {
            if (i == 0 || answer->records[i].ttl < ttl) ttl = answer->records[i].ttl;
        }
    }
    if (ttl == 0) ttl = 1;
    e->ttl = ttl;
    e->expires_ns = now_ns() + (uint64_t)ttl * 1000000000ull;
    e->last_hit_ns = now_ns();

    if (answer->count > 0) {
        dns_arena_t *ar = dns_arena_new(answer->count * sizeof(dns_record_t) + 256);
        if (!ar) { free(e); return; }
        dns_record_t *cp = (dns_record_t *)dns_arena_alloc(ar, answer->count * sizeof(dns_record_t));
        if (!cp) { dns_arena_free(ar); free(e); return; }
        memcpy(cp, answer->records, answer->count * sizeof(dns_record_t));
        e->records = cp;
        e->count = answer->count;
        e->arena = ar;
    }
    link_front(c, e);
    c->count++;
    c->bytes += sizeof(*e) + (e->count * sizeof(dns_record_t));
}

void dns_cache_put_negative(dns_cache_t *c, const char *name, uint16_t type, uint16_t cls,
                            uint8_t rcode, uint32_t ttl) {
    if (!c || !name) return;
    entry_t *old = find(c, name, type, cls);
    if (old) free_entry(c, old);
    while (c->count >= c->max && c->tail) { c->evictions++; free_entry(c, c->tail); }
    entry_t *e = (entry_t *)calloc(1, sizeof(*e));
    if (!e) return;
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->type = type;
    e->cls = cls;
    e->is_negative = 1;
    e->rcode = rcode;
    e->ttl = ttl ? ttl : 30;
    e->expires_ns = now_ns() + (uint64_t)e->ttl * 1000000000ull;
    e->last_hit_ns = now_ns();
    link_front(c, e);
    c->count++;
    c->bytes += sizeof(*e);
}

int dns_cache_put_host(dns_cache_t *c, const char *name, const char *ip, uint32_t ttl) {
    if (!c || !name || !ip) return -1;
    dns_arena_t *ar = dns_arena_new(512);
    if (!ar) return -1;
    dns_answer_t a;
    memset(&a, 0, sizeof(a));
    a.arena = ar;
    a.records = (dns_record_t *)dns_arena_alloc(ar, sizeof(dns_record_t));
    if (!a.records) { dns_arena_free(ar); return -1; }
    a.count = 1;
    dns_record_t *r = &a.records[0];
    snprintf(r->name, sizeof(r->name), "%s", name);
    r->ttl = ttl ? ttl : 3600;
    r->cls = DNS_CLASS_IN;

    /* detect v4 vs v6 by colon presence */
    if (strchr(ip, ':')) {
        r->type = DNS_TYPE_AAAA;
        /* parse IPv6 into 16 bytes */
        unsigned char buf[16] = {0};
        unsigned short words[8] = {0};
        int nw = 0, dcolon = -1;
        const char *p = ip;
        for (int i = 0; i < 8 && *p; i++) {
            if (p[0] == ':' && p[1] == ':') { dcolon = i; p += 2; continue; }
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
                v = (v << 4) | h;
                p++; digits++;
            }
            if (nw < 8) words[nw++] = (unsigned short)v;
        }
        if (dcolon >= 0) {
            int move = nw - dcolon;
            for (int i = move - 1; i >= 0; i--) words[7 - (move - 1 - i)] = words[dcolon + i];
            for (int i = dcolon; i < 8 - move; i++) words[i] = 0;
        }
        for (int i = 0; i < 8; i++) {
            buf[i*2]   = (unsigned char)(words[i] >> 8);
            buf[i*2+1] = (unsigned char)(words[i] & 0xFF);
        }
        memcpy(r->u.aaaa.addr, buf, 16);
    } else {
        r->type = DNS_TYPE_A;
        int a1, a2, a3, a4;
        if (sscanf(ip, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) == 4) {
            r->u.a.addr[0] = (uint8_t)a1;
            r->u.a.addr[1] = (uint8_t)a2;
            r->u.a.addr[2] = (uint8_t)a3;
            r->u.a.addr[3] = (uint8_t)a4;
        }
    }
    dns_cache_put(c, name, r->type, DNS_CLASS_IN, &a, ttl);
    dns_arena_free(ar);
    return 0;
}

void dns_cache_stats(dns_cache_t *c, dns_cache_stats_t *out) {
    if (!c || !out) return;
    memset(out, 0, sizeof(*out));
    out->entries = c->count;
    out->bytes = c->bytes;
    out->hits = c->hits;
    out->misses = c->misses;
    out->evictions = c->evictions;
    out->expired = c->expired;
}

/* ============================================================
 * Persistence: save/load A and AAAA entries as text.
 * Format per line:
 *   name type cls ttl_seconds records_count ip1 ip2 ...
 * Negative entries and non-address types are not persisted.
 * ============================================================ */

int dns_cache_save(dns_cache_t *c, const char *path) {
    if (!c || !path) return -1;
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    uint64_t now = now_ns();
    for (entry_t *e = c->head; e; e = e->next) {
        if (e->is_negative) continue;
        if (e->type != DNS_TYPE_A && e->type != DNS_TYPE_AAAA) continue;
        if (e->expires_ns <= now) continue;   /* already expired */

        uint64_t expires_s = e->expires_ns / 1000000000ull;
        fprintf(fp, "%s %u %u %llu %zu",
                e->name, (unsigned)e->type, (unsigned)e->cls,
                (unsigned long long)expires_s, e->count);
        for (size_t i = 0; i < e->count; i++) {
            char ip[64] = {0};
            if (e->type == DNS_TYPE_A) {
                inet_ntop(AF_INET, e->records[i].u.a.addr, ip, sizeof ip);
            } else {
                inet_ntop(AF_INET6, e->records[i].u.aaaa.addr, ip, sizeof ip);
            }
            fprintf(fp, " %s", ip);
        }
        fputc('\n', fp);
    }
    fclose(fp);
    return 0;
}

int dns_cache_load(dns_cache_t *c, const char *path) {
    if (!c || !path) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;   /* no file = nothing to load, not an error */

    uint64_t now = now_ns();
    char line[4096];
    int loaded = 0;

    while (fgets(line, sizeof line, fp)) {
        /* strip newline */
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        if (n == 0 || line[0] == '#') continue;

        char name[300];
        unsigned type = 0, cls = 0, count = 0;
        unsigned long long expires_s = 0;
        if (sscanf(line, "%255s %u %u %llu %u",
                   name, &type, &cls, &expires_s, &count) != 5) continue;
        if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA) continue;
        if (expires_s * 1000000000ull <= now) continue;   /* expired */
        if (count > 64) count = 64;

        /* split rest of line into IP tokens */
        dns_answer_t ans; memset(&ans, 0, sizeof ans);
        char *p = line;
        for (int skip = 0; skip < 5 && p; skip++) {
            p = strchr(p, ' ');
            if (p) p++;
        }
        if (!p) continue;

        dns_record_t recs[64];
        memset(recs, 0, sizeof recs);
        size_t got = 0;
        char *tok = strtok(p, " \t");
        while (tok && got < count) {
            if (type == DNS_TYPE_A) {
                struct in_addr a4;
                if (inet_pton(AF_INET, tok, &a4) == 1) {
                    recs[got].type = DNS_TYPE_A;
                    memcpy(recs[got].u.a.addr, &a4, 4);
                    got++;
                }
            } else {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, tok, &a6) == 1) {
                    recs[got].type = DNS_TYPE_AAAA;
                    memcpy(recs[got].u.aaaa.addr, &a6, 16);
                }
            }
            tok = strtok(NULL, " \t");
        }
        if (got == 0) continue;

        ans.count = got;
        ans.records = recs;
        /* insert directly; compute ttl as remaining seconds */
        uint32_t remaining = (uint32_t)((expires_s * 1000000000ull - now) / 1000000000ull);
        dns_cache_put(c, name, type, cls, &ans, remaining);
        loaded++;
    }
    fclose(fp);
    return loaded;
}
