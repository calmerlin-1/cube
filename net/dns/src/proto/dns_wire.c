/** dns_wire.c — wire format: name codec, query builder, id generator. */

#include "dns_wire.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/** Random */

static uint64_t g_rng = 0;
static int g_rng_init = 0;

/** xorshift64* seeded from time+pid. */
static void rng_seed(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t s = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 32);
    s ^= ((uint64_t)getpid() << 16);
    if (s == 0) s = 0x9E3779B97F4A7C15ull;
    g_rng = s;
    g_rng_init = 1;
}

static uint64_t rng_next(void) {
    if (!g_rng_init) rng_seed();
    uint64_t x = g_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    g_rng = x;
    return x * 0x2545F4914F6CDD1Dull;
}

uint16_t dns_random_id(void) {
    return (uint16_t)(rng_next() >> 48);
}

/** Name encoding */

size_t dns_wire_encode_name(const char *name, size_t namelen,
                            uint8_t *out, size_t outcap) {
    if (namelen == 0) {
        if (outcap < 1) return 0;
        out[0] = 0;
        return 1;
    }
    size_t w = 0;
    size_t i = 0;
    while (i < namelen) {
        /* find next '.' */
        size_t j = i;
        while (j < namelen && name[j] != '.') j++;
        size_t llen = j - i;
        if (llen == 0) {
            /* empty label (consecutive dots or trailing dot at start) — skip */
            i = j + 1;
            if (j >= namelen) break;
            continue;
        }
        if (llen > DNS_MAX_LABEL) return 0;
        if (w + 1 + llen > outcap) return 0;
        out[w++] = (uint8_t)llen;
        memcpy(out + w, name + i, llen);
        w += llen;
        if (j >= namelen) break;
        i = j + 1;
    }
    /* root terminator */
    if (w + 1 > outcap) return 0;
    out[w++] = 0;
    if (w > DNS_MAX_NAME) return 0;
    return w;
}

/** Name decoding with compression pointers */

size_t dns_wire_decode_name(const uint8_t *pkt, size_t pkt_len,
                            size_t p_off,
                            char *out, size_t outcap) {
    size_t w = 0;
    size_t off = p_off;
    size_t consumed = 0;      /* bytes used at start */
    int followed = 0;
    int jumps = 0;

    for (;;) {
        if (off >= pkt_len) return 0;
        uint8_t len = pkt[off];

        if ((len & 0xC0) == 0xC0) {
            /* compression pointer */
            if (off + 1 >= pkt_len) return 0;
            uint16_t ptr = (uint16_t)(((len & 0x3F) << 8) | pkt[off + 1]);
            if (!followed) { consumed = off + 2 - p_off; followed = 1; }
            if (ptr >= off) return 0;   /* must point backward */
            off = ptr;
            if (++jumps > 64) return 0; /* loop protection */
            continue;
        }

        if (len == 0) {
            if (!followed) consumed = off + 1 - p_off;
            break;
        }

        if ((len & 0xC0) != 0) return 0;   /* reserved bits */
        if (off + 1 + len > pkt_len) return 0;

        if (w + len + 2 > outcap) return 0;   /* label + dot + NUL */
        if (w > 0) out[w++] = '.';
        for (size_t k = 0; k < len; k++) {
            uint8_t c = pkt[off + 1 + k];
            out[w++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
        }
        off += 1 + len;
        if (!followed) consumed = off - p_off;
    }
    if (w >= outcap) return 0;
    out[w] = '\0';
    return consumed;
}

size_t dns_wire_skip_name(const uint8_t *pkt, size_t pkt_len, size_t p_off) {
    size_t off = p_off;
    for (;;) {
        if (off >= pkt_len) return 0;
        uint8_t len = pkt[off];
        if ((len & 0xC0) == 0xC0) {
            return off + 2 - p_off;
        }
        if (len == 0) return off + 1 - p_off;
        if ((len & 0xC0) != 0) return 0;
        off += 1 + len;
    }
}

/** Query builder */

size_t dns_wire_build_query(uint16_t id,
                            const char *name, size_t namelen,
                            uint16_t type, uint16_t cls,
                            uint32_t flags_extra,
                            uint16_t edns_size,
                            uint8_t *out, size_t outcap) {
    if (outcap < 12) return 0;

    /* header */
    wr16(out + 0, id);
    uint16_t flags = 0;
    if (!(flags_extra & DNS_F_NO_RECURSE)) flags |= DNS_FLAG_RD;
    wr16(out + 2, flags);
    wr16(out + 4, 1);                 /* qdcount */
    wr16(out + 6, 0);                 /* ancount */
    wr16(out + 8, 0);                 /* nscount */
    wr16(out + 10, edns_size ? 1 : 0); /* arcount (1 if EDNS0 OPT) */

    /* question */
    size_t w = 12;
    size_t nlen = dns_wire_encode_name(name, namelen, out + w, outcap - w);
    if (nlen == 0) return 0;
    w += nlen;
    if (w + 4 > outcap) return 0;
    wr16(out + w, type); w += 2;
    wr16(out + w, cls);  w += 2;

    /* EDNS0 OPT pseudo-record in additional */
    if (edns_size) {
        if (w + 11 > outcap) return 0;
        out[w++] = 0;                     /* root name */
        wr16(out + w, DNS_TYPE_OPT); w += 2;
        wr16(out + w, edns_size);   w += 2;   /* class field = UDP size */
        uint32_t ttl = 0;
        if (flags_extra & DNS_F_DNSSEC) ttl |= 0x8000;   /* DO bit */
        wr32(out + w, ttl); w += 4;
        wr16(out + w, 0); w += 2;         /* rdlength = 0, no options */
    }

    return w;
}
