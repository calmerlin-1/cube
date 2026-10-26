/** dns_parse.c — walk a DNS response packet into a dns_answer_t. */

#include "dns_wire.h"
#include "dns_arena.h"
#include <string.h>

/** Forward-declared from dns_records.c */
int dns_record_decode_rdata(const uint8_t *pkt, size_t pkt_len,
                            size_t rdata_off, uint16_t rdlen,
                            dns_record_t *rec);

/** Parse a single RR starting at off. Advances *off. Fills rec. */
static int parse_rr(const uint8_t *pkt, size_t pkt_len, size_t *off,
                    dns_record_t *rec, dns_arena_t *ar) {
    if (*off >= pkt_len) return 0;

    char name[DNS_MAX_NAME];
    size_t nl = dns_wire_decode_name(pkt, pkt_len, *off, name, sizeof(name));
    if (nl == 0) return 0;
    *off += nl;
    if (*off + 10 > pkt_len) return 0;

    rec->type = rd16(pkt + *off);
    rec->cls  = rd16(pkt + *off + 2);
    rec->ttl  = rd32(pkt + *off + 4);
    uint16_t rdlen = rd16(pkt + *off + 8);
    *off += 10;
    if (*off + rdlen > pkt_len) return 0;

    memcpy(rec->name, name, strlen(name) + 1);

    /* OPT pseudo-record is handled separately at the caller. Skip RDATA. */
    if (rec->type == DNS_TYPE_OPT) {
        *off += rdlen;
        return 2;   /* signal: this is OPT, not a real record */
    }

    if (!dns_record_decode_rdata(pkt, pkt_len, *off, rdlen, rec))
        return 0;
    *off += rdlen;
    (void)ar;
    return 1;
}

/** Extract EDNS0 fields from the OPT record if present. */
static int parse_opt(const uint8_t *pkt, size_t pkt_len, size_t off,
                     uint16_t rdlen, dns_edns_t *ed) {
    if (off + 10 > pkt_len) return 0;
    /* class field = UDP payload size */
    ed->udp_size = rd16(pkt + off + 2);
    /* TTL field: [ext-rcode:8][version:8][flags:16] */
    uint32_t ttl = rd32(pkt + off + 4);
    ed->ext_rcode = (uint8_t)(ttl >> 24);
    ed->version   = (uint8_t)(ttl >> 16);
    ed->flags     = (uint16_t)ttl;
    /* options */
    size_t opt_off = off + 10;
    size_t opt_end = opt_off + rdlen;
    while (opt_off + 4 <= opt_end && opt_off + 4 <= pkt_len) {
        uint16_t ocode = rd16(pkt + opt_off);
        uint16_t olen  = rd16(pkt + opt_off + 2);
        opt_off += 4;
        if (opt_off + olen > pkt_len || opt_off + olen > opt_end) break;
        if (ocode == DNS_EDNS_COOKIE && olen <= sizeof(ed->cookie)) {
            memcpy(ed->cookie, pkt + opt_off, olen);
            ed->cookie_len = (uint8_t)olen;
        } else if (ocode == DNS_EDNS_NSID && olen <= sizeof(ed->nsid)) {
            memcpy(ed->nsid, pkt + opt_off, olen);
            ed->nsid_len = olen;
        }
        opt_off += olen;
    }
    return 1;
}

int dns_wire_parse_response(const uint8_t *pkt, size_t pkt_len,
                            uint16_t expect_id,
                            const char *expect_name,
                            uint16_t expect_type,
                            dns_answer_t *out) {
    if (pkt_len < 12) return DNS_ERR_WIRE;
    memset(out, 0, sizeof(*out));

    uint16_t id     = rd16(pkt + 0);
    uint16_t flags  = rd16(pkt + 2);
    uint16_t qd     = rd16(pkt + 4);
    uint16_t an     = rd16(pkt + 6);
    uint16_t ns     = rd16(pkt + 8);
    uint16_t ar     = rd16(pkt + 10);

    if (id != expect_id) return DNS_ERR_WIRE;
    if (!(flags & DNS_FLAG_QR)) return DNS_ERR_WIRE;

    out->rcode         = (uint8_t)(flags & 0x0F);
    out->flags         = (uint8_t)((flags >> 4) & 0xFF);
    out->authoritative = (flags & DNS_FLAG_AA) ? 1 : 0;
    out->truncated     = (flags & DNS_FLAG_TC) ? 1 : 0;
    if (out->truncated) return DNS_ERR_TRUNCATED;

    size_t off = 12;

    /* question */
    if (qd >= 1) {
        char qname[DNS_MAX_NAME];
        size_t nl = dns_wire_decode_name(pkt, pkt_len, off, qname, sizeof(qname));
        if (nl == 0) return DNS_ERR_WIRE;
        off += nl;
        if (off + 4 > pkt_len) return DNS_ERR_WIRE;
        uint16_t qt = rd16(pkt + off);
        uint16_t qc = rd16(pkt + off + 2);
        off += 4;
        memcpy(out->qname, qname, strlen(qname) + 1);
        out->qtype  = qt;
        out->qclass = qc;
        if (expect_name && strcmp(qname, expect_name) != 0) return DNS_ERR_WIRE;
        if (expect_type && qt != expect_type) return DNS_ERR_WIRE;
    }

    /* arena for records */
    dns_arena_t *arena = dns_arena_new(an > 0 ? 2048 : 512);
    if (!arena) return DNS_ERR_NOMEM;
    out->arena = arena;

    size_t cap = an > 0 ? an : 1;
    if (cap > DNS_MAX_ANSWERS) cap = DNS_MAX_ANSWERS;
    dns_record_t *recs = (dns_record_t *)dns_arena_alloc(arena, cap * sizeof(dns_record_t));
    if (!recs) { dns_arena_free(arena); out->arena = NULL; return DNS_ERR_NOMEM; }
    out->records = recs;
    out->capacity = cap;
    out->count = 0;

    /* answer section */
    for (uint16_t i = 0; i < an; i++) {
        if (out->count >= DNS_MAX_ANSWERS) break;
        dns_record_t *r = &recs[out->count];
        int pr = parse_rr(pkt, pkt_len, &off, r, arena);
        if (pr == 0) { dns_arena_free(arena); out->arena = NULL; return DNS_ERR_WIRE; }
        if (pr == 2) { dns_arena_free(arena); out->arena = NULL; return DNS_ERR_WIRE; }   /* OPT in answer: malformed */
        if (pr == 1) out->count++;
    }

    /* authority section — keep NS/SOA for negative caching */
    for (uint16_t i = 0; i < ns; i++) {
        if (out->count >= DNS_MAX_ANSWERS) break;
        dns_record_t *r = &recs[out->count];
        int pr = parse_rr(pkt, pkt_len, &off, r, arena);
        if (pr == 0) { dns_arena_free(arena); out->arena = NULL; return DNS_ERR_WIRE; }
        if (pr == 1) out->count++;
    }

    /* additional — extract OPT if present */
    dns_edns_t ed;
    memset(&ed, 0, sizeof(ed));
    for (uint16_t i = 0; i < ar; i++) {
        if (off + 1 > pkt_len) break;
        /* peek whether this is an OPT record by decoding the name and reading type */
        size_t save = off;
        dns_record_t tmp;
        int pr = parse_rr(pkt, pkt_len, &off, &tmp, arena);
        if (pr == 0) break;
        if (pr == 2) {
            /* it was OPT — we already advanced past type/class/ttl/rdlen in parse_rr;
               we need to re-parse to get the OPT fields. Backtrack. */
            size_t back = save;
            size_t nl = dns_wire_skip_name(pkt, pkt_len, back);
            if (nl == 0) break;
            size_t rec_off = back + nl;
            if (rec_off + 10 > pkt_len) break;
            uint16_t rdlen = rd16(pkt + rec_off + 8);
            parse_opt(pkt, pkt_len, rec_off, rdlen, &ed);
        }
    }

    /* combine extended rcode from EDNS0 */
    if (ed.udp_size > 0) {
        uint16_t full_rcode = (uint16_t)((ed.ext_rcode << 4) | (out->rcode & 0x0F));
        out->rcode = (uint8_t)full_rcode;
    }

    if (out->rcode == DNS_RCODE_NXDOMAIN) return DNS_ERR_NXDOMAIN;
    if (out->rcode != DNS_RCODE_NOERROR)   return DNS_ERR_RCODE;

    return DNS_OK;
}
