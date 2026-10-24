/** dns_records.c — decode RDATA into dns_record_t for each supported type. */

#include "dns_wire.h"
#include <string.h>

/** Decode one record's RDATA at pkt+rdata_off, length rdlen.
 * Fills rec->u based on rec->type.
 * Returns 1 on success, 0 on malformed. */
int dns_record_decode_rdata(const uint8_t *pkt, size_t pkt_len,
                            size_t rdata_off, uint16_t rdlen,
                            dns_record_t *rec) {
    if (rdata_off + rdlen > pkt_len) return 0;
    const uint8_t *r = pkt + rdata_off;

    switch (rec->type) {
        case DNS_TYPE_A:
            if (rdlen != 4) return 0;
            memcpy(rec->u.a.addr, r, 4);
            return 1;

        case DNS_TYPE_AAAA:
            if (rdlen != 16) return 0;
            memcpy(rec->u.aaaa.addr, r, 16);
            return 1;

        case DNS_TYPE_CNAME: {
            char tmp[DNS_MAX_NAME];
            size_t n = dns_wire_decode_name(pkt, pkt_len, rdata_off, tmp, sizeof(tmp));
            if (n == 0) return 0;
            memcpy(rec->u.cname.target, tmp, strlen(tmp) + 1);
            return 1;
        }

        case DNS_TYPE_NS: {
            char tmp[DNS_MAX_NAME];
            size_t n = dns_wire_decode_name(pkt, pkt_len, rdata_off, tmp, sizeof(tmp));
            if (n == 0) return 0;
            memcpy(rec->u.ns.target, tmp, strlen(tmp) + 1);
            return 1;
        }

        case DNS_TYPE_PTR: {
            char tmp[DNS_MAX_NAME];
            size_t n = dns_wire_decode_name(pkt, pkt_len, rdata_off, tmp, sizeof(tmp));
            if (n == 0) return 0;
            memcpy(rec->u.ptr.target, tmp, strlen(tmp) + 1);
            return 1;
        }

        case DNS_TYPE_MX: {
            if (rdlen < 3) return 0;
            rec->u.mx.preference = rd16(r);
            char tmp[DNS_MAX_NAME];
            size_t n = dns_wire_decode_name(pkt, pkt_len, rdata_off + 2, tmp, sizeof(tmp));
            if (n == 0) return 0;
            memcpy(rec->u.mx.target, tmp, strlen(tmp) + 1);
            return 1;
        }

        case DNS_TYPE_SOA: {
            char mname[DNS_MAX_NAME], rname[DNS_MAX_NAME];
            size_t n1 = dns_wire_decode_name(pkt, pkt_len, rdata_off, mname, sizeof(mname));
            if (n1 == 0) return 0;
            size_t off2 = rdata_off + n1;
            if (off2 >= pkt_len) return 0;
            size_t n2 = dns_wire_decode_name(pkt, pkt_len, off2, rname, sizeof(rname));
            if (n2 == 0) return 0;
            size_t off3 = off2 + n2;
            if (off3 + 20 > pkt_len) return 0;
            memcpy(rec->u.soa.mname, mname, strlen(mname) + 1);
            memcpy(rec->u.soa.rname, rname, strlen(rname) + 1);
            rec->u.soa.serial  = rd32(pkt + off3 +  0);
            rec->u.soa.refresh = rd32(pkt + off3 +  4);
            rec->u.soa.retry   = rd32(pkt + off3 +  8);
            rec->u.soa.expire  = rd32(pkt + off3 + 12);
            rec->u.soa.minimum = rd32(pkt + off3 + 16);
            return 1;
        }

        case DNS_TYPE_SRV: {
            if (rdlen < 6) return 0;
            rec->u.srv.priority = rd16(r);
            rec->u.srv.weight   = rd16(r + 2);
            rec->u.srv.port     = rd16(r + 4);
            char tmp[DNS_MAX_NAME];
            size_t n = dns_wire_decode_name(pkt, pkt_len, rdata_off + 6, tmp, sizeof(tmp));
            if (n == 0) return 0;
            memcpy(rec->u.srv.target, tmp, strlen(tmp) + 1);
            return 1;
        }

        case DNS_TYPE_TXT: {
            /* concatenate all character-strings, bounded by DNS_MAX_RDATA */
            size_t w = 0;
            size_t i = 0;
            while (i < rdlen && w < DNS_MAX_RDATA - 1) {
                uint8_t l = r[i];
                if (i + 1 + l > rdlen) return 0;
                size_t copy = l;
                if (w + copy > DNS_MAX_RDATA - 1) copy = DNS_MAX_RDATA - 1 - w;
                memcpy(rec->u.txt.text + w, r + i + 1, copy);
                w += copy;
                i += 1 + l;
            }
            rec->u.txt.text[w] = '\0';
            rec->u.txt.len = (uint16_t)w;
            return 1;
        }

        case DNS_TYPE_CAA: {
            if (rdlen < 2) return 0;
            rec->u.caa.flags = r[0];
            rec->u.caa.taglen = r[1];
            if ((size_t)2 + rec->u.caa.taglen > rdlen) return 0;
            if (rec->u.caa.taglen > 31) rec->u.caa.taglen = 31;
            memcpy(rec->u.caa.tag, r + 2, rec->u.caa.taglen);
            rec->u.caa.tag[rec->u.caa.taglen] = '\0';
            size_t vlen = rdlen - 2 - r[1];
            if (vlen > DNS_MAX_RDATA) vlen = DNS_MAX_RDATA;
            memcpy(rec->u.caa.value, r + 2 + r[1], vlen);
            rec->u.caa.valuelen = (uint8_t)vlen;
            return 1;
        }

        case DNS_TYPE_DS:
            if (rdlen < 4) return 0;
            rec->u.ds.keytag = rd16(r);
            rec->u.ds.algorithm = r[2];
            rec->u.ds.digesttype = r[3];
            {
                size_t dl = rdlen - 4;
                if (dl > sizeof(rec->u.ds.digest)) dl = sizeof(rec->u.ds.digest);
                memcpy(rec->u.ds.digest, r + 4, dl);
                rec->u.ds.digestlen = (uint16_t)dl;
            }
            return 1;

        case DNS_TYPE_DNSKEY:
            if (rdlen < 4) return 0;
            rec->u.dnskey.flags = rd16(r);
            rec->u.dnskey.protocol = r[2];
            rec->u.dnskey.algorithm = r[3];
            {
                size_t kl = rdlen - 4;
                if (kl > sizeof(rec->u.dnskey.key)) kl = sizeof(rec->u.dnskey.key);
                memcpy(rec->u.dnskey.key, r + 4, kl);
                rec->u.dnskey.keylen = (uint16_t)kl;
            }
            return 1;

        case DNS_TYPE_RRSIG: {
            if (rdlen < 18) return 0;
            rec->u.rrsig.typecovered = rd16(r);
            rec->u.rrsig.algorithm = r[2];
            rec->u.rrsig.labels = r[3];
            rec->u.rrsig.origttl = rd32(r + 4);
            rec->u.rrsig.sigexp = rd32(r + 8);
            rec->u.rrsig.siginc = rd32(r + 12);
            rec->u.rrsig.keytag = rd16(r + 16);
            char signer[DNS_MAX_NAME];
            size_t sn = dns_wire_decode_name(pkt, pkt_len, rdata_off + 18,
                                             signer, sizeof(signer));
            if (sn == 0) return 0;
            memcpy(rec->u.rrsig.signer, signer, strlen(signer) + 1);
            size_t soff = rdata_off + 18 + sn;
            size_t slen = (soff < rdata_off + rdlen) ? (rdata_off + rdlen - soff) : 0;
            if (slen > sizeof(rec->u.rrsig.sig)) slen = sizeof(rec->u.rrsig.sig);
            if (slen > 0) memcpy(rec->u.rrsig.sig, pkt + soff, slen);
            rec->u.rrsig.siglen = (uint16_t)slen;
            return 1;
        }

        case DNS_TYPE_SVCB:
        case DNS_TYPE_HTTPS:
            if (rdlen < 3) return 0;
            rec->u.svcb.priority = rd16(r);
            {
                char target[DNS_MAX_NAME];
                size_t tn = dns_wire_decode_name(pkt, pkt_len, rdata_off + 2,
                                                 target, sizeof(target));
                if (tn == 0) return 0;
                memcpy(rec->u.svcb.target, target, strlen(target) + 1);
                size_t poff = rdata_off + 2 + tn;
                size_t plen = (poff < rdata_off + rdlen) ? (rdata_off + rdlen - poff) : 0;
                if (plen > sizeof(rec->u.svcb.params)) plen = sizeof(rec->u.svcb.params);
                if (plen > 0) memcpy(rec->u.svcb.params, pkt + poff, plen);
                rec->u.svcb.paramslen = (uint16_t)plen;
            }
            return 1;

        default:
            /* unknown type — store raw */
            {
                size_t l = rdlen;
                if (l > sizeof(rec->u.raw.data)) l = sizeof(rec->u.raw.data);
                memcpy(rec->u.raw.data, r, l);
                rec->u.raw.len = (uint16_t)l;
            }
            return 1;
    }
}
