/** dns_types.h — record structures, type codes, class codes, flag bits. */

#ifndef CUBE_DNS_TYPES_H
#define CUBE_DNS_TYPES_H

#include <stddef.h>
#include <stdint.h>

/** Record types (QTYPE / TYPE) */
#define DNS_TYPE_A        1
#define DNS_TYPE_NS       2
#define DNS_TYPE_CNAME    5
#define DNS_TYPE_SOA      6
#define DNS_TYPE_PTR     12
#define DNS_TYPE_HINFO   13
#define DNS_TYPE_MX      15
#define DNS_TYPE_TXT     16
#define DNS_TYPE_AAAA    28
#define DNS_TYPE_SRV     33
#define DNS_TYPE_NAPTR   35
#define DNS_TYPE_DNAME   39
#define DNS_TYPE_DS      43
#define DNS_TYPE_RRSIG   46
#define DNS_TYPE_NSEC    47
#define DNS_TYPE_DNSKEY  48
#define DNS_TYPE_NSEC3   50
#define DNS_TYPE_NSEC3PARAM 51
#define DNS_TYPE_TLSA    52
#define DNS_TYPE_SSHFP   44
#define DNS_TYPE_CAA    257
#define DNS_TYPE_SVCB    64
#define DNS_TYPE_HTTPS   65
#define DNS_TYPE_OPT     41   /* pseudo-record for EDNS0 */
#define DNS_TYPE_ANY    255
#define DNS_TYPE_AXFR   252   /* zone transfer — should be refused */

/** Class codes (QCLASS / CLASS) */
#define DNS_CLASS_IN      1
#define DNS_CLASS_CH      3
#define DNS_CLASS_HS      4
#define DNS_CLASS_NONE  254
#define DNS_CLASS_ANY   255

/** Header flag bits (16-bit field) */
#define DNS_FLAG_QR   (1u << 15)   /* 0 = query, 1 = response */
#define DNS_FLAG_AA   (1u << 10)   /* authoritative answer */
#define DNS_FLAG_TC   (1u <<  9)   /* truncated */
#define DNS_FLAG_RD   (1u <<  8)   /* recursion desired */
#define DNS_FLAG_RA   (1u <<  7)   /* recursion available */
#define DNS_FLAG_AD   (1u <<  5)   /* authenticated data (DNSSEC) */
#define DNS_FLAG_CD   (1u <<  4)   /* checking disabled */

/** RCODE (low 4 bits of header flags, or extended via EDNS0) */
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5
#define DNS_RCODE_YXDOMAIN  6
#define DNS_RCODE_YXRRSET   7
#define DNS_RCODE_NXRRSET   8
#define DNS_RCODE_NOTAUTH   9
#define DNS_RCODE_NOTZONE  10
#define DNS_RCODE_BADVERS  16   /* via EDNS0 extended rcode */
#define DNS_RCODE_BADSIG   16   /* same value, TSIG context */
#define DNS_RCODE_BADKEY   17
#define DNS_RCODE_BADTIME  18
#define DNS_RCODE_BADMODE  19
#define DNS_RCODE_BADNAME  20
#define DNS_RCODE_BADALG   21
#define DNS_RCODE_BADTRUNC 22
#define DNS_RCODE_BADCOOKIE 23

/** Opcode */
#define DNS_OPCODE_QUERY   0
#define DNS_OPCODE_IQUERY  1
#define DNS_OPCODE_STATUS  2
#define DNS_OPCODE_NOTIFY  4
#define DNS_OPCODE_UPDATE  5

/** EDNS0 option codes */
#define DNS_EDNS_LLQ          1
#define DNS_EDNS_NSID         3
#define DNS_EDNS_DAU          5
#define DNS_EDNS_DHU          6
#define DNS_EDNS_N3U          7
#define DNS_EDNS_CLIENT_SUBNET 8
#define DNS_EDNS_EXPIRE       9
#define DNS_EDNS_COOKIE      10
#define DNS_EDNS_TCP_KEEPALIVE 11
#define DNS_EDNS_PADDING     12
#define DNS_EDNS_CHAIN       13
#define DNS_EDNS_KEY_TAG     14
#define DNS_EDNS_EDE         15   /* Extended DNS Errors */
#define DNS_EDNS_CLIENT_TAG  16
#define DNS_EDNS_SERVER_TAG  17

/** Size limits */
#define DNS_MAX_NAME       255   /* presentation name in bytes */
#define DNS_MAX_LABEL       63
#define DNS_MAX_UDP        512   /* classic UDP without EDNS0 */
#define DNS_MAX_UDP_EDNS  4096   /* typical EDNS0 advertised size */
#define DNS_MAX_TCP      65535   /* wire-level max */
#define DNS_MAX_RDATA      512   /* per-record cap we keep */
#define DNS_MAX_ANSWERS    128   /* per-response cap we keep */
#define DNS_MAX_SIG        512   /* RRSIG signature blob */

/** One DNS record, tagged by type */
typedef struct {
    char      name[DNS_MAX_NAME];   /* owner name, lowercase */
    uint16_t  type;
    uint16_t  cls;
    uint32_t  ttl;
    union {
        struct { uint8_t addr[4]; }              a;
        struct { uint8_t addr[16]; }             aaaa;
        struct { char target[DNS_MAX_NAME]; }    cname;
        struct { char target[DNS_MAX_NAME];
                 uint16_t preference; }          mx;
        struct { char target[DNS_MAX_NAME]; }    ns;
        struct { char mname[DNS_MAX_NAME];
                 char rname[DNS_MAX_NAME];
                 uint32_t serial, refresh, retry, expire, minimum; } soa;
        struct { char target[DNS_MAX_NAME]; }    ptr;
        struct { uint16_t priority, weight, port;
                 char target[DNS_MAX_NAME]; }    srv;
        struct { char text[DNS_MAX_RDATA];
                 uint16_t len; }                 txt;
        struct { uint8_t flags;
                 uint8_t taglen;
                 char    tag[32];
                 uint8_t valuelen;
                 uint8_t value[DNS_MAX_RDATA]; } caa;
        struct { uint16_t keytag;
                 uint8_t  algorithm;
                 uint8_t  digesttype;
                 uint8_t  digest[128];
                 uint16_t digestlen; }           ds;
        struct { uint16_t flags;
                 uint8_t  protocol;
                 uint8_t  algorithm;
                 uint8_t  key[DNS_MAX_RDATA];
                 uint16_t keylen; }              dnskey;
        struct { uint16_t typecovered;
                 uint8_t  algorithm;
                 uint8_t  labels;
                 uint32_t origttl;
                 uint32_t sigexp;
                 uint32_t siginc;
                 uint16_t keytag;
                 char     signer[DNS_MAX_NAME];
                 uint8_t  sig[DNS_MAX_SIG];
                 uint16_t siglen; }              rrsig;
        struct { uint16_t priority;
                 char     target[DNS_MAX_NAME];
                 /* SVCB/HTTPS params kept as raw */
                 uint8_t  params[DNS_MAX_RDATA];
                 uint16_t paramslen; }           svcb;
        /* Fallback: unrecognized type */
        struct { uint8_t data[DNS_MAX_RDATA];
                 uint16_t len; }                 raw;
    } u;
} dns_record_t;

/** DNS message header (12 bytes on the wire) */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/** EDNS0 OPT record info (extracted, not stored as a record) */
typedef struct {
    uint16_t udp_size;
    uint8_t  ext_rcode;
    uint8_t  version;
    uint16_t flags;      /* DO bit is 0x8000 */
    /* options */
    uint8_t  cookie[24];
    uint8_t  cookie_len;
    uint16_t nsid_len;
    char     nsid[64];
} dns_edns_t;

/** A full answer set */
typedef struct {
    dns_record_t *records;
    size_t        count;
    size_t        capacity;
    uint8_t       rcode;         /* combined rcode (header + ext) */
    uint8_t       flags;         /* AA, TC, RA, AD, CD masked */
    uint8_t       authoritative;
    uint8_t       truncated;
    uint16_t      qtype;         /* type that was asked */
    uint16_t      qclass;
    char          qname[DNS_MAX_NAME];
    uint64_t      elapsed_ns;    /* how long this took */
    void         *arena;         /* arena backing the records; free once */
} dns_answer_t;

#endif
