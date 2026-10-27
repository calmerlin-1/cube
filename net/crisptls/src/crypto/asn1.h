/* asn1.h — minimal DER/BER decoder for X.509. */
#ifndef CT_ASN1_H
#define CT_ASN1_H

#include <stddef.h>
#include <stdint.h>

/* Tag classes (bits 7-6 of first tag byte) */
#define ASN1_CLASS_UNIVERSAL     0x00
#define ASN1_CLASS_APPLICATION   0x40
#define ASN1_CLASS_CONTEXT       0x80
#define ASN1_CLASS_PRIVATE       0xC0

/* Universal tags we care about */
#define ASN1_TAG_BOOLEAN         0x01
#define ASN1_TAG_INTEGER         0x02
#define ASN1_TAG_BIT_STRING      0x03
#define ASN1_TAG_OCTET_STRING    0x04
#define ASN1_TAG_NULL            0x05
#define ASN1_TAG_OID             0x06
#define ASN1_TAG_UTF8STRING      0x0C
#define ASN1_TAG_SEQUENCE        0x30
#define ASN1_TAG_SET             0x31
#define ASN1_TAG_PRINTABLE_STR   0x13
#define ASN1_TAG_IA5STRING       0x16
#define ASN1_TAG_UTC_TIME        0x17
#define ASN1_TAG_GEN_TIME        0x18

typedef struct {
    uint8_t        tag;          /* full tag byte (class + constructed + number) */
    size_t         header_len;   /* bytes consumed by tag+length */
    size_t         value_len;    /* length of value */
    const uint8_t *value;        /* pointer to value bytes */
} asn1_tlv;

/* Parse one TLV at `buf[0..len)`. Returns bytes consumed (header+value),
 * or 0 on error. */
size_t asn1_parse(const uint8_t *buf, size_t len, asn1_tlv *out);

/* Iterate: `off` in, next offset out (or 0 at end/error). */
size_t asn1_next(const uint8_t *buf, size_t len, size_t off);

/* Read INTEGER value into uint64_t (truncates if > 8 bytes). Returns 0 on
 * error, else bytes consumed. */
size_t asn1_read_uint64(const uint8_t *buf, size_t len, uint64_t *out);

/* Read OID into dotted-decimal string. Returns 0 on error, else bytes
 * consumed. Writes up to cap-1 chars + NUL. */
size_t asn1_read_oid(const uint8_t *buf, size_t len, char *out, size_t cap);

/* Copy string tag value into buffer (UTF8String/PrintableString/IA5String). */
size_t asn1_read_string(const uint8_t *buf, size_t len, char *out, size_t cap);

/* Compare two DER-encoded Names (RFC 5280 §7.1, normalized). */
int asn1_name_equal(const uint8_t *a, size_t alen,
                    const uint8_t *b, size_t blen);

#endif
