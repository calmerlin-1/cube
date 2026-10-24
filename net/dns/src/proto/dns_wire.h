/** dns_wire.h — internal wire-format helpers. Not part of public API. */

#ifndef FLYWHEEL_DNS_WIRE_H
#define FLYWHEEL_DNS_WIRE_H

#include "../include/dns.h"
#include "../include/dns_types.h"
#include <stddef.h>
#include <stdint.h>

/** Reading */

/** Read big-endian integers from a byte cursor. */
static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/** Writing */

static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}

/** Name encoding / decoding */

/** Encode a dotted name ("example.com") into DNS wire format.
 * Returns length written, or 0 on error.
 * Enforces label <= 63, total <= 255. */
size_t dns_wire_encode_name(const char *name, size_t namelen,
                            uint8_t *out, size_t outcap);

/** Decode a DNS wire name into dotted form.
 * Handles compression pointers (0xC0..0xFF).
 * Returns bytes consumed at `p`, or 0 on error.
 * On compression-pointer loop or overflow, returns 0.
 * Writes name into `out` (lowercased), NUL-terminated. */
size_t dns_wire_decode_name(const uint8_t *pkt, size_t pkt_len,
                            size_t p_off,
                            char *out, size_t outcap);

/** Skip a name without decoding it. Returns bytes consumed, or 0 on error. */
size_t dns_wire_skip_name(const uint8_t *pkt, size_t pkt_len, size_t p_off);

/** Query builder */

/** Build a DNS query packet. Returns packet length, or 0 on error.
 * type: DNS_TYPE_A, etc.
 * flags_extra: DNS_F_DNSSEC, DNS_F_NO_RECURSE.
 * edns_size: advertised UDP payload size; 0 disables EDNS0.
 * Returns total bytes written. */
size_t dns_wire_build_query(uint16_t id,
                            const char *name, size_t namelen,
                            uint16_t type, uint16_t cls,
                            uint32_t flags_extra,
                            uint16_t edns_size,
                            uint8_t *out, size_t outcap);

/** Response parsing */

/** Parse a full DNS response into dns_answer_t.
 * Allocates records via arena. Caller frees `out->arena`.
 * Returns DNS_OK, or negative error code. */
int dns_wire_parse_response(const uint8_t *pkt, size_t pkt_len,
                            uint16_t expect_id,
                            const char *expect_name,
                            uint16_t expect_type,
                            dns_answer_t *out);

/** Random 16-bit query ID. */
uint16_t dns_random_id(void);

#endif
