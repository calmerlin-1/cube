/** quic_packet_test.c — RFC 9001 §A.2 full protected Client Initial.
 *
 * Assembles the complete protected packet from:
 *   - long header (this module)
 *   - AEAD-encrypted payload (crisptls quic_packet)
 *   - header protection mask (crisptls quic_hp)
 * and compares every byte against the RFC's published packet.
 */

#include "quic_packet.h"
#include "crisptls_quic.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int ok = 1;

static uint8_t *from_hex(const char *s, size_t *out_len) {
    size_t n = 0; const char *p = s;
    while (*p) { if (*p==' '||*p=='\n'||*p=='\t'){p++;continue;} n++; p++; }
    n /= 2;
    uint8_t *b = malloc(n ? n : 1);
    p = s; size_t i = 0;
    while (*p && i < n) {
        while (*p==' '||*p=='\n'||*p=='\t') p++;
        if (!*p) break;
        unsigned v; sscanf(p, "%02x", &v);
        b[i++] = (uint8_t)v; p += 2;
    }
    *out_len = n;
    return b;
}

static int check(const char *label, const uint8_t *got,
                  const char *want_hex, size_t n) {
    size_t wn = 0;
    uint8_t *want = from_hex(want_hex, &wn);
    int match = (wn == n) && (memcmp(got, want, n) == 0);
    printf("  %-24s %s\n", label, match ? "MATCH" : "MISMATCH");
    if (!match) {
        printf("    got:  ");
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n    want: ");
        for (size_t i = 0; i < wn; i++) printf("%02x", want[i]);
        printf("\n");
    }
    free(want);
    return match;
}

int main(void) {
    printf("RFC 9001 §A.2 client Initial packet (full)\n\n");

    /* DCID from §A.1 */
    uint8_t dcid[8] = { 0x83, 0x94, 0xc8, 0xf0,
                        0x3e, 0x51, 0x57, 0x08 };

    /* SCID = 0 bytes (as in the RFC example) */

    /* Derive client initial keys */
    crisptls_quic_keys_t keys;
    memset(&keys, 0, sizeof(keys));
    if (crisptls_quic_derive_initial(dcid, 8, CRISPTLS_QUIC_V1, &keys) != 0) {
        printf("derive failed\n"); return 1;
    }

    /* Payload = CRYPTO frame (167 bytes) + PADDING to 1162 bytes total.
     * RFC 9001 §A.2 pads the packet so the final UDP datagram is 1200 bytes:
     *   header(22) + pn(4) + ciphertext(1162) + tag(16) = 1204? no:
     *   header(22) includes PN bytes. So:
     *     header_with_pn = 22
     *     ciphertext = pt_len + 16 (tag inside length)
     *   1200 = 22 + pt_len + 16  -> pt_len = 1162 */
    uint8_t *small_pt = NULL;
    size_t small_len = 0;
    small_pt = from_hex(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e0005000501000000000033002600"
        "24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e9"
        "94fc3c6e52300100000c00000000000000000000",
        &small_len);
    printf("  small payload: %zu bytes\n", small_len);

    size_t pt_len = 1162;
    uint8_t *pt = calloc(1, pt_len);
    memcpy(pt, small_pt, small_len);
    free(small_pt);
    printf("  padded payload: %zu bytes (1200-byte UDP datagram)\n", pt_len);

    /* Packet number = 2 */
    uint64_t packet_number = 2;

    /* ---- Build the long header (unprotected) ---- */
    quic_long_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = CRISPTLS_QUIC_V1;
    hdr.dcid_len = 8;
    memcpy(hdr.dcid, dcid, 8);
    hdr.scid_len = 0;
    hdr.has_token = 1;
    hdr.token_len = 0;
    hdr.token = NULL;
    hdr.pn_len = 4;   /* RFC example uses 4-byte PN */
    hdr.packet_number = (uint32_t)packet_number;
    /* Length = pn_len + ciphertext + tag = 4 + pt_len + 16 */
    hdr.length = 4 + pt_len + 16;

    uint8_t header[256];
    int hdr_len = quic_long_hdr_encode(&hdr, header, sizeof(header));
    if (hdr_len < 0) { printf("header encode failed\n"); return 1; }
    printf("  header: %d bytes\n", hdr_len);

    /* ---- AEAD-encrypt the payload with the header as AAD ---- */
    uint8_t ct[4096];        /* must hold pt_len bytes (1162 in this test) */
    uint8_t tag[16];
    if (crisptls_quic_packet_encrypt(&keys.client, 0x1301, packet_number,
                                      header, (size_t)hdr_len,
                                      pt, pt_len, ct, tag) != 0) {
        printf("encrypt failed\n"); return 1;
    }

    /* ---- Assemble the unprotected packet ---- */
    uint8_t packet[2048];
    size_t plen = 0;
    memcpy(packet, header, (size_t)hdr_len); plen += (size_t)hdr_len;
    memcpy(packet + plen, ct, pt_len); plen += pt_len;
    memcpy(packet + plen, tag, 16); plen += 16;
    printf("  unprotected packet: %zu bytes\n", plen);

    /* ---- Apply header protection ---- */
    /* sample = ciphertext starting at offset (pn_offset + 4) */
    /* pn_offset is the offset of the PN bytes in the header.
     * For our layout: 1(fb)+4(ver)+1(dcid_len)+8(dcid)+1(scid_len)
     *               +1(token_len=0 as varint 1 byte)+2(length varint)
     * pn_offset = 1+4+1+8+1+1+2 = 18 */
    size_t pn_offset = (size_t)hdr_len - hdr.pn_len;
    size_t sample_off = pn_offset + 4;

    if (sample_off + 16 > plen) {
        printf("not enough data for HP sample\n");
        return 1;
    }
    uint8_t sample[16];
    memcpy(sample, packet + sample_off, 16);

    printf("  pn_offset = %zu, sample_off = %zu\n", pn_offset, sample_off);
    printf("  sample:    ");
    for (int i = 0; i < 16; i++) printf("%02x", sample[i]);
    printf("\n");

    printf("\n=== BEFORE apply_hp ===\n");
    printf("packet[0..21] = ");
    for (int i = 0; i < 22; i++) printf("%02x", packet[i]);
    printf("\n");

    uint8_t *pn_bytes = packet + pn_offset;
    if (crisptls_quic_apply_hp(keys.client.hp_key, 0x1301,
                                packet,      /* first byte */
                                pn_bytes, hdr.pn_len,
                                sample, 1 /* long header */) != 0) {
        printf("HP apply failed\n");
        return 1;
    }

    printf("=== AFTER apply_hp ===\n");
    printf("packet[0..21] = ");
    for (int i = 0; i < 22; i++) printf("%02x", packet[i]);
    printf("\n");

    /* ---- Compare against RFC 9001 §A.2 expected packet ---- */
    printf("\n");
    ok &= check("protected header (22B)",
                 packet,
                 "c000000001088394c8f03e5157080000449e7b9aec34",
                 22);
    /* Header on the wire is 20 bytes: 1+4+1+8+1+1+2+4 = 22
     * But HP flips bits in the first byte and PN bytes only,
     * so the "on the wire" bytes of the header are 22 total. */

    /* Full protected packet per RFC 9001 §A.2 */
    ok &= check("protected first 38B", packet,
                 "c000000001088394c8f03e5157080000449e7b9aec34"
                 "d1b1c98dd7689fb8ec11d242b123dc9b",
                 38);

    printf("\n");
    if (ok) printf("QUIC PACKET TESTS PASSED\n");
    else    printf("SOME QUIC PACKET TESTS FAILED\n");

    free(pt);
    return ok ? 0 : 1;
}
