/** quic_probe.c — standalone QUIC Initial packet exchange.
 *
 * Sends one QUIC v1 Initial packet carrying a TLS 1.3 ClientHello
 * to a real server. Decrypts the server's Initial response and
 * prints the contained frame types. Proves:
 *   - UDP socket layer works
 *   - crisptls_quic_derive_initial produces correct Initial keys
 *   - crisptls_quic_packet_encrypt / apply_hp produce a valid packet
 *   - crisptls_quic_packet_decrypt / remove_hp correctly decrypt a
 *     real server response
 *
 * Nothing is integrated into cube. Standalone test.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "udp.h"
#include "crisptls_quic.h"
#include "crypto.h"
#include "crisptls_policy.h"
#include "handshake.h"

/* TLS 1.3 cipher suite for Initial (RFC 9001 §5.2) */
#define TLS_AES_128_GCM_SHA256  0x1301

/* Varint encode (RFC 9000 §16) */
static size_t varint(uint8_t *out, uint64_t v) {
    if (v < 64) { out[0] = (uint8_t)v; return 1; }
    if (v < 16384) { out[0] = 0x40 | (uint8_t)(v >> 8); out[1] = (uint8_t)v; return 2; }
    if (v < 1073741824ULL) {
        out[0] = 0x80 | (uint8_t)(v >> 24);
        out[1] = (uint8_t)(v >> 16);
        out[2] = (uint8_t)(v >> 8);
        out[3] = (uint8_t)v;
        return 4;
    }
    out[0] = 0xC0 | (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
    return 8;
}

static int resolve(const char *host, char *ip, int *fam) {
    /* Fast path: literal IPv4 */
    struct in_addr a4;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        snprintf(ip, INET6_ADDRSTRLEN, "%s", host);
        *fam = AF_INET;
        return 0;
    }
    /* Otherwise use getaddrinfo for hostname resolution */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "quic_probe: getaddrinfo(%s) failed\n", host);
        return -1;
    }
    int ok = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        if (r->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)r->ai_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, ip, INET6_ADDRSTRLEN)) {
                *fam = AF_INET;
                ok = 0;
                break;
            }
        }
    }
    freeaddrinfo(res);
    if (ok != 0) fprintf(stderr, "quic_probe: no IPv4 address for %s\n", host);
    return ok;
}
/* Build a TLS 1.3 ClientHello with the mandatory QUIC transport
 * parameters extension (RFC 9001 §8.2). clienthello_build() does not
 * emit this extension, which causes QUIC servers to reject the
 * handshake (stateless reset).
 *
 * Layout (RFC 8446 §4.1.2):
 *   Handshake header: type(1)=0x01, length(3)
 *     legacy_version(2)=0x0303
 *     random(32)
 *     session_id_len(1)=0
 *     cipher_suites_len(2), cipher_suites(2*n)
 *     compression_len(1), compression(1) = 0x00
 *     extensions_len(2), extensions
 */
static int build_quic_clienthello(const char *sni,
                                  const uint8_t random[32],
                                  const uint8_t x25519_pub[32],
                                  const uint8_t scid[8], size_t scid_len,
                                  uint8_t *out, size_t cap, size_t *written) {
    size_t p = 0;
    /* reserve handshake header */
    if (cap < 4 + 256) return -1;
    out[p++] = 0x01;  /* HS_CLIENT_HELLO */
    size_t hs_len_pos = p;
    out[p++] = 0; out[p++] = 0; out[p++] = 0;

    /* legacy_version */
    out[p++] = 0x03; out[p++] = 0x03;
    /* random */
    memcpy(out + p, random, 32); p += 32;
    /* session_id (empty) */
    out[p++] = 0x00;
    /* cipher_suites: [0x1301] */
    out[p++] = 0x00; out[p++] = 0x02;
    out[p++] = 0x13; out[p++] = 0x01;
    /* compression: null */
    out[p++] = 0x01;
    out[p++] = 0x00;

    /* extensions — reserve ext_len */
    size_t ext_len_pos = p;
    out[p++] = 0; out[p++] = 0;

    size_t sni_len = strlen(sni);

    /* ext server_name (0x0000) */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x00;                 /* type */
        out[p++] = 0x00; out[p++] = 0x00;                 /* len placeholder */
        /* server_name_list: len(2) + entry */
        size_t list_len_pos = p; p += 2;
        out[p++] = 0x00;                                   /* hostname type: 0 = SNI */
        out[p++] = (uint8_t)(sni_len >> 8); out[p++] = (uint8_t)sni_len;
        memcpy(out + p, sni, sni_len); p += sni_len;
        size_t list_len = p - list_len_pos - 2;
        out[list_len_pos]     = (uint8_t)(list_len >> 8);
        out[list_len_pos + 1] = (uint8_t)list_len;
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext supported_versions (0x002B) = [0x0304] */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x2B;
        out[p++] = 0x00; out[p++] = 0x00;
        out[p++] = 0x02;                                   /* list_len */
        out[p++] = 0x03; out[p++] = 0x04;                  /* TLS 1.3 */
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext supported_groups (0x000A) = [x25519 (0x001D)] */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x0A;
        out[p++] = 0x00; out[p++] = 0x00;
        out[p++] = 0x00; out[p++] = 0x02;                  /* groups_len */
        out[p++] = 0x00; out[p++] = 0x1D;                  /* x25519 */
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext signature_algorithms (0x000D) = [rsa_pss_rsae_sha256 (0x0804),
     *                                       ecdsa_secp256r1_sha256 (0x0403)] */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x0D;
        out[p++] = 0x00; out[p++] = 0x00;
        out[p++] = 0x00; out[p++] = 0x04;                  /* sigalgs_len */
        out[p++] = 0x08; out[p++] = 0x04;
        out[p++] = 0x04; out[p++] = 0x03;
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext key_share (0x0033) = x25519 with our pubkey */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x33;
        out[p++] = 0x00; out[p++] = 0x00;
        out[p++] = 0x00; out[p++] = 0x24;                  /* shares_len (36) */
        out[p++] = 0x00; out[p++] = 0x1D;                  /* group x25519 */
        out[p++] = 0x00; out[p++] = 0x20;                  /* key_len 32 */
        memcpy(out + p, x25519_pub, 32); p += 32;
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext quic_transport_parameters (0x0039) — MANDATORY for QUIC.
     * RFC 9000 §18.2: minimal client TP is just initial_source_connection_id.
     * Numeric parameters (max_idle_timeout, initial_max_data, etc.) are
     * optional and their values are varint-encoded, not fixed-width. Omit
     * them; the server's defaults are fine. Getting the encoding wrong
     * causes QUIC servers to reject the handshake with a stateless reset. */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x39;                  /* ext type */
        out[p++] = 0x00; out[p++] = 0x00;                  /* ext len placeholder */
        /* 0x0F initial_source_connection_id = SCID (opaque, len varint) */
        out[p++] = 0x0F;
        out[p++] = (uint8_t)scid_len;                      /* 8 -> 1-byte varint */
        memcpy(out + p, scid, scid_len); p += scid_len;
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* ext ALPN (0x0010) = "h3" */
    {
        size_t ext_start = p;
        out[p++] = 0x00; out[p++] = 0x10;
        out[p++] = 0x00; out[p++] = 0x00;
        out[p++] = 0x00; out[p++] = 0x03;                  /* alpn_list_len */
        out[p++] = 0x02;                                   /* proto_len */
        out[p++] = 'h'; out[p++] = '3';
        size_t ext_len = p - ext_start - 4;
        out[ext_start + 2] = (uint8_t)(ext_len >> 8);
        out[ext_start + 3] = (uint8_t)ext_len;
    }

    /* patch extensions_len */
    {
        size_t ext_len = p - ext_len_pos - 2;
        out[ext_len_pos]     = (uint8_t)(ext_len >> 8);
        out[ext_len_pos + 1] = (uint8_t)ext_len;
    }
    /* patch handshake length (body = everything after the 4-byte header) */
    {
        size_t hs_len = p - 4;
        out[hs_len_pos]     = (uint8_t)(hs_len >> 16);
        out[hs_len_pos + 1] = (uint8_t)(hs_len >> 8);
        out[hs_len_pos + 2] = (uint8_t)hs_len;
    }
    *written = p;
    return 0;
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "162.159.137.85";
    uint16_t port = (argc > 2) ? (uint16_t)atoi(argv[2]) : 443;
    const char *sni  = (argc > 3) ? argv[3] : "cloudflare-quic.com";

    printf("[quic_probe] target %s:%u sni=%s\n", host, port, sni);

    char ip[INET6_ADDRSTRLEN] = {0};
    int  fam = 0;
    if (resolve(host, ip, &fam) != 0) return 1;
    printf("[quic_probe] resolved %s\n", ip);

    /* 1. Generate random DCID and SCID (8 bytes each) */
    uint8_t dcid[8], scid[8];
    if (ct_random(dcid, sizeof dcid) != 0) { fprintf(stderr, "random dcid failed\n"); return 2; }
    if (ct_random(scid, sizeof scid) != 0) { fprintf(stderr, "random scid failed\n"); return 2; }
    printf("[quic_probe] dcid=");
    for (size_t i = 0; i < sizeof dcid; i++) printf("%02x", dcid[i]);
    printf(" scid=");
    for (size_t i = 0; i < sizeof scid; i++) printf("%02x", scid[i]);
    printf("\n");

    /* 2. Derive Initial keys from DCID */
    crisptls_quic_keys_t keys;
    if (crisptls_quic_derive_initial(dcid, sizeof dcid, CRISPTLS_QUIC_V1, &keys) != 0) {
        fprintf(stderr, "derive_initial failed\n");
        return 3;
    }
    printf("[quic_probe] Initial keys derived (client key_len=%zu)\n",
           keys.client.key_len);

    /* 3. Build TLS ClientHello */
    uint8_t x25519_priv[32], x25519_pub[32];
    if (ct_x25519_keypair(x25519_priv, x25519_pub) != 0) {
        fprintf(stderr, "x25519 keypair failed\n");
        return 4;
    }

    uint8_t ch[2048];
    size_t ch_len = 0;
    uint8_t random[32];
    if (ct_random(random, sizeof random) != 0) return 4;
    if (build_quic_clienthello(sni, random, x25519_pub, scid, sizeof scid, ch, sizeof ch, &ch_len) != 0) {
        fprintf(stderr, "build_quic_clienthello failed\n");
        return 5;
    }
    printf("[quic_probe] ClientHello built: %zu bytes\n", ch_len);

    /* 4. Wrap ClientHello in a QUIC CRYPTO frame (type 0x06) */
    uint8_t frames[2200];
    size_t frames_len = 0;
    frames[frames_len++] = 0x06;                          /* CRYPTO frame type */
    frames_len += varint(frames + frames_len, 0);         /* offset = 0 */
    frames_len += varint(frames + frames_len, ch_len);    /* length */
    memcpy(frames + frames_len, ch, ch_len);
    frames_len += ch_len;

    /* RFC 9000 §14.1: client Initial datagrams MUST be >= 1200 bytes.
     * Pad plaintext with PADDING frames (0x00) so the encrypted
     * payload reaches the minimum after header + tag. Estimated
     * header+tag = 46 bytes (first + version + dcid_len + dcid +
     * scid_len + scid + token_len + length_varint + PN + AEAD tag). */
    {
        const size_t MIN_PKT = 1200;
        const size_t EST_HDR_TAG = 46;
        size_t target_frames = MIN_PKT - EST_HDR_TAG;
        if (frames_len < target_frames && target_frames <= sizeof frames) {
            size_t pad_n = target_frames - frames_len;
            memset(frames + frames_len, 0x00, pad_n);
            frames_len += pad_n;
            printf("[quic_probe] padded with %zu PADDING frames (total frames=%zu)\n",
                   pad_n, frames_len);
        }
    }
    printf("[quic_probe] CRYPTO frame: %zu bytes\n", frames_len);

    /* 5. Assemble QUIC Initial packet
     *    [first byte] [version 4B] [dcid_len 1B] [dcid] [scid_len 1B] [scid]
     *    [token_len varint] [length varint] [PN 1B] [encrypted payload] [tag 16B]
     *
     * Note: for a first packet (client → server), the PN length is at
     * minimum 4 bytes when we want the sample offset (pn_offset + 4) to
     * have 16 bytes available in the ciphertext. Use PN len = 4. */
    uint8_t pkt[3000];
    size_t p = 0;

    /* First byte: long header (0x80), fixed bit (0x40), type Initial (0x00),
     * reserved (0x00), PN len 4 (0x03). = 0xC3 */
    pkt[p++] = 0xC3;
    /* Version 1 */
    pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x01;
    /* DCID */
    pkt[p++] = sizeof dcid;
    memcpy(pkt + p, dcid, sizeof dcid); p += sizeof dcid;
    /* SCID */
    pkt[p++] = sizeof scid;
    memcpy(pkt + p, scid, sizeof scid); p += sizeof scid;
    /* Token length = 0 */
    pkt[p++] = 0x00;
    /* Length varint: PN(4) + payload_len + tag(16).
     * We'll patch after we know the payload length. Reserve 2-byte varint. */
    size_t len_pos = p;
    pkt[p++] = 0x40; pkt[p++] = 0x00;   /* placeholder for 2-byte varint */
    /* PN = 0 (4 bytes) */
    size_t pn_offset = p;
    pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00;

    /* AAD = bytes from start of packet through PN (RFC 9001 §5.3) */
    size_t aad_len = p;
    uint8_t aad[3000];
    memcpy(aad, pkt, aad_len);

    /* Now fill length varint */
    uint64_t pkt_payload = (uint64_t)frames_len + 16;  /* ciphertext + tag */
    uint64_t total = 4 + pkt_payload;                  /* PN + payload */
    uint8_t vbuf[8];
    size_t vlen = varint(vbuf, total);
    if (vlen != 2) { fprintf(stderr, "unexpected varint len %zu\n", vlen); return 6; }
    memcpy(pkt + len_pos, vbuf, 2);

    /* AAD must be re-copied now that length is final. */
    aad_len = p;
    memcpy(aad, pkt, aad_len);

    /* Encrypt frames → ct + tag */
    uint8_t ct[2200];
    uint8_t tag[16];
    if (crisptls_quic_packet_encrypt(&keys.client, TLS_AES_128_GCM_SHA256,
                                      0, aad, aad_len,
                                      frames, frames_len, ct, tag) != 0) {
        fprintf(stderr, "packet encrypt failed\n");
        return 7;
    }
    memcpy(pkt + p, ct, frames_len); p += frames_len;
    memcpy(pkt + p, tag, 16); p += 16;

    /* Sample offset = pn_offset + 4 (RFC 9001 §5.4.2) */
    size_t sample_off = pn_offset + 4;
    if (sample_off + 16 > p) { fprintf(stderr, "sample out of range\n"); return 8; }

    /* Apply header protection */
    uint8_t *pn_bytes = pkt + pn_offset;
    if (crisptls_quic_apply_hp(keys.client.hp_key, TLS_AES_128_GCM_SHA256,
                                &pkt[0], pn_bytes, 4,
                                pkt + sample_off, 1) != 0) {
        fprintf(stderr, "apply_hp failed\n");
        return 9;
    }

    printf("[quic_probe] packet assembled: %zu bytes (pn_off=%zu, sample_off=%zu)\n",
           p, pn_offset, sample_off);

    /* 6. Send via UDP */
    int fd = udp_socket(fam);
    if (fd < 0) { fprintf(stderr, "udp_socket failed\n"); return 10; }
    if (udp_connect(fd, ip, fam, port, 5000) != 0) {
        fprintf(stderr, "udp_connect failed\n");
        udp_close(fd);
        return 11;
    }
        { FILE *f_ = fopen("/tmp/quic_out.bin","wb"); if (f_) { fwrite(pkt,1,p,f_); fclose(f_); } }
if (udp_send(fd, pkt, p, 5000) != 0) {
        fprintf(stderr, "udp_send failed\n");
        udp_close(fd);
        return 12;
    }
    printf("[quic_probe] sent %zu bytes, waiting for response...\n", p);

    /* 7. Receive response */
    uint8_t rsp[3000];
    ssize_t rn = udp_recv(fd, rsp, sizeof rsp, 5000);
    udp_close(fd);
    if (rn <= 0) { fprintf(stderr, "no response (timeout or error)\n"); return 13; }
    printf("[quic_probe] received %zd bytes\n", rn);
    {
        const char *dump = "../.tmp/qrsp.bin";
        FILE *f_ = fopen(dump, "wb");
        if (f_) { fwrite(rsp, 1, rn, f_); fclose(f_); printf("[quic_probe] dumped rsp to %s\n", dump); }
    }
    printf("[quic_probe] response first 60 bytes: ");
    for (size_t _i = 0; _i < 60 && _i < (size_t)rn; _i++) printf("%02x", rsp[_i]);
    printf("\n");

    /* 8. Parse response header (still has HP applied) */
    if (rn < 30) { fprintf(stderr, "response too short\n"); return 14; }
    uint8_t first = rsp[0];
    printf("[quic_probe] first byte=0x%02x (long=%d type=%d pn_len=%d)\n",
           first, (first & 0x80) != 0, (first & 0x30) >> 4, (first & 0x03) + 1);

    /* For simplicity, assume this is a long-header Initial response.
     * Parse DCID/SCID/token and find PN offset. */
    if (!(first & 0x80)) { fprintf(stderr, "not a long header\n"); return 15; }
    size_t q = 5;  /* first byte + 4-byte version */
    uint8_t rdcil = rsp[q++];
    q += rdcil;
    uint8_t rscil = rsp[q++];
    q += rscil;
    /* token length (varint) */
    uint8_t tb = rsp[q];
    size_t tok_len_bytes = 1;
    uint64_t tok_len = 0;
    if ((tb & 0xC0) == 0x00) { tok_len = tb & 0x3F; tok_len_bytes = 1; }
    else if ((tb & 0xC0) == 0x40) { tok_len = ((tb & 0x3F) << 8) | rsp[q+1]; tok_len_bytes = 2; }
    else { fprintf(stderr, "unsupported token varint\n"); return 16; }
    q += tok_len_bytes;
    q += tok_len;
    /* length (varint) */
    uint8_t lb = rsp[q];
    size_t len_bytes = 1;
    uint64_t payload_len = 0;
    if ((lb & 0xC0) == 0x00) { payload_len = lb & 0x3F; len_bytes = 1; }
    else if ((lb & 0xC0) == 0x40) { payload_len = ((lb & 0x3F) << 8) | rsp[q+1]; len_bytes = 2; }
    else if ((lb & 0xC0) == 0x80) { payload_len = (((uint64_t)(lb & 0x3F)) << 24) | ((uint64_t)rsp[q+1] << 16) | ((uint64_t)rsp[q+2] << 8) | rsp[q+3]; len_bytes = 4; }
    else { fprintf(stderr, "unsupported length varint\n"); return 16; }
    q += len_bytes;

    size_t rpn_offset = q;
    /* RFC 9001 §5.4.2: PN length is masked, so assume max (4 bytes) to
     * locate the sample and unmask. Read the real pn_len from the
     * unmasked first byte afterward. */
    size_t sample_off_rsp = rpn_offset + 4;
    if (sample_off_rsp + 16 > (size_t)rn) {
        fprintf(stderr, "response sample out of range\n");
        return 17;
    }
    printf("[quic_probe] response pn_offset=%zu sample_off=%zu payload_len=%llu\n",
           rpn_offset, sample_off_rsp, (unsigned long long)payload_len);

    /* 9. Remove header protection: unmask all 4 PN bytes regardless of
     * what the masked low bits claim; only the unmasked byte knows. */
    uint8_t rpn_bytes[4] = {0};
    memcpy(rpn_bytes, rsp + rpn_offset, 4);
    if (crisptls_quic_remove_hp(keys.server.hp_key, TLS_AES_128_GCM_SHA256,
                                 &rsp[0], rpn_bytes, 4,
                                 rsp + sample_off_rsp, 1) != 0) {
        fprintf(stderr, "remove_hp failed\n");
        return 18;
    }
    /* Now read real pn_len from unmasked first byte */
    size_t rpn_len = (rsp[0] & 0x03) + 1;
    printf("[quic_probe] real pn_len after HP = %zu\n", rpn_len);
    printf("[quic_probe] rpn_bytes after HP: ");
    for (size_t _di = 0; _di < rpn_len; _di++) printf("%02x ", rpn_bytes[_di]);
    printf("\n");
    printf("[quic_probe] sample (16 bytes at sample_off=%zu): ", sample_off_rsp);
    for (size_t _di = 0; _di < 16; _di++) printf("%02x ", rsp[sample_off_rsp + _di]);
    printf("\n");
    printf("[quic_probe] post-HP header first 40 bytes: ");
    for (size_t _di = 0; _di < 40 && _di < (size_t)rn; _di++) printf("%02x ", rsp[_di]);
    printf("\n");
    printf("[quic_probe] after HP removal: first=0x%02x\n", rsp[0]);

    /* 10. Decrypt payload */
    /* 10. Decrypt payload.
     * ct_len is bounded by the declared packet payload_len (header
     * length varint), which includes PN + ciphertext + tag. Anything
     * after that in the UDP datagram is padding or coalesced packets. */
    size_t ct_start = rpn_offset + rpn_len;
    if (payload_len < rpn_len + 16) {
        fprintf(stderr, "payload too short for tag\n");
        return 19;
    }
    size_t ct_len = (size_t)payload_len - rpn_len - 16;
    uint8_t rt[16];
    memcpy(rt, rsp + ct_start + ct_len, 16);

    /* Rebuild AAD: everything before PN, with the new PN and length. */
    uint8_t raad[3000];
    memcpy(raad, rsp, rpn_offset);
    memcpy(raad + rpn_offset, rpn_bytes, rpn_len);

    /* Extract real packet number from unprotected PN bytes */
    uint64_t rpn = 0;
    for (size_t _i = 0; _i < rpn_len; _i++) rpn = (rpn << 8) | rpn_bytes[_i];
    printf("[quic_probe] extracted PN=%llu\n", (unsigned long long)rpn);

    uint8_t pt[3000];
    if (crisptls_quic_packet_decrypt(&keys.server, TLS_AES_128_GCM_SHA256,
                                      rpn, raad, rpn_offset + rpn_len,
                                      rsp + ct_start, ct_len, rt, pt) != 0) {
        fprintf(stderr, "packet decrypt failed\n");
        return 20;
    }
    printf("[quic_probe] decrypted %zu bytes\n", ct_len);

    /* 11. Parse frames */
    size_t fp = 0;
    while (fp < ct_len) {
        uint8_t ft = pt[fp];
        if (ft == 0x06) {
            /* CRYPTO */
            fp++;
            uint8_t vb = pt[fp];
            uint64_t off = 0; size_t nb = 1;
            if ((vb & 0xC0) == 0x00) { off = vb & 0x3F; }
            else if ((vb & 0xC0) == 0x40) { off = ((vb & 0x3F) << 8) | pt[fp+1]; nb = 2; }
            else { fprintf(stderr, "unsupported crypto offset varint\n"); break; }
            fp += nb;
            vb = pt[fp];
            uint64_t clen = 0; nb = 1;
            if ((vb & 0xC0) == 0x00) { clen = vb & 0x3F; }
            else if ((vb & 0xC0) == 0x40) { clen = ((vb & 0x3F) << 8) | pt[fp+1]; nb = 2; }
            else { fprintf(stderr, "unsupported crypto len varint\n"); break; }
            fp += nb;
            printf("[quic_probe] CRYPTO frame at offset %llu, %llu bytes\n",
                   (unsigned long long)off, (unsigned long long)clen);
            if (clen >= 4) {
                uint8_t hs_type = pt[fp];
                const char *hs_name =
                    hs_type == 2 ? "ServerHello" :
                    hs_type == 8 ? "EncryptedExtensions" :
                    hs_type == 11 ? "Certificate" :
                    hs_type == 15 ? "CertificateVerify" :
                    hs_type == 20 ? "Finished" : "unknown";
                printf("[quic_probe]   handshake type=%u (%s)\n", hs_type, hs_name);
            }
            fp += clen;
        } else if (ft == 0x00) {
            /* PADDING */
            fp++;
        } else if (ft == 0x02 || ft == 0x03) {
            /* ACK — skip */
            printf("[quic_probe] ACK frame (skipped)\n");
            break;
        } else if (ft == 0x1C || ft == 0x1D) {
            printf("[quic_probe] CONNECTION_CLOSE frame\n");
            break;
        } else {
            printf("[quic_probe] unknown frame type 0x%02x at offset %zu\n", ft, fp);
            break;
        }
    }

    printf("[quic_probe] SUCCESS\n");
    return 0;
}
