/** clienthello.c — build ClientHello for TLS 1.3 and 1.2. */

#include "crisptls_policy.h"
#include "extensions.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================
 * GREASE (RFC 8701)
 * =========================================================
 * 16 reserved values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa.
 * Clients insert one at the start of each list (ciphers,
 * extensions, groups, sigalgs) and as a standalone empty
 * extension — to keep the protocol extensible.
 */

static const uint16_t GREASE_VALUES[16] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
};

/** Pick a random GREASE value for this connection. */
static uint16_t pick_grease(void) {
    uint8_t b = 0;
    extern int ct_random(uint8_t *out, size_t n);
    if (ct_random(&b, 1) != 0) return GREASE_VALUES[0];
    return GREASE_VALUES[b & 0x0f];
}

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2

/** Message builder — reserve-and-backpatch for length fields. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   w;
    int      err;
} wbuf_t;

static void wb_u8(wbuf_t *b, uint8_t v) {
    if (b->err || b->w + 1 > b->cap) { b->err = 1; return; }
    b->buf[b->w++] = v;
}
static void wb_u16(wbuf_t *b, uint16_t v) {
    if (b->err || b->w + 2 > b->cap) { b->err = 1; return; }
    b->buf[b->w++] = (uint8_t)(v >> 8);
    b->buf[b->w++] = (uint8_t)(v & 0xFF);
}
static void __attribute__((unused)) wb_u24(wbuf_t *b, uint32_t v) {
    if (b->err || b->w + 3 > b->cap) { b->err = 1; return; }
    b->buf[b->w++] = (uint8_t)(v >> 16);
    b->buf[b->w++] = (uint8_t)(v >> 8);
    b->buf[b->w++] = (uint8_t)(v & 0xFF);
}
static void wb_bytes(wbuf_t *b, const uint8_t *p, size_t n) {
    if (b->err || b->w + n > b->cap) { b->err = 1; return; }
    memcpy(b->buf + b->w, p, n);
    b->w += n;
}
/** Reserve n bytes; return position for later backpatch. */
static size_t wb_reserve(wbuf_t *b, size_t n) {
    size_t pos = b->w;
    if (b->err || b->w + n > b->cap) { b->err = 1; return 0; }
    b->w += n;
    return pos;
}
static void wb_patch_u16(wbuf_t *b, size_t pos, uint16_t v) {
    if (b->err || pos + 2 > b->cap) return;
    b->buf[pos]     = (uint8_t)(v >> 8);
    b->buf[pos + 1] = (uint8_t)(v & 0xFF);
}
static void wb_patch_u24(wbuf_t *b, size_t pos, uint32_t v) {
    if (b->err || pos + 3 > b->cap) return;
    b->buf[pos]     = (uint8_t)(v >> 16);
    b->buf[pos + 1] = (uint8_t)(v >> 8);
    b->buf[pos + 2] = (uint8_t)(v & 0xFF);
}

/** Write an extension: type(2) length(2) body */
static void ext_begin(wbuf_t *b, uint16_t type, size_t *body_pos) {
    wb_u16(b, type);
    *body_pos = wb_reserve(b, 2);
}
static void ext_end(wbuf_t *b, size_t body_pos) {
    wb_patch_u16(b, body_pos, (uint16_t)(b->w - body_pos - 2));
}

/** Write SNI extension */
static void write_ext_sni(wbuf_t *b, const char *host) {
    size_t bp;
    ext_begin(b, EXT_SERVER_NAME, &bp);
    size_t hlen = strlen(host);
    wb_u16(b, (uint16_t)(hlen + 3));
    wb_u8(b, 0);
    wb_u16(b, (uint16_t)hlen);
    wb_bytes(b, (const uint8_t *)host, hlen);
    ext_end(b, bp);
}

/** Write supported_groups */
static void write_ext_supported_groups(wbuf_t *b, const uint16_t *groups, int grease) {
    size_t bp;
    ext_begin(b, EXT_SUPPORTED_GROUPS, &bp);
    size_t count = 0;
    while (groups && groups[count]) count++;
    uint16_t grease_val = grease ? pick_grease() : 0;
    size_t total = count + (grease ? 1 : 0);
    wb_u16(b, (uint16_t)(total * 2));
    if (grease) wb_u16(b, grease_val);   /* GREASE group at position 0 */
    for (size_t i = 0; i < count; i++) wb_u16(b, groups[i]);
    ext_end(b, bp);
}

/** Write signature_algorithms */
static void write_ext_sigalgs(wbuf_t *b, const uint16_t *sigs) {
    size_t bp;
    ext_begin(b, EXT_SIGNATURE_ALGORITHMS, &bp);
    size_t count = 0;
    while (sigs && sigs[count]) count++;
    wb_u16(b, (uint16_t)(count * 2));
    for (size_t i = 0; i < count; i++) wb_u16(b, sigs[i]);
    ext_end(b, bp);
}

/** Write ALPN */
static void write_ext_alpn(wbuf_t *b, const char *protos) {
    if (!protos) return;
    size_t bp;
    ext_begin(b, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &bp);
    size_t lp = wb_reserve(b, 2);   /* length of protocol list */
    size_t list_start = b->w;
    const char *p = protos;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t l = comma ? (size_t)(comma - p) : strlen(p);
        if (l > 255) l = 255;
        wb_u8(b, (uint8_t)l);
        wb_bytes(b, (const uint8_t *)p, l);
        if (!comma) break;
        p = comma + 1;
    }
    wb_patch_u16(b, lp, (uint16_t)(b->w - list_start));
    ext_end(b, bp);
}

/** Write supported_versions (TLS 1.3 form) */
static void write_ext_supported_versions(wbuf_t *b, uint16_t min, uint16_t max) {
    size_t bp;
    ext_begin(b, EXT_SUPPORTED_VERSIONS, &bp);
    /* client form: 1-byte length then list */
    uint16_t versions[8];
    size_t n = 0;
    for (uint16_t v = max; v >= min && n < 7; v--) {
        versions[n++] = v;
        if (v == 0) break;
    }
    wb_u8(b, (uint8_t)(n * 2));
    for (size_t i = 0; i < n; i++) wb_u16(b, versions[i]);
    ext_end(b, bp);
}

/** Write key_share */
static void write_ext_key_share_x25519(wbuf_t *b, const uint8_t pub[32]) {
    size_t bp;
    ext_begin(b, EXT_KEY_SHARE, &bp);
    size_t list = wb_reserve(b, 2);
    size_t list_start = b->w;
    wb_u16(b, 0x001D);   /* x25519 */
    wb_u16(b, 32);
    wb_bytes(b, pub, 32);
    wb_patch_u16(b, list, (uint16_t)(b->w - list_start));
    ext_end(b, bp);
}

/** extended_master_secret (23) — empty body. */
static void write_ext_ems(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 23, &bp);
    ext_end(b, bp);
}

/** renegotiation_info (65281 = 0xff01) — 1 byte: renegotiated_connection length = 0. */
static void write_ext_reneg_info(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 0xff01, &bp);
    wb_u8(b, 0);
    ext_end(b, bp);
}

/** session_ticket (35) — empty body (signals support, server decides). */
static void write_ext_session_ticket(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 35, &bp);
    ext_end(b, bp);
}

/** status_request (5) — OCSP. Body: type=1(ocsp), responder_id_list len=0, extensions len=0. */
static void write_ext_status_request(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 5, &bp);
    wb_u8(b, 1);           /* status_type = ocsp */
    wb_u16(b, 0);          /* responder_id_list length */
    wb_u16(b, 0);          /* request_extensions length */
    ext_end(b, bp);
}

/** signed_certificate_timestamp (18) — empty body requests SCT. */
static void write_ext_sct(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 18, &bp);
    ext_end(b, bp);
}

/** compress_certificate (27) — advertise brotli (2) and zlib (1). */
static void write_ext_compress_cert(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 27, &bp);
    wb_u8(b, 4);           /* list length: 2 algorithms x 2 bytes */
    wb_u16(b, 2);          /* brotli */
    wb_u16(b, 1);          /* zlib   */
    ext_end(b, bp);
}

/** application_settings (17513 = 0x4469, ALPS) — Chrome-only. Body:
 *   2-byte protocol list length, then ALPN entries. */
static void write_ext_app_settings(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 0x4469, &bp);
    /* Advertise h2 */
    wb_u16(b, 3);          /* list length */
    wb_u8(b, 2);           /* entry length */
    wb_bytes(b, (const uint8_t *)"h2", 2);
    ext_end(b, bp);
}

/** delegated_credentials (34) — Firefox. Empty (signals support). */
static void write_ext_delegated_creds(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 34, &bp);
    ext_end(b, bp);
}

/** record_size_limit (28) — Firefox. 2-byte limit. */
static void write_ext_record_size_limit(wbuf_t *b) {
    size_t bp;
    ext_begin(b, 28, &bp);
    wb_u16(b, 16385);      /* 2^14 + 1 */
    ext_end(b, bp);
}

/** Write a GREASE extension (empty body). */
static void write_ext_grease(wbuf_t *b) {
    size_t bp;
    ext_begin(b, pick_grease(), &bp);
    ext_end(b, bp);
}

/** Write psk_key_exchange_modes (needed for TLS 1.3 even without PSK) */
static void write_ext_psk_modes(wbuf_t *b) {
    size_t bp;
    ext_begin(b, EXT_PSK_KEY_EXCHANGE_MODES, &bp);
    wb_u8(b, 1);      /* length */
    wb_u8(b, 1);      /* psk_dhe_ke */
    ext_end(b, bp);
}

/** Build a full ClientHello message.
 * out: buffer; cap: size; written: bytes written.
 * x25519_pub: client's X25519 public key (32 bytes).
 * Returns 0 on success. */
int clienthello_build(const crisptls_policy_t *p,
                      const char *hostname,
                      const uint8_t random[32],
                      const uint8_t x25519_pub[32],
                      uint8_t *out, size_t cap, size_t *written) {
    if (!p || !hostname || !random || !out) return -1;

    wbuf_t b = { out, cap, 0, 0 };

    /* Handshake header: type(1) length(3) — backpatched */
    wb_u8(&b, HS_CLIENT_HELLO);
    size_t len_pos = wb_reserve(&b, 3);

    /* legacy_version = 0x0303 */
    /* legacy_version: 0x0303 for TLS 1.2+, min_version for older, per RFC 5246 §7.4.1.2 */
    wb_u16(&b, (uint16_t)(p->legacy_version_field ? p->legacy_version_field : 0x0303));

    /* random */
    wb_bytes(&b, random, 32);

    /* session_id: empty in TLS 1.3 */
    wb_u8(&b, 0);

    /* cipher_suites */
    size_t cs_pos = wb_reserve(&b, 2);
    size_t cs_start = b.w;
    /* GREASE cipher at position 0 if enabled */
    if (p->send_grease) wb_u16(&b, pick_grease());
    if (p->cipher_suites_13 && p->max_version >= 0x0304) {
        for (size_t i = 0; p->cipher_suites_13[i]; i++) wb_u16(&b, p->cipher_suites_13[i]);
    }
    if (p->cipher_suites_12) {
        for (size_t i = 0; p->cipher_suites_12[i]; i++) wb_u16(&b, p->cipher_suites_12[i]);
    }
    wb_patch_u16(&b, cs_pos, (uint16_t)(b.w - cs_start));

    /* compression_methods: null only */
    wb_u8(&b, 1);
    wb_u8(&b, 0);

    /* extensions */
    size_t ext_pos = wb_reserve(&b, 2);
    size_t ext_start = b.w;

    /* If the policy provides an explicit extension_order, walk it and
     * dispatch to the matching writer. Otherwise use a hardcoded order
     * that mimics Chrome. */
    /* Dispatch one extension by type ID. */
    #define WRITE_EXT(et) do { \
        switch (et) { \
            case 0:      if (p->send_sni) write_ext_sni(&b, hostname); break; \
            case 5:      write_ext_status_request(&b); break; \
            case 10:     write_ext_supported_groups(&b, p->groups, p->send_grease); break; \
            case 13:     write_ext_sigalgs(&b, p->sigalgs); break; \
            case 16:     write_ext_alpn(&b, p->alpn); break; \
            case 18:     write_ext_sct(&b); break; \
            case 23:     write_ext_ems(&b); break; \
            case 27:     write_ext_compress_cert(&b); break; \
            case 28:     write_ext_record_size_limit(&b); break; \
            case 34:     write_ext_delegated_creds(&b); break; \
            case 35:     write_ext_session_ticket(&b); break; \
            case 43:     write_ext_supported_versions(&b, p->min_version, p->max_version); break; \
            case 45:     if (p->max_version >= 0x0304) write_ext_psk_modes(&b); break; \
            case 51:     if (p->max_version >= 0x0304) write_ext_key_share_x25519(&b, x25519_pub); break; \
            case 0x4469: write_ext_app_settings(&b); break; \
            case 0xff01: write_ext_reneg_info(&b); break; \
            default: break; \
        } \
    } while (0)

    if (p->extension_order) {
        for (size_t ei = 0; p->extension_order[ei]; ei++) {
            WRITE_EXT(p->extension_order[ei]);
        }
    } else {
        /* Default order — safe set only. */
        if (p->send_grease) write_ext_grease(&b);
        if (p->send_sni)    write_ext_sni(&b, hostname);
        write_ext_supported_groups(&b, p->groups, p->send_grease);
        write_ext_sigalgs(&b, p->sigalgs);
        write_ext_alpn(&b, p->alpn);
        write_ext_supported_versions(&b, p->min_version, p->max_version);
        if (p->max_version >= 0x0304) write_ext_key_share_x25519(&b, x25519_pub);
        if (p->max_version >= 0x0304) write_ext_psk_modes(&b);
    }

    #undef WRITE_EXT

    wb_patch_u16(&b, ext_pos, (uint16_t)(b.w - ext_start));

    /* backpatch handshake length */
    wb_patch_u24(&b, len_pos, (uint32_t)(b.w - len_pos - 3));

    if (b.err) return -1;
    if (written) *written = b.w;
    if (getenv("CRISPTLS_DUMP_CH")) {
        fprintf(stderr, "═══ ClientHello (%zu bytes) ═══\n", b.w);
        for (size_t i = 0; i < b.w; i++) {
            fprintf(stderr, "%02x ", out[i]);
            if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
        }
        if (b.w % 16) fprintf(stderr, "\n");
    }
    return 0;
}

/** Serialize a handshake message header (type + 3-byte length). */
size_t hs_write_header(uint8_t type, uint32_t len, uint8_t out[4]) {
    out[0] = type;
    out[1] = (uint8_t)(len >> 16);
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)(len & 0xFF);
    return 4;
}
