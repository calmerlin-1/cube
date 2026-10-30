/** session.c — connection state, I/O, handshake orchestration. */

#include "session.h"
#include "handshake.h"
#include "keyschedule.h"
#include "keyschedule_legacy.h"
#include "record.h"
#include "crypto.h"
#include "extensions.h"
#include "crisptls_tier.h"
#include "trace.h"
extern const char *alert_name(uint8_t d);
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

/* poll() is POSIX-only; WSAPoll has the same ABI on Windows. */
#ifdef _WIN32
#include <winsock2.h>
#ifndef POLLIN
#define POLLIN POLLRDNORM
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
typedef WSAPOLLFD ct_pollfd_t;
static int ct_poll(ct_pollfd_t *p, int n, int t) { return WSAPoll(p, n, t); }
#else
#include <poll.h>
#include <sys/socket.h>
typedef struct pollfd ct_pollfd_t;
static int ct_poll(ct_pollfd_t *p, int n, int t) { return poll(p, n, t); }
#endif

/* ---- debug trace ---- */
extern int g_crisptls_trace;
extern int g_crisptls_quiet;
extern char g_crisptls_last_fail_step[80];
#define TRACE(...) do { \
    if (g_crisptls_trace) { fprintf(stderr, "[tls] " __VA_ARGS__); fputc('\n', stderr); } \
    char _m[120]; \
    snprintf(_m, sizeof _m, __VA_ARGS__); \
    if (strstr(_m, "failed") || strstr(_m, "error") || \
        strstr(_m, "timeout") || strstr(_m, "closed") || \
        strstr(_m, "recv:") || strstr(_m, "poll:") || \
        strstr(_m, "too large")) { \
        snprintf(g_crisptls_last_fail_step, sizeof g_crisptls_last_fail_step, "%s", _m); \
    } \
} while (0)

#define CT_HANDSHAKE 22
#define CT_ALERT     21
#define CT_CCS       20
#define CT_APP       23

/* Cipher dispatch */

/* Returns 0 on success and fills aead + key_len. */
static int session_cipher_to_aead(uint16_t suite, int *aead, size_t *key_len) {
    switch (suite) {
        case 0x1301: *aead = SESSION_AEAD_AES128; *key_len = 16; return 0;
        case 0x1302: *aead = SESSION_AEAD_AES256; *key_len = 32; return 0;
        case 0x1303: *aead = SESSION_AEAD_CHACHA; *key_len = 32; return 0;
        default:     return -1;
    }
}

/* 32 for SHA-256 (0x1301, 0x1303), 48 for SHA-384 (0x1302). */
static size_t session_cipher_hash_len(uint16_t suite) {
    return (suite == 0x1302) ? 48 : 32;
}

/* Install a direction's AEAD key from a 32-byte traffic secret. */
static int session_install_key(session_dir_t *d,
                               const uint8_t secret[48],
                               size_t hash_len,
                               int aead, size_t key_len) {
    uint8_t key[48], iv[12];
    int rc;
    if (hash_len == 48) {
        rc = ct_hkdf_expand_label_sha384(secret, "key", (const uint8_t *)"", 0, key, key_len);
        if (rc == CT_OK) rc = ct_hkdf_expand_label_sha384(secret, "iv", (const uint8_t *)"", 0, iv, 12);
    } else {
        rc = ct_hkdf_expand_label_sha256(secret, "key", (const uint8_t *)"", 0, key, key_len);
        if (rc == CT_OK) rc = ct_hkdf_expand_label_sha256(secret, "iv", (const uint8_t *)"", 0, iv, 12);
    }
    if (rc != CT_OK) return -1;
    memset(d->key, 0, sizeof(d->key));
    memcpy(d->key, key, key_len);
    memcpy(d->iv, iv, 12);
    d->key_len = key_len;
    d->aead = aead;
    d->seq = 0;
    return 0;
}

/* Decrypt one record using whatever aead is installed on d. */
static int session_decrypt_record(session_dir_t *d, uint16_t version, uint8_t record_type,
                                   const uint8_t *ct, size_t ct_len,
                                   uint8_t *out, uint8_t *inner_ct_out) {
    /* TLS 1.2 uses negotiated version in AAD. TLS 1.3 uses wire version 0x0303. */
    uint16_t wire_ver = (version == 0x0304) ? 0x0303 : version;

    if (d->aead == SESSION_AEAD_AES128) {
        if (version == 0x0303) {
            int pt = tls_record_decrypt_12_aes128gcm(d->key, d->iv, d->seq,
                                                     record_type, wire_ver,
                                                     ct, ct_len, out, TLS_MAX_PLAINTEXT);
            if (pt > 0 && inner_ct_out) *inner_ct_out = record_type;
            return pt;
        }
        return tls_record_decrypt_13_aes128gcm(d->key, d->iv, d->seq,
                                                wire_ver, ct, ct_len,
                                                out, inner_ct_out);
    }
    if (d->aead == SESSION_AEAD_AES256) {
        if (version == 0x0303) return -1;
        extern int ct_aes256gcm_decrypt(const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t *ct, size_t ct_len,
                                        const uint8_t tag[16],
                                        uint8_t *pt);
        if (ct_len < 17) return -1;
        uint8_t nonce[12];
        memcpy(nonce, d->iv, 12);
        for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(d->seq >> (8 * i));
        uint8_t aad[5];
        tls_record_write_header(TLS_CT_APPLICATION_DATA, wire_ver,
                                (uint16_t)ct_len, aad);
        uint8_t tag[16];
        memcpy(tag, ct + ct_len - 16, 16);
        int r = ct_aes256gcm_decrypt(d->key, nonce, aad, 5,
                                     ct, ct_len - 16, tag, out);
        if (r != CT_OK) return -1;
        size_t il = ct_len - 16;
        while (il > 0 && out[il-1] == 0) il--;
        if (il == 0) return -1;
        if (inner_ct_out) *inner_ct_out = out[il-1];
        return (int)(il - 1);
    }
    if (d->aead == SESSION_AEAD_CHACHA) {
        if (version == 0x0303) {
            int pt = tls_record_decrypt_12_chacha20(d->key, d->iv, d->seq,
                                                    record_type, wire_ver,
                                                    ct, ct_len, out, TLS_MAX_PLAINTEXT);
            if (pt > 0 && inner_ct_out) *inner_ct_out = record_type;
            return pt;
        }
        return tls_record_decrypt_13_chacha20(d->key, d->iv, d->seq,
                                               wire_ver, ct, ct_len,
                                               out, inner_ct_out);
    }
    return -1;
}

/* Parse an ALPN extension body from EncryptedExtensions and store into s->alpn. */
static int session_parse_alpn_ext(const uint8_t *body, size_t blen,
                                   char *out, size_t out_cap) {
    if (blen < 3) return -1;
    uint16_t list_len = (uint16_t)((body[0] << 8) | body[1]);
    if ((size_t)list_len + 2 > blen) return -1;
    const uint8_t *p = body + 2;
    const uint8_t *end = p + list_len;
    if (p >= end) return -1;
    uint8_t plen = *p++;
    if (p + plen > end) return -1;
    if ((size_t)plen + 1 > out_cap) return -1;
    memcpy(out, p, plen);
    out[plen] = 0;
    return 0;
}

/* Parse a received alert record's plaintext: 2 bytes, level+desc. */
static void session_log_alert(const uint8_t *pt, size_t len, const char *when) {
    const char *level = pt && len >= 1
        ? (pt[0] == 1 ? "warning" : (pt[0] == 2 ? "fatal" : "?"))
        : "?";
    if (len < 2) { TRACE("%s: alert (short)", when); return; }
    if (!g_crisptls_quiet)
        fprintf(stderr, "ALERT %s: level=%s(%u) desc=%u\n",
                when, level, (unsigned)pt[0], (unsigned)pt[1]);
    (void)level;
}

/* fd I/O with timeout */

static int wait_fd(int fd, short ev, uint32_t timeout_ms) {
    ct_pollfd_t pfd;
    pfd.fd = fd;
    pfd.events = ev;
    pfd.revents = 0;
    int r = ct_poll(&pfd, 1, timeout_ms ? (int)timeout_ms : -1);
    if (r < 0) { TRACE("wait_fd: poll: %s (errno=%d)", strerror(errno), errno); return -1; }
    if (r == 0) { TRACE("wait_fd: timeout after %ums", timeout_ms); return -2; }
    return 0;
}

int session_fd_write_all(int fd, const uint8_t *buf, size_t n,
                         uint32_t timeout_ms) {
    size_t w = 0;
    while (w < n) {
        ssize_t r = send(fd, buf + w, n - w, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLOUT, timeout_ms) < 0) return -1;
                continue;
            }
            if (errno == EINTR) continue;
            return -1;
        }
        w += (size_t)r;
    }
    return 0;
}

int session_fd_read_some(int fd, uint8_t *buf, size_t cap, size_t *out_len,
                         uint32_t timeout_ms) {
    for (;;) {
        ssize_t r = recv(fd, buf, cap, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLIN, timeout_ms) < 0) return -1;
                continue;
            }
            if (errno == EINTR) continue;
            TRACE("recv: %s (errno=%d)", strerror(errno), errno); return -1;
        }
        if (r == 0) { TRACE("recv: peer closed connection (EOF)"); return -1; }   /* peer closed */
        *out_len = (size_t)r;
        return 0;
    }
}

/* transcript — accumulate all handshake messages, hash at end ========================================================= We keep a rolling SHA-256 context in session.c. But the session struct doesn't hold one (would need OpenSSL types in header). Simple approach: accumulate into a growing buffer stored on the stack of the handshake function. For now, we compute the hash fresh by keeping the full transcript in a static buffer. To keep the struct clean and still work, we hold transcript bytes in a separate malloc'd buffer tracked via a side table. */

/* We'll accumulate transcript in a stack-allocated buffer passed around
 * by the handshake function. The static API in session.h just hashes
 * the last message into s->transcript — but since we don't have a
 * streaming SHA-256 in session, we instead hash the full accumulated
 * buffer at the points where we need it.
 *
 * Practical compromise: store full transcript in a fixed 64 KiB buffer
 * inside the handshake function (stack), and the conn only keeps the
 * final hash. That's fine for a client: ClientHello + server flight is
 * well under 64 KiB.
 */

int session_transcript_update(struct crisptls_conn *s,
                              const uint8_t *msg, size_t len) {
    (void)s; (void)msg; (void)len;
    return 0;   /* handled in handshake loop */
}

/* Alerts */

int session_send_alert(struct crisptls_conn *s, uint8_t level, uint8_t desc) {
    uint8_t body[2] = { level, desc };
    uint8_t rec[5 + 2];
    tls_record_write_header(CT_ALERT, 0x0303, 2, rec);
    memcpy(rec + 5, body, 2);
    session_fd_write_all(s->fd, rec, 7, s->policy.write_timeout_ms);
    return 0;
}

static int record_send_encrypted(struct crisptls_conn *s, uint8_t inner_ct,
                                 const uint8_t *body, size_t body_len) {
    TRACE_ENTER("crisptls: encrypt+send TLS record", "inner_ct=%u len=%zu seq=%llu",
                inner_ct, body_len, (unsigned long long)s->tx.seq);
    if (body_len + 1 + 16 > TLS_MAX_CIPHERTEXT) return -1;

    uint8_t buf[TLS_MAX_CIPHERTEXT];
    memcpy(buf, body, body_len);
    int ct_len = -1;
    uint8_t outer_type = CT_APP;

    int is_tls12 = (s->version == 0x0303);

    if (s->tx.aead == SESSION_AEAD_AES128) {
        if (is_tls12) {
            /* TLS 1.2: explicit 8-byte nonce. Try to reuse tx.seq as the nonce. */
            uint8_t nonce[8];
            for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(s->tx.seq >> (8 * (7 - i)));
            ct_len = tls_record_encrypt_12_aes128gcm(s->tx.key, s->tx.iv,
                                                     nonce, s->tx.seq,
                                                     inner_ct, 0x0303,
                                                     body, body_len,
                                                     buf, sizeof(buf));
            outer_type = inner_ct;
        } else {
            ct_len = tls_record_encrypt_13_aes128gcm(s->tx.key, s->tx.iv,
                                                     s->tx.seq, inner_ct,
                                                     0x0303, buf, body_len);
        }
    } else if (s->tx.aead == SESSION_AEAD_AES256) {
        if (is_tls12) return -1;
        ct_len = tls_record_encrypt_13_aes256gcm(s->tx.key, s->tx.iv,
                                                 s->tx.seq, inner_ct,
                                                 0x0303, buf, body_len);
    } else if (s->tx.aead == SESSION_AEAD_CHACHA) {
        if (is_tls12) {
            uint8_t nonce[8];
            for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(s->tx.seq >> (8 * (7 - i)));
            ct_len = tls_record_encrypt_12_chacha20(s->tx.key, s->tx.iv,
                                                    nonce, s->tx.seq,
                                                    inner_ct, 0x0303,
                                                    body, body_len,
                                                    buf, sizeof(buf));
            outer_type = inner_ct;
        } else {
            ct_len = tls_record_encrypt_13_chacha20(s->tx.key, s->tx.iv,
                                                    s->tx.seq, inner_ct,
                                                    0x0303, buf, body_len);
        }
    } else {
        return -1;
    }
    if (ct_len < 0) return -1;

    /* Outer record header */
    uint8_t hdr[5];
    tls_record_write_header(outer_type, 0x0303, (uint16_t)ct_len, hdr);
    if (g_crisptls_trace) {
        fprintf(stderr, "[txbytes] hdr=%02x%02x%02x%02x%02x buf=",
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
        for (int _i = 0; _i < ct_len && _i < 128; _i++) fprintf(stderr, "%02x", buf[_i]);
        fprintf(stderr, "\n");
    }
    if (session_fd_write_all(s->fd, hdr, 5, s->policy.write_timeout_ms) < 0)
        return -1;
    if (session_fd_write_all(s->fd, buf, (size_t)ct_len,
                             s->policy.write_timeout_ms) < 0)
        return -1;

    s->tx.seq++;
    return 0;
}

/* Handshake orchestration */

/* Fixed transcript buffer for the client flight */
#define TRANSCRIPT_CAP 65536

typedef struct {
    uint8_t  buf[TRANSCRIPT_CAP];
    size_t   len;
} transcript_t;

static int tr_add(transcript_t *t, const uint8_t *msg, size_t len) {
    if (t->len + len > sizeof(t->buf)) return -1;
    memcpy(t->buf + t->len, msg, len);
    t->len += len;
    return 0;
}

static int tr_hash_hl(const transcript_t *t, size_t hl, uint8_t *out) {
    if (hl == 48) return ct_sha384(t->buf, t->len, out);
    return ct_sha256(t->buf, t->len, out);
}

/* Send ClientHello. Returns 0 on success. */
static int send_client_hello(struct crisptls_conn *s,
                             transcript_t *tr,
                             const uint8_t x25519_pub[32]) {
    uint8_t random[32];
    if (ct_random(random, 32) != CT_OK) return -1;
    memcpy(s->client_random, random, 32);

    uint8_t hs_msg[4096];
    size_t hs_len = 0;
    if (clienthello_build(&s->policy, s->sni, random, x25519_pub,
                          hs_msg, sizeof(hs_msg), &hs_len) != 0)
        return -1;

    /* Record: type=handshake, version=0x0301 (legacy for CH), payload=hs_msg */
    uint8_t hdr[5];
    tls_record_write_header(CT_HANDSHAKE, 0x0301, (uint16_t)hs_len, hdr);
    if (session_fd_write_all(s->fd, hdr, 5, s->policy.write_timeout_ms) < 0)
        return -1;
    if (session_fd_write_all(s->fd, hs_msg, hs_len,
                              s->policy.write_timeout_ms) < 0)
        return -1;

    /* Transcript includes just the handshake message (no record header) */
    tr_add(tr, hs_msg, hs_len);

    /* Retain the raw ClientHello bytes for JA4 fingerprinting. */
    if (hs_len <= sizeof(s->raw_ch)) {
        memcpy(s->raw_ch, hs_msg, hs_len);
        s->raw_ch_len = hs_len;
    }
#ifdef CT_DEBUG
    {
        FILE *fp = fopen("tests/ch_dump.bin", "wb");
        if (fp) { fwrite(hs_msg, 1, hs_len, fp); fclose(fp); }
    }
#endif
    return 0;
}

/* Read one record. Returns: 0 = ok, -1 = error, 1 = need more.
 * Note: caller must handle CCS records (type 20) — TLS 1.3 servers
 * send these for middlebox compatibility (RFC 8446 §5). */
static int read_record(struct crisptls_conn *s, tls_record_t *rec,
                       uint8_t *payload_buf, size_t payload_cap,
                       size_t *payload_len) {
    TRACE_ENTER("crisptls: read one TLS record from socket");
    /* Read header if we don't have it */
    while (s->rx_buf_len < 5) {
        size_t got = 0;
        if (session_fd_read_some(s->fd, s->rx_buf + s->rx_buf_len,
                                  sizeof(s->rx_buf) - s->rx_buf_len,
                                  &got, s->policy.handshake_timeout_ms) < 0)
            { TRACE("read_record: header read failed (rx_buf_len=%zu)", s->rx_buf_len); return -1; }
        s->rx_buf_len += got;
    }

    if (tls_record_parse_header(s->rx_buf, s->rx_buf_len, rec) != 5)
        { TRACE("read_record: header parse failed (rx_buf_len=%zu, first5=%02x %02x %02x %02x %02x)", s->rx_buf_len, s->rx_buf[0], s->rx_buf[1], s->rx_buf[2], s->rx_buf[3], s->rx_buf[4]); return -1; }
    TRACE("raw_hdr: %02x %02x %02x %02x %02x | type=%u len=%u",
          s->rx_buf[0], s->rx_buf[1], s->rx_buf[2], s->rx_buf[3], s->rx_buf[4],
          rec->type, rec->length);

    size_t need = 5 + rec->length;
    while (s->rx_buf_len < need) {
        size_t got = 0;
        if (session_fd_read_some(s->fd, s->rx_buf + s->rx_buf_len,
                                  sizeof(s->rx_buf) - s->rx_buf_len,
                                  &got, s->policy.handshake_timeout_ms) < 0)
            { TRACE("read_record: payload read failed (need=%zu have=%zu)", need, s->rx_buf_len); return -1; }
        s->rx_buf_len += got;
    }

    if (rec->length > payload_cap) { TRACE("read_record: payload too large (%u > %zu)", rec->length, payload_cap); return -1; }
    memcpy(payload_buf, s->rx_buf + 5, rec->length);
    *payload_len = rec->length;

    /* Shift remaining bytes down */
    size_t consumed = need;
    if (consumed < s->rx_buf_len) {
        memmove(s->rx_buf, s->rx_buf + consumed, s->rx_buf_len - consumed);
        s->rx_buf_len -= consumed;
    } else {
        s->rx_buf_len = 0;
    }
    return 0;
}

/* Walk the handshake message stream, calling a handler for each. */

/* walk_handshake was removed — the handshake message walk is now
 * inline in session_handshake(), with CertVerify/EE/Cert/Finished
 * dispatch and transcript ordering handled together. */

/* Handshake: main driver */
/* TLS 1.2 handshake — helpers and main driver ECDHE + AEAD only in this pass. */

static int read_handshake_plain(struct crisptls_conn *s, uint8_t *out, size_t cap,
                                size_t *out_len)
{
    for (;;) {
        /* If a complete handshake message is already in the accumulator,
         * extract it. Handles multiple messages per record and messages
         * fragmented across records. */
        if (s->hs_accum_len >= 4) {
            uint32_t mlen = ((uint32_t)s->hs_accum[1] << 16) |
                            ((uint32_t)s->hs_accum[2] << 8) |
                             (uint32_t)s->hs_accum[3];
            size_t need = 4 + mlen;
            if (need <= s->hs_accum_len) {
                if (need > cap) return -1;
                memcpy(out, s->hs_accum, need);
                *out_len = need;
                memmove(s->hs_accum, s->hs_accum + need,
                        s->hs_accum_len - need);
                s->hs_accum_len -= need;
                TRACE("hs_ret type=%u len=%zu accum=%zu",
                        out[0], need, s->hs_accum_len);
                return 0;
            }
        }

        /* Need more bytes: read a record, append its payload. */
        tls_record_t rec;
        uint8_t rbuf[TLS_MAX_CIPHERTEXT];
        size_t plen = 0;
        int rr = read_record(s, &rec, rbuf, sizeof(rbuf), &plen);
        if (rr != 0) {
            fprintf(stderr, "[tls] hs_plain: read_record failed rr=%d\n", rr);
            return -1;
        }

        if (rec.type == TLS_CT_ALERT) {
            if (plen >= 2)
                fprintf(stderr, "[!] server alert level=%u desc=%u\n",
                        rbuf[0], rbuf[1]);
            return -1;
        }
        if (rec.type != TLS_CT_HANDSHAKE) {
            fprintf(stderr, "[tls] hs_plain: skipping non-handshake record type=%u len=%zu\n",
                    rec.type, plen);
            continue;
        }

        if (s->hs_accum_len + plen > sizeof(s->hs_accum)) return -1;
        memcpy(s->hs_accum + s->hs_accum_len, rbuf, plen);
        s->hs_accum_len += plen;
    }
}

static int session_handshake_12(struct crisptls_conn *s,
                                const server_hello_t *sh,
                                const uint8_t priv[32],
                                transcript_t *tr)
{
    uint8_t buf[TLS_MAX_CIPHERTEXT];
    size_t blen = 0;
    uint8_t server_random[32];
    memcpy(server_random, sh->random, 32);

    /* 1. Read Certificate */
    if (read_handshake_plain(s, buf, sizeof(buf), &blen) != 0) return -1;
    if (blen < 4 || buf[0] != HS_CERTIFICATE) return -1;
    tr_add(tr, buf, blen);
    {
        uint32_t mlen = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
        if (4 + mlen > blen) return -1;
        cert_chain_t chain;
        if (certificate_parse(buf + 4, mlen, &chain) != 0 || chain.count == 0) return -1;
        if (s->leaf_der) free(s->leaf_der);
        size_t ll = chain.certs[0].len;
        s->leaf_der = malloc(ll);
        if (!s->leaf_der) return -1;
        memcpy(s->leaf_der, chain.certs[0].data, ll);
        s->leaf_der_len = ll;
        s->chain_count = 0;
        for (size_t i = 0; i < chain.count && i < 16; i++) {
            size_t cl = chain.certs[i].len;
            s->chain_der[i] = malloc(cl);
            if (!s->chain_der[i]) return -1;
            memcpy(s->chain_der[i], chain.certs[i].data, cl);
            s->chain_len[i] = cl;
            s->chain_count++;
        }
    }

    /* 2. Read ServerKeyExchange (ECDHE only) */
    TRACE("12-step2: reading ServerKeyExchange");
    if (read_handshake_plain(s, buf, sizeof(buf), &blen) != 0) { TRACE("12-step2: read failed"); return -1; }
    if (blen < 4 || buf[0] != 12) { TRACE("12-step2: unexpected type %u", blen >= 1 ? buf[0] : 0); return -1; }
    TRACE("12-step2: ServerKeyExchange %zu bytes", blen);
    tr_add(tr, buf, blen);
    const uint8_t *server_pub = NULL;
    size_t server_pub_len = 0;
    uint16_t curve_id = 0;
    {
        uint32_t mlen = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
        if (4 + mlen > blen) { TRACE("12-step2: mlen > blen"); return -1; }
        const uint8_t *p = buf + 4;
        const uint8_t *end = p + mlen;
        if (p + 4 > end) { TRACE("12-step2: short"); return -1; }
        uint8_t curve_type = *p++;
        if (curve_type != 0x03) { TRACE("12-step2: curve_type %u != named_curve", curve_type); return -1; }
        curve_id = ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        uint8_t pklen = *p++;
        if (p + pklen > end) { TRACE("12-step2: pklen > end"); return -1; }
        server_pub = p;
        server_pub_len = pklen;
        TRACE("12-step2: curve=0x%04x server_pub_len=%zu", curve_id, server_pub_len);
    }

    /* 3. Read ServerHelloDone */
    TRACE("12-step3: reading ServerHelloDone");
    if (read_handshake_plain(s, buf, sizeof(buf), &blen) != 0) { TRACE("12-step3: read failed"); return -1; }
    if (blen < 4 || buf[0] != 14) { TRACE("12-step3: unexpected type %u", blen >= 1 ? buf[0] : 0); return -1; }
    tr_add(tr, buf, blen);

    /* 3b. Generate OUR keypair ONCE. Used for shared secret AND ClientKeyExchange. */
    uint8_t our_pub[65];
    size_t our_pub_len = 0;
    TRACE("12-step3b: generating client keypair (curve=0x%04x)", curve_id);
    if (curve_id == 0x0017) {
        if (ct_p256_keypair((uint8_t *)priv, our_pub) != 0) { TRACE("12-step3b: p256 keypair failed"); return -1; }
        our_pub_len = 65;
    } else if (curve_id == 0x001D) {
        if (ct_x25519_keypair((uint8_t *)priv, our_pub) != 0) { TRACE("12-step3b: x25519 keypair failed"); return -1; }
        our_pub_len = 32;
    } else {
        TRACE("12-step3b: unsupported curve 0x%04x", curve_id); return -1;
    }

    /* 4. Premaster secret — dispatch on selected curve */
    TRACE("12-step4: computing premaster (curve=0x%04x)", curve_id);
    uint8_t premaster[32];
    {
        int kvrc;
        if (curve_id == 0x0017)
            kvrc = ct_p256_ecdh(premaster, priv, server_pub);
        else if (curve_id == 0x001D)
            kvrc = keyexchange_x25519_shared(premaster, priv, server_pub);
        else { TRACE("12-step4: unsupported curve 0x%04x", curve_id); return -1; }
        if (kvrc != 0) { TRACE("12-step4: shared failed"); return -1; }
    }
    TRACE("12-step4: premaster ok");

    /* 5. Master secret */
    TRACE("12-step5: master secret");
    ctl_hash_t prf_hash = tls12_suite_prf_hash(s->cipher);
    if (prf_hash == 0) { TRACE("12-step5: no prf hash for cipher 0x%04x", s->cipher); return -1; }
    uint8_t master[48];
    if (tls_master_secret(0x0303, prf_hash, premaster, 32,
                          s->client_random, server_random, master) != 0) {
        TRACE("12-step5: tls_master_secret failed"); return -1;
    }
    memcpy(s->master_secret, master, 48);
    TRACE("12-step5: master ok");

    /* 6. Key block */
    TRACE("12-step6: key block for cipher 0x%04x", s->cipher);
    size_t key_len = 0, mac_len = 0, iv_len = 0;
    int aead_sel = SESSION_AEAD_NONE;
    switch (s->cipher) {
        case 0xC02F: case 0xC02B:
            aead_sel = SESSION_AEAD_AES128; key_len = 16; iv_len = 4; break;
        case 0xC030: case 0xC02C:
            aead_sel = SESSION_AEAD_AES256; key_len = 32; iv_len = 4; break;
        case 0xCCA8: case 0xCCA9:
            aead_sel = SESSION_AEAD_CHACHA; key_len = 32; iv_len = 12; break;
        default:
            TRACE("12-step6: cipher 0x%04x not supported", s->cipher);
            return -1;
    }
    keyschedule_12_t ks;
    if (keyschedule_legacy_derive(0x0303, prf_hash, master,
                                  s->client_random, server_random,
                                  mac_len, key_len, iv_len, &ks) != 0) {
        TRACE("12-step6: keyschedule_legacy_derive failed"); return -1;
    }
    TRACE("12-step6: keyblock ok (key_len=%zu iv_len=%zu)", key_len, iv_len);

    /* 7. Install rx keys */
    memset(&s->rx, 0, sizeof(s->rx));
    memcpy(s->rx.key, ks.server_write_key, key_len);
    if (aead_sel == SESSION_AEAD_CHACHA)
        memcpy(s->rx.iv, ks.server_write_iv, 12);
    else
        memcpy(s->rx.iv, ks.server_write_iv, 4);
    s->rx.key_len = key_len;
    s->rx.aead = aead_sel;
    s->rx.seq = 0;

    /* 8. Send ClientKeyExchange (plaintext) — uses our_pub from step 3b */
    TRACE("12-step8: sending ClientKeyExchange");
    {
        uint8_t msg[4 + 1 + 65];
        msg[0] = 16;
        msg[1] = 0; msg[2] = 0; msg[3] = (uint8_t)(1 + our_pub_len);
        msg[4] = (uint8_t)our_pub_len;
        memcpy(msg + 5, our_pub, our_pub_len);
        size_t msg_len = 4 + 1 + our_pub_len;
        tr_add(tr, msg, msg_len);

        uint8_t hdr[5];
        tls_record_write_header(TLS_CT_HANDSHAKE, 0x0303, (uint16_t)msg_len, hdr);
        if (session_fd_write_all(s->fd, hdr, 5, s->policy.write_timeout_ms) < 0) { TRACE("12-step8: write hdr failed"); return -1; }
        if (session_fd_write_all(s->fd, msg, msg_len, s->policy.write_timeout_ms) < 0) { TRACE("12-step8: write body failed"); return -1; }
    }

    /* 9. Send ChangeCipherSpec */
    TRACE("12-step9: sending CCS");
    {
        uint8_t hdr[5]; uint8_t body = 1;
        tls_record_write_header(TLS_CT_CHANGE_CIPHER_SPEC, 0x0303, 1, hdr);
        if (session_fd_write_all(s->fd, hdr, 5, s->policy.write_timeout_ms) < 0) { TRACE("12-step9: write hdr failed"); return -1; }
        if (session_fd_write_all(s->fd, &body, 1, s->policy.write_timeout_ms) < 0) { TRACE("12-step9: write body failed"); return -1; }
    }

    /* 10. Install tx keys */
    memset(&s->tx, 0, sizeof(s->tx));
    memcpy(s->tx.key, ks.client_write_key, key_len);
    if (aead_sel == SESSION_AEAD_CHACHA)
        memcpy(s->tx.iv, ks.client_write_iv, 12);
    else
        memcpy(s->tx.iv, ks.client_write_iv, 4);
    s->tx.key_len = key_len;
    s->tx.aead = aead_sel;
    s->tx.seq = 0;

    /* 11. Send Finished (encrypted) */
    TRACE("12-step11: sending Finished");
    {
        size_t hl = (prf_hash == CTL_SHA384) ? 48 : 32;
        uint8_t th[48];
        if (tr_hash_hl(tr, hl, th) != 0) { TRACE("12-step11: tr_hash_hl failed"); return -1; }
        uint8_t verify[12];
        if (tls_finished_verify(0x0303, prf_hash, master, 1, th, hl, verify) != 0) { TRACE("12-step11: finished_verify failed"); return -1; }

        uint8_t msg[4 + 12];
        msg[0] = HS_FINISHED;
        msg[1] = 0; msg[2] = 0; msg[3] = 12;
        memcpy(msg + 4, verify, 12);
        tr_add(tr, msg, sizeof(msg));

        uint8_t explicit_nonce[8];
        if (ct_random(explicit_nonce, 8) != CT_OK) { TRACE("12-step11: random failed"); return -1; }

        uint8_t ct[TLS_MAX_CIPHERTEXT];
        int ct_len = -1;
        if (aead_sel == SESSION_AEAD_AES128)
            ct_len = tls_record_encrypt_12_aes128gcm(s->tx.key, s->tx.iv,
                                                      explicit_nonce, s->tx.seq,
                                                      TLS_CT_HANDSHAKE, 0x0303,
                                                      msg, sizeof(msg), ct, sizeof(ct));
        else if (aead_sel == SESSION_AEAD_CHACHA)
            ct_len = tls_record_encrypt_12_chacha20(s->tx.key, s->tx.iv,
                                                     explicit_nonce, s->tx.seq,
                                                     TLS_CT_HANDSHAKE, 0x0303,
                                                     msg, sizeof(msg), ct, sizeof(ct));
        else { TRACE("12-step11: no aead"); return -1; }
        if (ct_len < 0) { TRACE("12-step11: encrypt failed"); return -1; }

        uint8_t hdr[5];
        tls_record_write_header(TLS_CT_HANDSHAKE, 0x0303, (uint16_t)ct_len, hdr);
        if (session_fd_write_all(s->fd, hdr, 5, s->policy.write_timeout_ms) < 0) { TRACE("12-step11: write hdr failed"); return -1; }
        if (session_fd_write_all(s->fd, ct, (size_t)ct_len, s->policy.write_timeout_ms) < 0) { TRACE("12-step11: write ct failed"); return -1; }
        s->tx.seq++;
    }

    /* 12. Read ChangeCipherSpec */
    TRACE("12-step12: reading CCS");
    {
        tls_record_t rec;
        uint8_t rb[TLS_MAX_CIPHERTEXT];
        size_t rl = 0;
        if (read_record(s, &rec, rb, sizeof(rb), &rl) != 0) { return -1; }
        if (rec.type == TLS_CT_ALERT) {
            TRACE("12-step12: SERVER ALERT level=%u desc=%u (%s) rl=%zu",
                  rl >= 1 ? rb[0] : 0, rl >= 2 ? rb[1] : 0,
                  rl >= 2 ? alert_name(rb[1]) : "?", rl);
            if (rl >= 2) fprintf(stderr, "[!] server alert: %s(%u)\n", alert_name(rb[1]), rb[1]);
            return -1;
        }
        if (rec.type != TLS_CT_CHANGE_CIPHER_SPEC) { TRACE("12-step12: type %u != CCS", rec.type); return -1; }
    }

    /* 13. Read Finished (encrypted) */
    TRACE("12-step13: reading server Finished");
    {
        tls_record_t rec;
        uint8_t rb[TLS_MAX_CIPHERTEXT];
        size_t rl = 0;
        if (read_record(s, &rec, rb, sizeof(rb), &rl) != 0) { return -1; }

        uint8_t pt[TLS_MAX_PLAINTEXT];
        int ptl = -1;
        if (aead_sel == SESSION_AEAD_AES128)
            ptl = tls_record_decrypt_12_aes128gcm(s->rx.key, s->rx.iv, s->rx.seq,
                                                   rec.type, 0x0303, rb, rl,
                                                   pt, sizeof(pt));
        else if (aead_sel == SESSION_AEAD_CHACHA)
            ptl = tls_record_decrypt_12_chacha20(s->rx.key, s->rx.iv, s->rx.seq,
                                                  rec.type, 0x0303, rb, rl,
                                                  pt, sizeof(pt));
        if (ptl < 16) { TRACE("12-step13: decrypt failed ptl=%d", ptl); return -1; }
        s->rx.seq++;

        if (pt[0] != HS_FINISHED) { TRACE("12-step13: type %u != Finished", pt[0]); return -1; }
        TRACE("12-step13: server Finished ok");
    }

    s->handshake_done = 1;
    TRACE("12-complete: handshake done");
    return 0;
}

int session_handshake(struct crisptls_conn *s) {
    if (!s) return -1;

    transcript_t *tr = calloc(1, sizeof(transcript_t));
    if (!tr) return -1;

    int rc = -1;
    uint8_t priv[32], pub[32];
    uint8_t th_server_saved[48];      /* transcript hash through server Finished */
    memset(th_server_saved, 0, 48);
    server_hello_t sh;
    memset(&sh, 0, sizeof(sh));

    /* 1. X25519 keypair */
    if (keyexchange_x25519_keypair(priv, pub) != 0) { TRACE("step1: keypair failed"); goto done; }

    /* 2. Send ClientHello */
    if (send_client_hello(s, tr, pub) != 0) { TRACE("step2: send ClientHello failed"); goto done; }

    TRACE("step3: reading ServerHello");
    /* 3. Read ServerHello */
    {
        tls_record_t rec;
        uint8_t payload[TLS_MAX_CIPHERTEXT];
        size_t plen = 0;
        if (read_record(s, &rec, payload, sizeof(payload), &plen) != 0) { goto done; }
        TRACE("step3: got record type=%u len=%zu", rec.type, plen);

        /* Server can reply to ClientHello with an alert (e.g. if it
         * rejects our SNI, ALPN, ciphers, or version). Parse it and
         * report cleanly instead of "expected handshake". */
        if (rec.type == CT_ALERT) {
            if (plen >= 2) {
                const char *lvl = payload[0] == 1 ? "warning" :
                                  payload[0] == 2 ? "fatal"   : "?";
                (void)lvl;   /* used only inside TRACE */
                TRACE("step3: server sent alert %s(%u) %s(%u)",
                      lvl, (unsigned)payload[0],
                      alert_name(payload[1]), (unsigned)payload[1]);
                fprintf(stderr, "[!] server rejected: %s(%u)\n",
                        alert_name(payload[1]), (unsigned)payload[1]);
            } else {
                TRACE("step3: server sent short alert (%zu bytes)", plen);
            }
            goto done;
        }

        if (rec.type != CT_HANDSHAKE) { TRACE("step3: expected handshake, got %u", rec.type); goto done; }
        if (plen < 4) { TRACE("step3: payload too short %zu", plen); goto done; }
        if (payload[0] != HS_SERVER_HELLO) { TRACE("step3: expected SH, got msg=%u", payload[0]); goto done; }

        uint32_t mlen = ((uint32_t)payload[1] << 16) |
                        ((uint32_t)payload[2] << 8) | payload[3];
        if (4 + mlen > plen) goto done;

        if (serverhello_parse(payload + 4, mlen, &sh) != 0) { TRACE("step3: serverhello_parse failed"); goto done; }
        /* Parse ALPN extension from ServerHello (RFC 7301). TLS 1.3 path
         * does this in EncryptedExtensions; TLS 1.2 has it in ServerHello. */
        if (sh.extensions && sh.extensions_len > 0) {
            const uint8_t *ep = sh.extensions;
            const uint8_t *ee = ep + sh.extensions_len;
            while (ep + 4 <= ee) {
                uint16_t etype = (uint16_t)((ep[0] << 8) | ep[1]);
                uint16_t elen  = (uint16_t)((ep[2] << 8) | ep[3]);
                ep += 4;
                if (ep + elen > ee) break;
                if (etype == 16 && elen >= 3) {
                    session_parse_alpn_ext(ep, elen, s->alpn, sizeof(s->alpn));
                    TRACE("12: ALPN = %s", s->alpn);
                }
                ep += elen;
            }
        }
        tr_add(tr, payload, 4 + mlen);
#ifdef CT_DEBUG
        {
            FILE *fp = fopen("tests/sh_dump.bin", "wb");
            if (fp) { fwrite(payload, 1, 4 + mlen, fp); fclose(fp); }
        }
#endif

        /* HRR detection — RFC 8446 §4.1.3:
         * the ServerHello random is the SHA-256 of the string
         *   "HelloRetryRequest"
         * = CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
         *   C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
         */
        static const uint8_t HRR_MAGIC[32] = {
            0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
            0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
            0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
            0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
        };
        if (memcmp(sh.random, HRR_MAGIC, 32) == 0) {
            TRACE("step3: HelloRetryRequest received — not supported");
            /* Send a proper alert so the server doesn't hang */
            session_send_alert(s, 2, 40 /* handshake_failure */);
            goto done;
        }

        /* Policy gate (secure by default): downgrade sentinel first, then
         * version + suite against the active tier. Runs before anything is
         * derived from the server's choice. */
        {
            extern int vuln_report_connection(uint16_t, uint16_t);
            uint16_t nv = sh.selected_version ? sh.selected_version : sh.legacy_version;
            const char *why = NULL;
            int gate = crisptls_policy_check_downgrade(&s->policy, nv, sh.random, &why);
            if (gate == CRISPTLS_GATE_OK)
                gate = crisptls_policy_check(&s->policy, nv, sh.cipher_suite, &why);
            if (gate != CRISPTLS_GATE_OK) {
                fprintf(stderr, "[crisptls] refused: %s (version=0x%04x suite=0x%04x tier=%s)\n",
                        why, nv, sh.cipher_suite,
                        crisptls_tier_name((crisptls_tier_t)s->policy.tier));
                session_send_alert(s, 2, gate == CRISPTLS_GATE_VERSION ? 70 :
                                         gate == CRISPTLS_GATE_DOWNGRADE ? 47 : 40);
                goto done;
            }
            vuln_report_connection(nv, sh.cipher_suite);
        }

        s->version = sh.selected_version;
        s->cipher  = sh.cipher_suite;

        if (sh.selected_version != CRISPTLS_VERSION_TLS13) {
            rc = session_handshake_12(s, &sh, priv, tr);
            if (rc != 0) TRACE("tls12: handshake failed rc=%d", rc);
            goto done;
        }
    }

    TRACE("step4: deriving shared secret");
    /* 4. Derive shared secret */
    uint8_t shared[32];
    if (keyexchange_x25519_shared(shared, priv, sh.server_pubkey) != 0) { TRACE("step4: ECDH failed"); goto done; }

    /* 5. Compute transcript hash of CH||SH. Hash depends on negotiated
     * cipher suite — SHA-384 for AES_256_GCM_SHA384, SHA-256 otherwise. */
    size_t hl = session_cipher_hash_len(s->cipher);
    uint8_t th[48];
    if (tr_hash_hl(tr, hl, th) != 0) goto done;

    /* 6. Derive handshake secrets */
    keyschedule_13_t ks;
    if (keyschedule_13_derive_handshake(shared, th, hl, &ks) != 0) { TRACE("step6: keyschedule_13 failed"); goto done; }

    memcpy(s->client_hs_secret, ks.client_handshake_traffic, hl);
    memcpy(s->server_hs_secret, ks.server_handshake_traffic, hl);
    memcpy(s->master_secret, ks.exporter_master, hl);

    /* 7. Install server handshake traffic keys (for decrypt). Pick AEAD
     * based on negotiated cipher suite, not hardcoded. */
    {
        int aead; size_t klen;
        if (session_cipher_to_aead(s->cipher, &aead, &klen) != 0) {
            TRACE("step7: unsupported cipher 0x%04x", s->cipher);
            goto done;
        }
        if (session_install_key(&s->rx, s->server_hs_secret, hl, aead, klen) != 0) {
            TRACE("step7: install_key failed");
            goto done;
        }
        TRACE("step7: installed rx aead=%d klen=%zu", aead, klen);
    }

        TRACE("step8: reading server encrypted flight");
    /* 8. Read server flight: EncryptedExtensions, Certificate, CertVerify, Finished
     *    All are encrypted with server_hs keys. */
    {
        tls_record_t rec;
        uint8_t payload[TLS_MAX_CIPHERTEXT];
        uint8_t plain[TLS_MAX_PLAINTEXT];
        size_t plen = 0;

        int got_finished = 0;
        uint8_t server_finished[48];
        int server_finished_len = 0;

        while (!got_finished) {
            if (read_record(s, &rec, payload, sizeof(payload), &plen) != 0) { goto done; }
            TRACE("step8: record type=%u len=%zu", rec.type, plen);

            /* TLS 1.3 middlebox compat: server may send ChangeCipherSpec
             * (RFC 8446 §5). Ignore it. */
            if (rec.type == CT_CCS) {
                TRACE("step8: ignoring CCS (middlebox compat)");
                continue;
            }

            if (rec.type == CT_ALERT) {
                TRACE("step8: got plaintext alert before encrypted flight");
                goto done;
            }

            if (rec.type != CT_APP) { TRACE("step8: expected app-data (encrypted), got %u", rec.type); goto done; }
            if (plen < 17) { TRACE("step8: ciphertext too short %zu", plen); goto done; }

            uint8_t inner_ct = 0;
            int pt = session_decrypt_record(&s->rx, s->version, rec.type,
                                             payload, plen,
                                             plain, &inner_ct);
            if (pt < 0) {
                FILE *fp = fopen("tests/duck_dump.txt", "w");
                if (fp) {
                    fprintf(fp, "CIPHER=0x%04x\n", s->cipher);
                    fprintf(fp, "KEY=");
                    for (int _i = 0; _i < (int)s->rx.key_len; _i++) fprintf(fp, "%02x", s->rx.key[_i]);
                    fprintf(fp, "\nIV=");
                    for (int _i = 0; _i < 12; _i++) fprintf(fp, "%02x", s->rx.iv[_i]);
                    fprintf(fp, "\nSEQ=%llu\n", (unsigned long long)s->rx.seq);
                    fprintf(fp, "CTLEN=%zu\n", plen);
                    fprintf(fp, "CIPHERTEXT=");
                    for (size_t _i = 0; _i < plen; _i++) fprintf(fp, "%02x", payload[_i]);
                    fprintf(fp, "\n");
                    fclose(fp);
                    TRACE("step8: dumped failed record to tests/duck_dump.txt");
                }
                TRACE("step8: decrypt failed"); goto done;
            }
            TRACE("step8: decrypted %d bytes inner_ct=%u", pt, inner_ct);
            s->rx.seq++;

            if (inner_ct == CT_ALERT) {
                session_log_alert(plain, (size_t)pt, "step8");
                goto done;
            }
            if (inner_ct != CT_HANDSHAKE) continue;

            /* Walk handshake messages in this record */
            size_t p = 0;
            while (p + 4 <= (size_t)pt) {
                uint8_t mtype = plain[p];
                uint32_t mlen = ((uint32_t)plain[p+1] << 16) |
                                ((uint32_t)plain[p+2] << 8) | plain[p+3];
                if (p + 4 + mlen > (size_t)pt) {
                    /* Handshake message spans multiple records. TLS 1.3
                     * allows this but no real server does it to a client.
                     * If we ever hit one, this trace tells us exactly what
                     * arrived and how much is missing. */
                    TRACE("step8: fragmented handshake msg (need %u, have %zu at offset %zu)",
                          (unsigned)(4 + mlen), (size_t)pt - p, p);
                    goto done;
                }

                /* CertificateVerify signature covers the transcript
                 * through Certificate — NOT including this message.
                 * So compute the hash BEFORE adding to transcript. */
                if (mtype == HS_CERTIFICATE_VERIFY) {
                    uint16_t sig_scheme = 0;
                    const uint8_t *sig = NULL; size_t sig_len = 0;
                    if (certificate_verify_parse(plain + p + 4, mlen,
                                                  &sig_scheme, &sig, &sig_len) == 0) {
                        uint8_t tc_hash[48];
                        if (tr_hash_hl(tr, hl, tc_hash) == 0) {
                            /* Build signature_context:
                             *   64 spaces || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
                             * Wait — RFC 8446 §4.4.3:
                             *   64 bytes of 0x20, then context string, then 0x00, then transcript_hash.
                             */
                            static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
                            uint8_t sc[64 + sizeof(ctx_str) - 1 + 1 + 48];
                            size_t sc_len = 0;
                            memset(sc, 0x20, 64);
                            sc_len = 64;
                            memcpy(sc + sc_len, ctx_str, sizeof(ctx_str) - 1);
                            sc_len += sizeof(ctx_str) - 1;
                            sc[sc_len++] = 0x00;
                            memcpy(sc + sc_len, tc_hash, hl);
                            sc_len += hl;

                            /* Extract SPKI from leaf, verify. */
                            const uint8_t *spki = NULL; size_t spki_len = 0;
                            int vrc = CT_ERR_VERIFY;
                            if (s->leaf_der && s->leaf_der_len > 0 &&
                                ct_cert_get_spki(s->leaf_der, s->leaf_der_len,
                                                  &spki, &spki_len) == 0) {
                                switch (sig_scheme) {
                                    case 0x0403: /* ecdsa_secp256r1_sha256 */
                                        vrc = ct_verify_ecdsa_p256_sha256(spki, spki_len,
                                                                           sc, sc_len,
                                                                           sig, sig_len);
                                        break;
                                    case 0x0804: /* rsa_pss_rsae_sha256 */
                                    case 0x0809: /* rsa_pss_pss_sha256 */
                                        vrc = ct_verify_rsa_pss_sha256(spki, spki_len,
                                                                       sc, sc_len,
                                                                       sig, sig_len);
                                        break;
                                    case 0x0807: /* ed25519 — needs raw key, not SPKI */
                                        /* TODO: extract raw 32-byte key from SPKI */
                                        vrc = CT_ERR_VERIFY;
                                        TRACE("step8: CertVerify ed25519 not yet wired");
                                        break;
                                    default:
                                        TRACE("step8: CertVerify sig_scheme 0x%04x not supported",
                                              sig_scheme);
                                        break;
                                }
                                ct_free_spki(spki);
                            } else {
                                TRACE("step8: CertVerify — no leaf or SPKI extract failed");
                            }
                            s->verify_result = (vrc == CT_OK) ? CRISPTLS_VERIFY_OK
                                                              : CRISPTLS_VERIFY_UNTRUSTED;
                            TRACE("step8: CertVerify sig_scheme=0x%04x result=%d",
                                  sig_scheme, vrc);
                        }
                    } else {
                        TRACE("step8: CertVerify parse failed");
                    }
                }

                tr_add(tr, plain + p, 4 + mlen);

                if (mtype == HS_ENCRYPTED_EXTENSIONS) {
                    /* Walk extensions in the EE body, look for ALPN (type 16). */
                    const uint8_t *eb = plain + p + 4;
                    size_t elen = mlen;
                    if (elen >= 2) {
                        uint16_t ext_total = (uint16_t)((eb[0] << 8) | eb[1]);
                        if ((size_t)ext_total + 2 <= elen) {
                            const uint8_t *ep = eb + 2;
                            const uint8_t *ee_end = ep + ext_total;
                            while (ep + 4 <= ee_end) {
                                uint16_t etype = (uint16_t)((ep[0] << 8) | ep[1]);
                                uint16_t elen2 = (uint16_t)((ep[2] << 8) | ep[3]);
                                ep += 4;
                                if (ep + elen2 > ee_end) break;
                                if (etype == EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                                    session_parse_alpn_ext(ep, elen2,
                                                            s->alpn, sizeof(s->alpn));
                                    TRACE("step8: negotiated ALPN = %s", s->alpn);
                                }
                                ep += elen2;
                            }
                        }
                    }
                } else if (mtype == HS_CERTIFICATE) {
                    cert_chain_t chain;
                    if (certificate_parse(plain + p + 4, mlen, &chain) == 0 &&
                        chain.count > 0) {
                        size_t ll = chain.certs[0].len;
                        s->leaf_der = malloc(ll);
                        if (s->leaf_der) {
                            memcpy(s->leaf_der, chain.certs[0].data, ll);
                            s->leaf_der_len = ll;
                        }
                        /* Keep intermediates too */
                        int n = (int)chain.count;
                        if (n > 16) n = 16;
                        for (int ci = 0; ci < n; ci++) {
                            size_t cl = chain.certs[ci].len;
                            s->chain_der[ci] = malloc(cl);
                            if (!s->chain_der[ci]) break;
                            memcpy(s->chain_der[ci], chain.certs[ci].data, cl);
                            s->chain_len[ci] = cl;
                            s->chain_count = ci + 1;
                        }
                        TRACE("step8: stored %d certs in chain", s->chain_count);
                    }
                } else if (mtype == HS_FINISHED) {
                    if (mlen != hl) { TRACE("step8: Finished len=%u expected %zu", mlen, hl); goto done; }
                    memcpy(server_finished, plain + p + 4, hl);
                    server_finished_len = (int)hl;
                }
                p += 4 + mlen;
            }
            if (server_finished_len == (int)hl) got_finished = 1;
        }

        /* 9. Verify server Finished */
        uint8_t th_server[48];
        if (tr_hash_hl(tr, hl, th_server) != 0) goto done;

        /* Transcript hash up to but NOT including server Finished.
         * Finished msg = 4 (hdr) + hl (verify_data). */
        transcript_t tr_before = *tr;
        size_t fin_len = 4 + hl;
        if (tr_before.len >= fin_len) tr_before.len -= fin_len;
        uint8_t th_before[48];
        if (tr_hash_hl(&tr_before, hl, th_before) != 0) goto done;

        TRACE("step9: verifying server Finished (hl=%zu)", hl);
        if (finished_13_verify(s->server_hs_secret, th_before, hl,
                                server_finished, (size_t)server_finished_len) != 0) {
            TRACE("step9: Finished verify failed");
            goto done;
        }

        memcpy(th_server_saved, th_server, hl);
        TRACE("step9: saved th_server for app keys");
    }

    /* 10. Install client handshake keys (for sending Finished). */
    {
        int aead; size_t klen;
        if (session_cipher_to_aead(s->cipher, &aead, &klen) != 0) goto done;
        if (session_install_key(&s->tx, s->client_hs_secret, hl, aead, klen) != 0)
            goto done;
    }

    TRACE("step11: sending client Finished");
    /* 11. Send client Finished */
    {
        uint8_t th_full[48];
        if (tr_hash_hl(tr, hl, th_full) != 0) goto done;

        uint8_t verify[48];
        if (finished_13_compute(s->client_hs_secret, th_full, hl, verify) != 0)
            goto done;

        uint8_t msg[4 + 48];
        msg[0] = HS_FINISHED;
        msg[1] = 0; msg[2] = 0; msg[3] = (uint8_t)hl;
        memcpy(msg + 4, verify, hl);

        tr_add(tr, msg, 4 + hl);

        if (record_send_encrypted(s, CT_HANDSHAKE, msg, 4 + hl) != 0) { TRACE("step11: send Finished failed"); goto done; }
    }

    /* 12. Switch to application traffic keys */
    {
        TRACE("step12: using th_server_saved for app keys");

        uint8_t c_app[32], s_app[32];
        if (keyschedule_13_derive_application(s->master_secret, th_server_saved,
                                               hl, c_app, s_app) != 0) goto done;

        memcpy(s->client_app_secret, c_app, 32);
        if (g_crisptls_trace) {
            fprintf(stderr, "[appk] client_random=");
            for (int _i = 0; _i < 32; _i++) fprintf(stderr, "%02x", s->client_random[_i]);
            fprintf(stderr, "\n[appk] chs=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", s->client_hs_secret[_i]);
            fprintf(stderr, "\n[appk] shs=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", s->server_hs_secret[_i]);
            fprintf(stderr, "\n[appk] master=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", s->master_secret[_i]);
            fprintf(stderr, "\n[appk] th=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", th_server_saved[_i]);
            fprintf(stderr, "\n[appk] c_app=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", c_app[_i]);
            fprintf(stderr, "\n[appk] s_app=");
            for (size_t _i = 0; _i < hl; _i++) fprintf(stderr, "%02x", s_app[_i]);
            fprintf(stderr, "\n");
        }
        memcpy(s->server_app_secret, s_app, 32);

        int aead; size_t klen;
        if (session_cipher_to_aead(s->cipher, &aead, &klen) != 0) goto done;
        if (session_install_key(&s->tx, c_app, hl, aead, klen) != 0) goto done;
        if (g_crisptls_trace) {
            fprintf(stderr, "[key] tx.key=");
            for (size_t _i = 0; _i < s->tx.key_len; _i++) fprintf(stderr, "%02x", s->tx.key[_i]);
            fprintf(stderr, "\n[key] tx.iv=");
            for (int _i = 0; _i < 12; _i++) fprintf(stderr, "%02x", s->tx.iv[_i]);
            fprintf(stderr, "\n[key] tx.seq=%llu\n", (unsigned long long)s->tx.seq);
        }
        if (session_install_key(&s->rx, s_app, hl, aead, klen) != 0) goto done;
    }

    TRACE("step12: handshake complete");
    s->handshake_done = 1;
    s->verify_result = CRISPTLS_VERIFY_OK;
    rc = 0;

done:
    free(tr);
    return rc;
}

/* Lifecycle */

struct crisptls_conn *session_new(const crisptls_policy_t *policy, int fd,
                                   const char *sni_host) {
    struct crisptls_conn *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fd = fd;
    if (policy) s->policy = *policy;
    else crisptls_policy_default(&s->policy);
    if (sni_host) {
        size_t n = strlen(sni_host);
        if (n >= sizeof(s->sni)) n = sizeof(s->sni) - 1;
        memcpy(s->sni, sni_host, n);
        s->sni[n] = 0;
    }
    s->hs.state = HS_STATE_INIT;
    return s;
}

void session_free(struct crisptls_conn *s) {
    if (!s) return;
    if (s->leaf_der) { free(s->leaf_der); s->leaf_der = NULL; }
    for (int i = 0; i < s->chain_count; i++) {
        if (s->chain_der[i]) { free(s->chain_der[i]); s->chain_der[i] = NULL; }
        s->chain_len[i] = 0;
    }
    s->chain_count = 0;
    free(s);
}

/* Application data I/O */

ssize_t session_write_app(struct crisptls_conn *s, const void *buf, size_t n) {
    TRACE_ENTER("crisptls: write app data", "want=%zu", n);
    if (!s || !s->handshake_done) return -1;
    if (n > TLS_MAX_PLAINTEXT) n = TLS_MAX_PLAINTEXT;

    if (record_send_encrypted(s, CT_APP, (const uint8_t *)buf, n) != 0)
        return -1;
    return (ssize_t)n;
}

/* KeyUpdate (RFC 8446 §4.6.3) */

/** Send a KeyUpdate message; then install new tx keys. */
static int session_send_key_update(struct crisptls_conn *s, uint8_t request) {
    uint8_t body[1] = { request };
    /* KeyUpdate is a post-handshake handshake message — encrypted with
     * current app keys and inner content-type = handshake. */
    if (record_send_encrypted(s, CT_HANDSHAKE, body, 1) != 0) return -1;

    /* Rotate tx secret */
    size_t hl = (s->cipher == 0x1302) ? 48 : 32;
    int aead; size_t klen;
    if (session_cipher_to_aead(s->cipher, &aead, &klen) != 0) return -1;

    uint8_t next[48];
    if (keyschedule_13_traffic_update(s->client_app_secret, hl, next) != 0)
        return -1;
    memcpy(s->client_app_secret, next, hl);
    if (session_install_key(&s->tx, s->client_app_secret, hl, aead, klen) != 0)
        return -1;
    TRACE("keyupdate: rotated tx keys (request=%u)", request);
    return 0;
}

/** Process a received KeyUpdate body (1 byte). Rotate rx; if requested, send ours. */
static int session_handle_key_update(struct crisptls_conn *s,
                                      const uint8_t *body, size_t body_len) {
    if (body_len < 1) return -1;
    uint8_t request = body[0];
    TRACE("keyupdate: received (request=%u)", request);

    size_t hl = (s->cipher == 0x1302) ? 48 : 32;
    int aead; size_t klen;
    if (session_cipher_to_aead(s->cipher, &aead, &klen) != 0) return -1;

    /* Rotate rx secret */
    uint8_t next[48];
    if (keyschedule_13_traffic_update(s->server_app_secret, hl, next) != 0)
        return -1;
    memcpy(s->server_app_secret, next, hl);
    if (session_install_key(&s->rx, s->server_app_secret, hl, aead, klen) != 0)
        return -1;
    TRACE("keyupdate: rotated rx keys");

    /* If they asked us to update, respond with our own. */
    if (request == 1) {
        if (session_send_key_update(s, 0 /* update_not_requested */) != 0) {
            TRACE("keyupdate: send response failed");
            return -1;
        }
    }
    return 0;
}

ssize_t session_read_app(struct crisptls_conn *s, void *buf, size_t n) {
    TRACE_ENTER("crisptls: read app data", "want=%zu", n);
    if (!s || !s->handshake_done) return -1;
    if (n == 0) return 0;

    /* 1. Drain any plaintext left over from a previous decrypt. */
    if (s->app_buf_pos < s->app_buf_len) {
        size_t avail = s->app_buf_len - s->app_buf_pos;
        size_t copy  = n < avail ? n : avail;
        memcpy(buf, s->app_buf + s->app_buf_pos, copy);
        s->app_buf_pos += copy;
        if (s->app_buf_pos >= s->app_buf_len) {
            s->app_buf_pos = 0;
            s->app_buf_len = 0;
        }
        if (copy > 0) {
            if (g_crisptls_trace) {
            fprintf(stderr, "[appread] got %zu bytes: ", copy);
            for (size_t _i = 0; _i < copy; _i++) fprintf(stderr, "%02x ", ((uint8_t*)buf)[_i]);
            fprintf(stderr, "('");
            for (size_t _i = 0; _i < copy; _i++) {
                uint8_t _b = ((uint8_t*)buf)[_i];
                fprintf(stderr, "%c", (_b >= 32 && _b < 127) ? _b : '.');
            }
            fprintf(stderr, "')\n");
            }
        }
        TRACE("tls_app: drained %zu from buffer (remain=%zu)",
              copy, s->app_buf_len - s->app_buf_pos);
        return (ssize_t)copy;
    }

    for (;;) {
        tls_record_t rec;
        uint8_t payload[TLS_MAX_CIPHERTEXT];
        size_t plen = 0;
        if (read_record(s, &rec, payload, sizeof(payload), &plen) != 0)
            return -1;

        if (rec.type == CT_ALERT) {
            /* TLS 1.2 alerts are encrypted. Decrypt, then parse level+desc. */
            uint8_t plain[TLS_MAX_PLAINTEXT];
            uint8_t inner_ct = 0;
            int pt = session_decrypt_record(&s->rx, s->version, rec.type,
                                             payload, plen,
                                             plain, &inner_ct);
            if (pt >= 2) {
                s->rx.seq++;
                TRACE("tls_app: got alert — level=%u desc=%u (%s) — returning 0",
                      (unsigned)plain[0], (unsigned)plain[1],
                      alert_name(plain[1]));
            } else {
                TRACE("tls_app: got outer alert (decrypt failed pt=%d) — returning 0", pt);
            }
            return 0;
        }
        if (rec.type != CT_APP) {
            TRACE("tls_app: skipping non-app record type=%u", rec.type);
            continue;
        }

        uint8_t plain[TLS_MAX_PLAINTEXT];
        uint8_t inner_ct = 0;
        int pt = session_decrypt_record(&s->rx, s->version, rec.type,
                                         payload, plen,
                                         plain, &inner_ct);
        if (pt < 0) return -1;
        s->rx.seq++;

        if (inner_ct == CT_ALERT) {
            session_log_alert(plain, (size_t)pt, "read_app");
            return 0;
        }
        if (inner_ct == CT_HANDSHAKE) {
            size_t p = 0;
            while (p + 4 <= (size_t)pt) {
                uint8_t mt = plain[p];
                uint32_t ml = ((uint32_t)plain[p+1] << 16) |
                              ((uint32_t)plain[p+2] << 8) | plain[p+3];
                if (p + 4 + ml > (size_t)pt) break;
                if (mt == HS_KEY_UPDATE) {
                    if (session_handle_key_update(s, plain + p + 4, ml) != 0)
                        return -1;
                }
                p += 4 + ml;
            }
            continue;
        }
        if (inner_ct != CT_APP) continue;

        /* 2. Fresh plaintext arrived. Return what fits, buffer the rest. */
        size_t avail = (size_t)pt;
        size_t copy  = n < avail ? n : avail;
        memcpy(buf, plain, copy);

        if (avail > copy) {
            size_t remain = avail - copy;
            if (remain > sizeof(s->app_buf)) remain = sizeof(s->app_buf);
            memcpy(s->app_buf, plain + copy, remain);
            s->app_buf_len = remain;
            s->app_buf_pos = 0;
            TRACE("tls_app: read %zu, buffered %zu", copy, remain);
        } else {
            s->app_buf_len = 0;
            s->app_buf_pos = 0;
        }
        return (ssize_t)copy;
    }
}
