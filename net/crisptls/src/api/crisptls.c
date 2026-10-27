/** crisptls.c — implementation of the public API in crisptls.h. */

#include "crisptls.h"
#include "crisptls_fingerprint.h"
#include "crisptls_policy.h"
#include "session.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto_cert.h"

/* Context */

struct crisptls_ctx {
    crisptls_policy_t policy;
    int               has_policy;
    char              backend[16];
};

static const char *g_backend = "native";
static char        g_backend_buf[16] = "native";

crisptls_ctx_t *crisptls_ctx_new(const crisptls_policy_t *policy) {
    struct crisptls_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    if (policy) { c->policy = *policy; c->has_policy = 1; }
    else { crisptls_policy_default(&c->policy); c->has_policy = 1; }
    strncpy(c->backend, g_backend, sizeof(c->backend) - 1);
    return c;
}

void crisptls_ctx_free(crisptls_ctx_t *ctx) {
    free(ctx);
}

int crisptls_ctx_set_policy(crisptls_ctx_t *ctx, const crisptls_policy_t *policy) {
    if (!ctx || !policy) return CRISPTLS_ERR_ARGS;
    ctx->policy = *policy;
    ctx->has_policy = 1;
    return CRISPTLS_OK;
}

/* Backend selection */

int crisptls_set_backend(const char *name) {
    if (!name) return CRISPTLS_ERR_ARGS;
    strncpy(g_backend_buf, name, sizeof(g_backend_buf) - 1);
    g_backend = g_backend_buf;
    return CRISPTLS_OK;
}

const char *crisptls_get_backend(void) {
    return g_backend;
}

/* Connect / close */

static char g_last_error[256];
char g_crisptls_last_fail_step[80] = {0};

const char *crisptls_last_error(void) {
    return g_last_error[0] ? g_last_error : NULL;
}

crisptls_conn_t *crisptls_connect(crisptls_ctx_t *ctx, int fd, const char *sni_host) {
    g_last_error[0] = 0;
    if (!ctx || fd < 0) {
        snprintf(g_last_error, sizeof g_last_error, "invalid args (ctx=%p fd=%d)",
                 (void *)ctx, fd);
        return NULL;
    }
    struct crisptls_conn *s = session_new(&ctx->policy, fd, sni_host);
    if (!s) {
        snprintf(g_last_error, sizeof g_last_error, "session_new failed (out of memory)");
        return NULL;
    }
    if (session_handshake(s) != 0) {
        if (g_crisptls_last_fail_step[0])
            snprintf(g_last_error, sizeof g_last_error, "handshake failed: %s", g_crisptls_last_fail_step);
        else
            snprintf(g_last_error, sizeof g_last_error, "handshake failed (no step info)");
        session_free(s);
        return NULL;
    }

    /* Post-handshake: verify peer certificate chain (RFC 5280 + 6125).
     * Set verify_peer = 0 to bypass (--insecure). */
    if (s->policy.verify_peer && s->chain_count > 0) {
        int vrc = cert_verify_chain((const uint8_t *const *)s->chain_der,
                                    (const size_t *)s->chain_len,
                                    (size_t)s->chain_count,
                                    sni_host,
                                    s->policy.ca_bundle_path,
                                    NULL);
        const char *why = NULL;
        switch (vrc) {
            case CERT_OK:              s->verify_result = CRISPTLS_VERIFY_OK; break;
            case CERT_ERR_EXPIRED:     s->verify_result = CRISPTLS_VERIFY_EXPIRED;    why = "certificate expired"; break;
            case CERT_ERR_HOST:        s->verify_result = CRISPTLS_VERIFY_WRONGHOST;  why = "hostname mismatch"; break;
            case CERT_ERR_ROOT:        s->verify_result = CRISPTLS_VERIFY_SELFSIGNED; why = "untrusted root CA"; break;
            case CERT_ERR_SIG:         s->verify_result = CRISPTLS_VERIFY_BADCHAIN;   why = "chain signature invalid"; break;
            case CERT_ERR_CHAIN:       s->verify_result = CRISPTLS_VERIFY_UNTRUSTED;  why = "chain does not reach trusted root"; break;
            case CERT_ERR_CA_MISSING:  s->verify_result = CRISPTLS_VERIFY_UNTRUSTED;  why = "no CA bundle found"; break;
            case CERT_ERR_UNSUPPORTED: s->verify_result = CRISPTLS_VERIFY_UNTRUSTED;  why = "signature algorithm not supported"; break;
            default:                   s->verify_result = CRISPTLS_VERIFY_UNTRUSTED;  why = "certificate verification failed"; break;
        }
        if (vrc != CERT_OK) {
            if (!g_crisptls_quiet) {
                if (g_crisptls_color)
                    fprintf(stderr, "\033[1;31m[!] cert verify: %s%s\033[0m\n",
                            why ? why : "cert verify failed",
                            s->policy.verify_peer >= 2 ? " (strict: refusing)" : " (advisory)");
                else
                    fprintf(stderr, "[!] cert verify: %s%s\n",
                            why ? why : "cert verify failed",
                            s->policy.verify_peer >= 2 ? " (strict: refusing)" : " (advisory)");
            }
            /* An algorithm we cannot verify is never advisory. */
            if (vrc == CERT_ERR_UNSUPPORTED) {
                snprintf(g_last_error, sizeof g_last_error, "%s", why ? why : "unsupported algorithm");
                session_free(s);
                return NULL;
            }
            if (s->policy.verify_peer >= 2) {
                snprintf(g_last_error, sizeof g_last_error, "%s", why ? why : "cert verify failed");
                session_free(s);
                return NULL;
            }
        }
    } else if (!s->policy.verify_peer) {
        /* --insecure: verification explicitly skipped */
        s->verify_result = CRISPTLS_VERIFY_OK;
    }

    return s;
}

void crisptls_close(crisptls_conn_t *conn) {
    if (!conn) return;
    if (!conn->sent_close_notify) {
        session_send_alert(conn, 1 /* warning */, 0 /* close_notify */);
        conn->sent_close_notify = 1;
    }
    session_free(conn);
}

/* I/O */

ssize_t crisptls_read(crisptls_conn_t *conn, void *buf, size_t n) {
    if (!conn || !buf) return CRISPTLS_ERR_ARGS;
    return session_read_app(conn, buf, n);
}

ssize_t crisptls_write(crisptls_conn_t *conn, const void *buf, size_t n) {
    if (!conn || !buf) return CRISPTLS_ERR_ARGS;
    return session_write_app(conn, buf, n);
}

/* Handshake metadata */

int crisptls_get_version(crisptls_conn_t *conn) {
    if (!conn) return 0;
    return conn->version;
}

const char *crisptls_get_cipher(crisptls_conn_t *conn) {
    if (!conn) return NULL;

    /* Short names as shown by Wireshark, openssl s_client, and Chrome devtools.
     * Full IANA names ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") can be derived
     * but are rarely what a user wants to see. */
    static const struct { uint16_t code; const char *name; } TBL[] = {
        /* TLS 1.3 (RFC 8446) */
        { 0x1301, "TLS_AES_128_GCM_SHA256" },
        { 0x1302, "TLS_AES_256_GCM_SHA384" },
        { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },

        /* TLS 1.2 ECDHE AEAD (RFC 5289) */
        { 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256" },
        { 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384" },
        { 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256" },
        { 0xC030, "ECDHE-RSA-AES256-GCM-SHA384" },

        /* TLS 1.2 ECDHE ChaCha20-Poly1305 (RFC 7905) */
        { 0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305" },
        { 0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305" },
        { 0xCCAA, "DHE-RSA-CHACHA20-POLY1305" },

        /* TLS 1.2 ECDHE CBC */
        { 0xC009, "ECDHE-ECDSA-AES128-SHA" },
        { 0xC00A, "ECDHE-ECDSA-AES256-SHA" },
        { 0xC013, "ECDHE-RSA-AES128-SHA" },
        { 0xC014, "ECDHE-RSA-AES256-SHA" },
        { 0xC023, "ECDHE-ECDSA-AES128-SHA256" },
        { 0xC024, "ECDHE-ECDSA-AES256-SHA384" },
        { 0xC027, "ECDHE-RSA-AES128-SHA256" },
        { 0xC028, "ECDHE-RSA-AES256-SHA384" },

        /* TLS 1.2 DHE AEAD (RFC 5288) */
        { 0x009E, "DHE-RSA-AES128-GCM-SHA256" },
        { 0x009F, "DHE-RSA-AES256-GCM-SHA384" },

        /* TLS 1.2 DHE CBC */
        { 0x0033, "DHE-RSA-AES128-SHA" },
        { 0x0039, "DHE-RSA-AES256-SHA" },
        { 0x0067, "DHE-RSA-AES128-SHA256" },
        { 0x006B, "DHE-RSA-AES256-SHA256" },

        /* TLS 1.2 RSA AEAD (RFC 5288) */
        { 0x009C, "AES128-GCM-SHA256" },
        { 0x009D, "AES256-GCM-SHA384" },

        /* TLS 1.2 RSA CBC (RFC 5246) */
        { 0x002F, "AES128-SHA" },
        { 0x0035, "AES256-SHA" },
        { 0x003C, "AES128-SHA256" },
        { 0x003D, "AES256-SHA256" },

        /* RC4 (SSL 3.0 / TLS 1.0 / 1.1) — RFC 6101 / 7465 (historic) */
        { 0x0004, "RC4-MD5" },
        { 0x0005, "RC4-SHA" },
        { 0xC007, "ECDHE-ECDSA-RC4-SHA" },
        { 0xC011, "ECDHE-RSA-RC4-SHA" },

        /* 3DES */
        { 0x000A, "DES-CBC3-SHA" },
        { 0xC008, "ECDHE-ECDSA-DES-CBC3-SHA" },
        { 0xC012, "ECDHE-RSA-DES-CBC3-SHA" },

        /* PSK variants occasionally seen on embedded servers */
        { 0x00A8, "PSK-AES128-GCM-SHA256" },
        { 0x00A9, "PSK-AES256-GCM-SHA384" },
        { 0x00AE, "PSK-AES128-CBC-SHA" },
        { 0x00AF, "PSK-AES256-CBC-SHA" },

        { 0, NULL }
    };

    for (size_t i = 0; TBL[i].name; i++)
        if (TBL[i].code == conn->cipher) return TBL[i].name;
    return "UNKNOWN";
}

const char *crisptls_get_alpn(crisptls_conn_t *conn) {
    if (!conn) return NULL;
    return conn->alpn[0] ? conn->alpn : NULL;
}

const char *crisptls_get_sni(crisptls_conn_t *conn) {
    if (!conn) return NULL;
    return conn->sni[0] ? conn->sni : NULL;
}

int crisptls_get_peer_cert_der(crisptls_conn_t *conn,
                                uint8_t *out, size_t cap, size_t *out_len) {
    if (!conn || !out || !out_len) return CRISPTLS_ERR_ARGS;
    if (!conn->leaf_der) return CRISPTLS_ERR_VERIFY;
    if (cap < conn->leaf_der_len) return CRISPTLS_ERR_ARGS;
    memcpy(out, conn->leaf_der, conn->leaf_der_len);
    *out_len = conn->leaf_der_len;
    return CRISPTLS_OK;
}

int crisptls_get_peer_chain_der(crisptls_conn_t *conn, int index,
                                uint8_t *out, size_t cap, size_t *out_len) {
    if (!conn || !out || !out_len) return CRISPTLS_ERR_ARGS;
    if (index < 0 || index >= conn->chain_count) return CRISPTLS_ERR_VERIFY;
    if (cap < conn->chain_len[index]) return CRISPTLS_ERR_ARGS;
    memcpy(out, conn->chain_der[index], conn->chain_len[index]);
    *out_len = conn->chain_len[index];
    return CRISPTLS_OK;
}

int crisptls_verify_status(crisptls_conn_t *conn) {
    if (!conn) return CRISPTLS_ERR_ARGS;
    return conn->verify_result;
}

/* Fingerprint */

extern int crisptls_ja3_from_raw(const uint8_t *raw, size_t raw_len,
                                 char *md5_hex_out, size_t cap);
extern int crisptls_ja4_from_raw(const uint8_t *raw, size_t raw_len,
                                 char *out, size_t cap);

int crisptls_conn_ja3_hash(crisptls_conn_t *conn, char *out, size_t cap) {
    if (!conn || !out || cap < 33) return CRISPTLS_ERR_ARGS;
    if (conn->raw_ch_len > 0 &&
        crisptls_ja3_from_raw(conn->raw_ch, conn->raw_ch_len, out, cap) == 0) {
        return CRISPTLS_OK;
    }
    memset(out, '0', 32);
    out[32] = 0;
    return CRISPTLS_OK;
}

extern int crisptls_ja4_from_raw(const uint8_t *raw, size_t raw_len,
                                 char *out, size_t cap);

int crisptls_conn_ja4_hash(crisptls_conn_t *conn, char *out, size_t cap) {
    if (!conn || !out || cap < 40) return CRISPTLS_ERR_ARGS;
    if (conn->raw_ch_len > 0 &&
        crisptls_ja4_from_raw(conn->raw_ch, conn->raw_ch_len, out, cap) == 0) {
        return CRISPTLS_OK;
    }
    memset(out, '0', 36);
    out[36] = 0;
    return CRISPTLS_OK;
}

/* Errors */

const char *crisptls_err_name(int err) {
    switch (err) {
        case CRISPTLS_OK:              return "OK";
        case CRISPTLS_ERR_ARGS:        return "ARGS";
        case CRISPTLS_ERR_NOMEM:       return "NOMEM";
        case CRISPTLS_ERR_BACKEND:     return "BACKEND";
        case CRISPTLS_ERR_SOCKET:      return "SOCKET";
        case CRISPTLS_ERR_HANDSHAKE:   return "HANDSHAKE";
        case CRISPTLS_ERR_VERIFY:      return "VERIFY";
        case CRISPTLS_ERR_TIMEOUT:     return "TIMEOUT";
        case CRISPTLS_ERR_CLOSED:      return "CLOSED";
        case CRISPTLS_ERR_ALPN:        return "ALPN";
        case CRISPTLS_ERR_POLICY:      return "POLICY";
        case CRISPTLS_ERR_PROFILE:     return "PROFILE";
        default:                       return "UNKNOWN";
    }
}

/* Runtime trace switch. Default off. */
int g_crisptls_trace = 0;
int g_crisptls_color = 1;   /* default on; --no-color sets to 0 */
int g_crisptls_quiet = 0;   /* default off; --quiet or --no-warnings sets to 1 */

void crisptls_set_trace(int on) { g_crisptls_trace = on; }
void crisptls_set_color(int on) { g_crisptls_color = on; }
void crisptls_set_quiet(int on) { g_crisptls_quiet = on; }

