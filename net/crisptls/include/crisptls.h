/** crisptls.h — CRISP TLS public API. Everything user-facing lives here. */

#ifndef CRISPTLS_H
#define CRISPTLS_H

#include "crisptls_types.h"
#include "crisptls_policy.h"
#include "crisptls_fingerprint.h"

#include <sys/types.h>

/** Lifecycle */

/** Create a context (shared across connections). Holds cert caches, session cache. */
crisptls_ctx_t *crisptls_ctx_new(const crisptls_policy_t *policy);
void            crisptls_ctx_free(crisptls_ctx_t *ctx);

/** Change the policy on an existing context (affects future connections). */
int  crisptls_ctx_set_policy(crisptls_ctx_t *ctx, const crisptls_policy_t *policy);

/** Select backend ("openssl", "mbedtls", "native"). Must be set before first connect. */
int  crisptls_set_backend(const char *name);
const char *crisptls_get_backend(void);

/** Connect */

/** Given a connected TCP socket, perform TLS handshake.
 * `sni_host` used for SNI extension and hostname verification. */
crisptls_conn_t *crisptls_connect(crisptls_ctx_t *ctx, int fd, const char *sni_host);

/** Close (sends close_notify, frees conn). Socket is NOT closed — caller owns fd. */
void crisptls_close(crisptls_conn_t *conn);

/** I/O */

ssize_t crisptls_read (crisptls_conn_t *conn, void *buf, size_t n);
ssize_t crisptls_write(crisptls_conn_t *conn, const void *buf, size_t n);

/** Handshake metadata */

int          crisptls_get_version(crisptls_conn_t *conn);   /* 0x0303 etc */
const char  *crisptls_get_cipher (crisptls_conn_t *conn);
const char  *crisptls_get_alpn   (crisptls_conn_t *conn);
const char  *crisptls_get_sni    (crisptls_conn_t *conn);

/** Peer certificate (leaf), DER-encoded. Returns length or -1 on error. */
int crisptls_get_peer_cert_der(crisptls_conn_t *conn,
                               uint8_t *out, size_t cap, size_t *out_len);

/** Get certificate at `index` from the peer chain (0 = leaf).
 *  Returns CRISPTLS_OK, CRISPTLS_ERR_ARGS, or CRISPTLS_ERR_VERIFY if out of range. */
int crisptls_get_peer_chain_der(crisptls_conn_t *conn, int index,
                               uint8_t *out, size_t cap, size_t *out_len);

/** Chain verification status. */
int crisptls_verify_status(crisptls_conn_t *conn);

/** Fingerprint (of the connection that happened) */

int crisptls_conn_ja3_hash(crisptls_conn_t *conn, char *out, size_t cap);
int crisptls_conn_ja4_hash(crisptls_conn_t *conn, char *out, size_t cap);

/** Errors */
const char *crisptls_err_name(int err);

#endif
const char *crisptls_err_name(int err);

/** Last error string from the most recent crisptls_connect() that failed.
 *  Returns NULL if the last connect succeeded or no connect has run yet.
 *  String is owned by crisptls, valid until the next crisptls_connect(). */
const char *crisptls_last_error(void);
const char *crisptls_err_name(int err);

/* Runtime trace switch. When enabled, TLS handshake steps and record-layer
 * operations print to stderr. Default off. Safe to call any time. */
/* Runtime trace flag; set by crisptls_set_trace. Do not modify directly. */
extern int g_crisptls_trace;
extern int g_crisptls_color;
extern int g_crisptls_quiet;

void crisptls_set_trace(int on);
void crisptls_set_color(int on);
void crisptls_set_quiet(int on);
