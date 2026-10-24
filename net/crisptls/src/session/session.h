/** session.h — internal connection state. Not public API. */

#ifndef CRISPTLS_SESSION_H
#define CRISPTLS_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include "crisptls_policy.h"
#include "crisptls_types.h"
#include "state.h"
#include <sys/types.h>

/* AEAD selection for a direction */
enum {
    SESSION_AEAD_NONE    = 0,
    SESSION_AEAD_AES128  = 1,
    SESSION_AEAD_AES256  = 2,
    SESSION_AEAD_CHACHA  = 3,
};

typedef struct {
    uint8_t  key[32];
    uint8_t  iv[12];
    size_t   key_len;
    int      aead;
    uint64_t seq;
} session_dir_t;

struct crisptls_conn {
    int            fd;
    crisptls_policy_t policy;   /* copy so caller can free theirs */

    /* negotiated */
    uint16_t version;
    uint16_t cipher;
    char     cipher_name[64];
    char     alpn[64];
    char     sni[256];

    /* client random from ClientHello — needed for TLS 1.2 master secret */
    uint8_t  client_random[32];
    /* handshake */
    hs_context_t hs;

    /* transcript — SHA-256 over all handshake messages */
    uint8_t  transcript[32];

    /* key material (TLS 1.3) */
    uint8_t  client_hs_secret[48];
    uint8_t  server_hs_secret[48];
    uint8_t  client_app_secret[48];
    uint8_t  server_app_secret[48];
    uint8_t  master_secret[48];

    session_dir_t tx;
    session_dir_t rx;

    /* cert */
    uint8_t *leaf_der;
    size_t   leaf_der_len;
    int      verify_result;

    /* Full cert chain (leaf at index 0, intermediates after) */
    uint8_t *chain_der[16];
    size_t   chain_len[16];
    int      chain_count;

    /* plaintext buffer — survives across session_read_app calls.
     * TLS records may deliver more plaintext than the caller asked for;
     * the excess is buffered here and drained on the next call. */
    /* same value as TLS_MAX_PLAINTEXT in record.h; hardcoded here to
     * avoid a header dependency cycle (record.h <-> session.h). */
    uint8_t  app_buf[16384];
    size_t   app_buf_len;
    size_t   app_buf_pos;

    /* state flags */
    int      handshake_done;
    int      sent_close_notify;
    int      recv_close_notify;
    int      fatal_error;
    char     fail_step[80];  /* specific failure step, e.g. "step8: decrypt failed" */

    /* scratch for reads */
    uint8_t  rx_buf[18432];
    size_t   rx_buf_len;

    /* raw ClientHello we sent (for JA4 fingerprint) */
    uint8_t  raw_ch[2048];
    size_t   raw_ch_len;

    /* Handshake message reassembly buffer (for fragmented messages
     * split across multiple TLS records). */
    uint8_t  hs_accum[32768];
    size_t   hs_accum_len;
};

/* --- lifecycle --- */
struct crisptls_conn *session_new(const crisptls_policy_t *policy, int fd,
                                   const char *sni_host);
void session_free(struct crisptls_conn *s);

/* --- handshake driver --- */
int session_handshake(struct crisptls_conn *s);

/* --- record I/O --- */
ssize_t session_write_app(struct crisptls_conn *s, const void *buf, size_t n);
ssize_t session_read_app (struct crisptls_conn *s, void *buf, size_t n);
int     session_send_alert(struct crisptls_conn *s, uint8_t level, uint8_t desc);

/* --- helpers --- */
int session_transcript_update(struct crisptls_conn *s,
                              const uint8_t *msg, size_t len);
int session_fd_write_all(int fd, const uint8_t *buf, size_t n,
                         uint32_t timeout_ms);
int session_fd_read_some(int fd, uint8_t *buf, size_t cap, size_t *out_len,
                         uint32_t timeout_ms);

#endif
