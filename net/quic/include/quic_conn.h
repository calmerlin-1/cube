/** quic_conn.h — QUIC connection state machine (RFC 9000 §7-§17).
 *
 * Scope for now:
 *   - Client-side handshake driver
 *   - Three packet number spaces (Initial, Handshake, Application)
 *   - CRYPTO frame accumulation for TLS handshake
 *   - Key installation for each space
 *
 * Uses crisptls for:
 *   - clienthello_build (identical to TLS-over-TCP)
 *   - serverhello_parse
 *   - keyschedule_13_derive_handshake / _application
 *   - finished_13_compute / _verify
 *   - QUIC-specific key derivation (crisptls_quic.h)
 *
 * Uses this module for:
 *   - UDP transport (quic_udp.h)
 *   - Packet framing (quic_packet.h)
 *   - Frame encoding (quic_frame.h)
 */

#ifndef QUIC_CONN_H
#define QUIC_CONN_H

#include <stdint.h>
#include <stddef.h>
#include "quic_udp.h"

/* ---- Connection states ---- */
typedef enum {
    QUIC_ST_IDLE = 0,
    QUIC_ST_INITIAL_SENT,
    QUIC_ST_HANDSHAKE_RECV,
    QUIC_ST_HANDSHAKE_SENT,
    QUIC_ST_ESTABLISHED,
    QUIC_ST_CLOSING,
    QUIC_ST_CLOSED,
    QUIC_ST_ERROR,
} quic_state_t;

/* ---- Packet number space ---- */
typedef struct {
    uint64_t next_pn;         /* next PN to use when sending */
    uint64_t largest_acked;   /* highest PN acked by peer */
    uint64_t largest_recv;    /* highest PN received from peer */
    uint64_t recv_count;      /* packets received */
    uint64_t send_count;      /* packets sent */
    /* Keys for this space (set when secrets are derived) */
    int      have_keys;
    uint8_t  tx_key[32];      /* packet protection key */
    uint8_t  tx_iv[12];
    uint8_t  tx_hp[32];       /* header protection key */
    size_t   tx_key_len;
    uint8_t  rx_key[32];
    uint8_t  rx_iv[12];
    uint8_t  rx_hp[32];
    size_t   rx_key_len;
} quic_pn_space_t;

/* ---- Connection ID ---- */
#define QUIC_CID_MAX 20

/* ---- Handshake accumulation buffer ---- */
#define QUIC_HS_BUF_MAX 16384

/* ---- Connection ---- */
typedef struct quic_conn {
    quic_state_t state;

    /* UDP transport */
    quic_udp_t   udp;

    /* Server address */
    char         server_host[256];

    /* Connection IDs */
    uint8_t      dcid_len;
    uint8_t      dcid[QUIC_CID_MAX];    /* peer's chosen CID */
    uint8_t      scid_len;
    uint8_t      scid[QUIC_CID_MAX];    /* our chosen CID */

    /* Original DCID used to derive initial secrets */
    uint8_t      original_dcid_len;
    uint8_t      original_dcid[QUIC_CID_MAX];

    /* Packet number spaces */
    quic_pn_space_t initial;
    quic_pn_space_t handshake;
    quic_pn_space_t application;

    /* Handshake message accumulation (from CRYPTO frames) */
    uint8_t      hs_buf[QUIC_HS_BUF_MAX];
    size_t       hs_buf_len;

    /* TLS handshake state */
    uint8_t      client_random[32];
    uint8_t      x25519_priv[32];
    uint8_t      x25519_pub[32];
    uint8_t      shared_secret[32];

    /* Transcript for the TLS handshake (CH || SH || EE || Cert || CV || Fin) */
    uint8_t      transcript[QUIC_HS_BUF_MAX];
    size_t       transcript_len;

    /* Negotiated */
    uint16_t     cipher_suite;      /* 0x1301, etc. */

    /* Handshake secrets (48 bytes each, use SHA-384 max) */
    uint8_t      client_hs_secret[48];
    uint8_t      server_hs_secret[48];
    uint8_t      master_secret[48];

    /* Hash length for the negotiated cipher */
    size_t       hash_len;          /* 32 or 48 */

    /* Error code from CONNECTION_CLOSE */
    uint64_t     close_error;

    /* Stats */
    uint64_t     bytes_sent;
    uint64_t     bytes_recv;

} quic_conn_t;

/* ---- Lifecycle ---- */

/* Initialize a connection to `host` (IP string) : `port`. */
int quic_conn_init(quic_conn_t *c, const char *host, uint16_t port);

/* Free resources. */
void quic_conn_free(quic_conn_t *c);

/* ---- Handshake driver ---- */

/* Send the client Initial packet (ClientHello in CRYPTO frame). */
int quic_conn_send_initial(quic_conn_t *c);

/* Process an incoming datagram. Returns 0 on success, -1 on error,
 * 1 if the handshake just completed. */
int quic_conn_process_datagram(quic_conn_t *c,
                               const uint8_t *buf, size_t len);

/* Drive the handshake for up to `timeout_ms`. Returns:
 *   0 = still in progress
 *   1 = handshake complete
 *  -1 = error
 */
int quic_conn_handshake(quic_conn_t *c, int timeout_ms);

/* ---- PN spaces ---- */

void quic_pn_space_init(quic_pn_space_t *sp);

/* Install TX/RX keys for a space from a traffic secret. */
int quic_pn_space_install_keys(quic_pn_space_t *sp,
                                const uint8_t *tx_secret, size_t secret_len,
                                const uint8_t *rx_secret,
                                uint16_t cipher_suite);

const char *quic_state_name(quic_state_t s);

#endif /* QUIC_CONN_H */
