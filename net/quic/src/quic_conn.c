/** quic_conn.c — QUIC connection state machine (client side).
 *
 * Client handshake driver:
 *   1. Generate SCID + x25519 keypair
 *   2. Build ClientHello, wrap in CRYPTO frame, put in Initial packet, send
 *   3. Receive datagrams: decrypt, extract CRYPTO frames, accumulate handshake
 *   4. When ServerHello arrives: derive handshake keys, install in handshake PN space
 *   5. When server Finished arrives: verify, send client Finished
 *   6. On HANDSHAKE_DONE (or first 1-RTT packet): switch to application keys
 */

#include "quic_conn.h"
#include "quic_frame.h"
#include "quic_packet.h"
#include "quic_varint.h"
#include "crisptls_quic.h"
#include "crypto.h"
#include "handshake.h"
#include "keyschedule.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#define QUIC_TRACE(...) do { fprintf(stderr, "[quic] " __VA_ARGS__); fputc('\n', stderr); } while (0)

/* PN space */

void quic_pn_space_init(quic_pn_space_t *sp) {
    if (!sp) return;
    memset(sp, 0, sizeof(*sp));
}

int quic_pn_space_install_keys(quic_pn_space_t *sp,
                                const uint8_t *tx_secret, size_t secret_len,
                                const uint8_t *rx_secret,
                                uint16_t cipher_suite) {
    if (!sp || !tx_secret || !rx_secret) return -1;

    crisptls_quic_dir_keys_t txk, rxk;
    if (crisptls_quic_derive_dir(tx_secret, secret_len, cipher_suite, &txk) != 0)
        return -1;
    if (crisptls_quic_derive_dir(rx_secret, secret_len, cipher_suite, &rxk) != 0)
        return -1;

    memcpy(sp->tx_key, txk.packet_key, txk.key_len);
    memcpy(sp->tx_iv,  txk.packet_iv, 12);
    memcpy(sp->tx_hp,  txk.hp_key,    txk.key_len);
    sp->tx_key_len = txk.key_len;
    memcpy(sp->rx_key, rxk.packet_key, rxk.key_len);
    memcpy(sp->rx_iv,  rxk.packet_iv, 12);
    memcpy(sp->rx_hp,  rxk.hp_key,    rxk.key_len);
    sp->rx_key_len = rxk.key_len;
    sp->have_keys = 1;
    sp->next_pn = 0;
    sp->largest_acked = 0;
    sp->largest_recv = 0;
    return 0;
}

const char *quic_state_name(quic_state_t s) {
    switch (s) {
        case QUIC_ST_IDLE: return "idle";
        case QUIC_ST_INITIAL_SENT: return "initial-sent";
        case QUIC_ST_HANDSHAKE_RECV: return "handshake-recv";
        case QUIC_ST_HANDSHAKE_SENT: return "handshake-sent";
        case QUIC_ST_ESTABLISHED: return "established";
        case QUIC_ST_CLOSING: return "closing";
        case QUIC_ST_CLOSED: return "closed";
        case QUIC_ST_ERROR: return "error";
        default: return "?";
    }
}

/* Connection init / free */

int quic_conn_init(quic_conn_t *c, const char *host, uint16_t port) {
    if (!c || !host) return -1;
    memset(c, 0, sizeof(*c));

    c->state = QUIC_ST_IDLE;
    strncpy(c->server_host, host, sizeof(c->server_host) - 1);

    /* Open UDP + connect */
    if (quic_udp_open(&c->udp, AF_INET) != 0) return -1;
    if (quic_udp_connect(&c->udp, host, port) != 0) {
        quic_udp_close(&c->udp);
        return -1;
    }
    quic_udp_set_timeout(&c->udp, 500);

    /* Generate our SCID (8 bytes) */
    c->scid_len = 8;
    if (ct_random(c->scid, 8) != CT_OK) return -1;

    /* Generate the original DCID we send to the server (this seeds
     * the initial secrets before the server picks its own CID). */
    c->original_dcid_len = 8;
    if (ct_random(c->original_dcid, 8) != CT_OK) return -1;
    memcpy(c->dcid, c->original_dcid, 8);
    c->dcid_len = 8;

    /* Generate x25519 keypair */
    if (keyexchange_x25519_keypair(c->x25519_priv, c->x25519_pub) != 0)
        return -1;

    /* Generate client_random */
    if (ct_random(c->client_random, 32) != CT_OK) return -1;

    /* Derive initial secrets from the ORIGINAL DCID */
    crisptls_quic_keys_t ik;
    memset(&ik, 0, sizeof(ik));
    if (crisptls_quic_derive_initial(c->original_dcid, 8,
                                      CRISPTLS_QUIC_V1, &ik) != 0)
        return -1;

    /* Install in Initial PN space */
    memcpy(c->initial.tx_key, ik.client.packet_key, ik.client.key_len);
    memcpy(c->initial.tx_iv,  ik.client.packet_iv, 12);
    memcpy(c->initial.tx_hp,  ik.client.hp_key,    ik.client.key_len);
    c->initial.tx_key_len = ik.client.key_len;
    memcpy(c->initial.rx_key, ik.server.packet_key, ik.server.key_len);
    memcpy(c->initial.rx_iv,  ik.server.packet_iv, 12);
    memcpy(c->initial.rx_hp,  ik.server.hp_key,    ik.server.key_len);
    c->initial.rx_key_len = ik.server.key_len;
    c->initial.have_keys = 1;

    QUIC_TRACE("init: scid=");
    for (int i = 0; i < c->scid_len; i++) fprintf(stderr, "%02x", c->scid[i]);
    fprintf(stderr, " dcid=");
    for (int i = 0; i < c->dcid_len; i++) fprintf(stderr, "%02x", c->dcid[i]);
    fprintf(stderr, "\n");

    return 0;
}

void quic_conn_free(quic_conn_t *c) {
    if (!c) return;
    quic_udp_close(&c->udp);
}

/* Send ClientInitial */

int quic_conn_send_initial(quic_conn_t *c) {
    if (!c) return -1;

    /* ---- Build ClientHello ---- */
    crisptls_policy_t pol;
    crisptls_policy_default(&pol);
    /* QUIC ALPN */
    pol.alpn = "h3";

    uint8_t ch[2048];
    size_t ch_len = 0;
    if (clienthello_build(&pol, c->server_host, c->client_random,
                          c->x25519_pub, ch, sizeof(ch), &ch_len) != 0) {
        QUIC_TRACE("clienthello_build failed");
        return -1;
    }
    QUIC_TRACE("built CH, %zu bytes", ch_len);

    /* Save CH in transcript */
    if (ch_len > sizeof(c->transcript)) return -1;
    memcpy(c->transcript, ch, ch_len);
    c->transcript_len = ch_len;

    /* ---- Wrap in CRYPTO frame ---- */
    quic_frame_t f;
    quic_frame_make_crypto(&f, 0, ch, ch_len);

    uint8_t payload[2048];
    int plen = quic_frame_encode(&f, payload, sizeof(payload));
    if (plen < 0) { QUIC_TRACE("crypto frame encode failed"); return -1; }

    /* Pad payload to ensure the datagram is at least 1200 bytes
     * (RFC 9000 §14.1). Padding is PADDING frames (0x00 bytes). */
    size_t total_payload = (size_t)plen;
    /* Calculate the size header will be, then pad to 1200 total */
    uint8_t header[128];
    /* Rough header size: 1+4+1+8+1+8+1+2+4 = 30 bytes. */
    size_t approx_header = 30;
    size_t min_payload = 1200 - approx_header - 16;   /* -16 for tag */
    if (total_payload < min_payload) {
        memset(payload + total_payload, 0x00,
               min_payload - total_payload);
        total_payload = min_payload;
    }

    /* ---- Build long header (Initial) ---- */
    quic_long_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = CRISPTLS_QUIC_V1;
    hdr.dcid_len = c->dcid_len;
    memcpy(hdr.dcid, c->dcid, c->dcid_len);
    hdr.scid_len = c->scid_len;
    memcpy(hdr.scid, c->scid, c->scid_len);
    hdr.has_token = 1;
    hdr.token_len = 0;
    hdr.token = NULL;
    hdr.pn_len = 4;
    hdr.packet_number = (uint32_t)c->initial.next_pn;
    hdr.length = hdr.pn_len + total_payload + 16;

    int hlen = quic_long_hdr_encode(&hdr, header, sizeof(header));
    if (hlen < 0) { QUIC_TRACE("long hdr encode failed"); return -1; }

    /* ---- AEAD encrypt payload with header as AAD ---- */
    uint8_t ct[2048];
    uint8_t tag[16];
    crisptls_quic_dir_keys_t txk;
    memset(&txk, 0, sizeof(txk));
    memcpy(txk.packet_key, c->initial.tx_key, c->initial.tx_key_len);
    memcpy(txk.packet_iv,  c->initial.tx_iv,  12);
    memcpy(txk.hp_key,     c->initial.tx_hp,  c->initial.tx_key_len);
    txk.key_len = c->initial.tx_key_len;
    if (crisptls_quic_packet_encrypt(&txk, 0x1301, c->initial.next_pn,
                                     header, (size_t)hlen,
                                     payload, total_payload, ct, tag) != 0) {
        QUIC_TRACE("aead failed");
        return -1;
    }

    /* ---- Assemble full packet ---- */
    uint8_t packet[2048];
    size_t off = 0;
    memcpy(packet + off, header, (size_t)hlen); off += (size_t)hlen;
    memcpy(packet + off, ct, total_payload); off += total_payload;
    memcpy(packet + off, tag, 16); off += 16;

    /* ---- Apply header protection ---- */
    size_t pn_offset = (size_t)hlen - hdr.pn_len;
    size_t sample_off = pn_offset + 4;
    uint8_t sample[16];
    memcpy(sample, packet + sample_off, 16);

    crisptls_quic_apply_hp(c->initial.tx_hp, 0x1301,
                            packet, packet + pn_offset,
                            hdr.pn_len, sample, 1);

    /* ---- Send ---- */
    fprintf(stderr, "[quic] send_initial hex (first 40): ");
    for (size_t _i = 0; _i < 40 && _i < off; _i++)
        fprintf(stderr, "%02x", packet[_i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[quic] send_initial total = %zu bytes\n", off);
    int sent = quic_udp_send(&c->udp, packet, off);
    QUIC_TRACE("sent Initial: %d bytes", sent);
    if (sent <= 0) return -1;

    c->initial.next_pn++;
    c->initial.send_count++;
    c->bytes_sent += off;
    c->state = QUIC_ST_INITIAL_SENT;
    return 0;
}

/* Handshake driver (stub for now) */

int quic_conn_process_datagram(quic_conn_t *c, const uint8_t *buf, size_t len) {
    if (!c || !buf) return -1;
    QUIC_TRACE("recv datagram: %zu bytes", len);
    c->bytes_recv += len;
    /* TODO: decrypt, dispatch frames, drive state */
    return 0;
}

int quic_conn_handshake(quic_conn_t *c, int timeout_ms) {
    if (!c) return -1;
    if (quic_conn_send_initial(c) != 0) return -1;

    uint8_t buf[2048];
    for (int i = 0; i < 20; i++) {
        int r = quic_udp_recv(&c->udp, buf, sizeof(buf), NULL, NULL);
        if (r > 0) {
            if (quic_conn_process_datagram(c, buf, (size_t)r) < 0)
                return -1;
        }
        if (c->state == QUIC_ST_ESTABLISHED) return 1;
        (void)timeout_ms;
    }
    return 0;
}
