/** crisptls_quic.h — QUIC-specific key derivation (RFC 9001 §5).
 *
 * QUIC reuses TLS 1.3's HKDF schedule, but derives keys with QUIC-specific
 * labels and applies them per-packet (no TLS record layer).
 *
 * The client and server both derive:
 *   - Initial secrets  — from the Destination Connection ID + version
 *   - Handshake secrets — from the TLS handshake secret (via CRYPTO frames)
 *   - 1-RTT (application) secrets
 *
 * Each direction (client→server, server→client) has:
 *   - packet protection key  (16 or 32 bytes)
 *   - packet protection IV   (12 bytes)
 *   - header protection key  (16 or 32 bytes)
 *
 * Uses the same crypto backend as crisptls (OpenSSL EVP via crypto.h).
 * This header exposes only the derivation; actual packet encryption lives
 * in net/quic/.
 */

#ifndef CRISPTLS_QUIC_H
#define CRISPTLS_QUIC_H

#include <stddef.h>
#include <stdint.h>

/* ---- QUIC v1 (RFC 9000) ---- */
#define CRISPTLS_QUIC_V1  0x00000001

/* Initial salt for QUIC v1 (RFC 9001 §5.2). */
extern const uint8_t CRISPTLS_QUIC_V1_INITIAL_SALT[20];

/* One direction's keys. */
typedef struct {
    uint8_t  packet_key[32];    /* AEAD key */
    uint8_t  packet_iv[12];     /* AEAD nonce base */
    uint8_t  hp_key[32];        /* header protection key */
    size_t   key_len;           /* 16 or 32 */
} crisptls_quic_dir_keys_t;

/* Result of deriving keys from one secret. */
typedef struct {
    crisptls_quic_dir_keys_t client;    /* client→server */
    crisptls_quic_dir_keys_t server;    /* server→client */
} crisptls_quic_keys_t;

/* ---- Initial secrets (RFC 9001 §5.2) ----
 *
 * initial_secret = HKDF-Extract(initial_salt, dcid)
 * client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
 * server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
 *
 * `dcid` = Destination Connection ID from the client's first Initial packet.
 * `dcid_len` = its length (usually 8).
 * `version` = QUIC version (use CRISPTLS_QUIC_V1).
 */
int crisptls_quic_derive_initial(const uint8_t *dcid, size_t dcid_len,
                                 uint32_t version,
                                 crisptls_quic_keys_t *out);

/* ---- Keys from a TLS 1.3 traffic secret (RFC 9001 §5.1) ----
 *
 * Given a TLS 1.3 traffic secret (32 bytes for SHA-256, 48 for SHA-384),
 * derive QUIC keys with labels:
 *   "quic key", "quic iv", "quic hp"
 *
 * `cipher_suite` selects SHA-256 vs SHA-384:
 *   0x1301 = TLS_AES_128_GCM_SHA256       → SHA-256, key_len = 16
 *   0x1302 = TLS_AES_256_GCM_SHA384       → SHA-384, key_len = 32
 *   0x1303 = TLS_CHACHA20_POLY1305_SHA256 → SHA-256, key_len = 32
 */
int crisptls_quic_derive_dir(const uint8_t *secret, size_t secret_len,
                             uint16_t cipher_suite,
                             crisptls_quic_dir_keys_t *out);

/* ---- Packet protection (RFC 9001 §5.3) ----
 *
 * AEAD-encrypt the packet with:
 *   nonce = iv XOR packet_number (last 8 bytes)
 *   AAD   = the packet header (with unprotected length)
 */
int crisptls_quic_packet_encrypt(const crisptls_quic_dir_keys_t *keys,
                                 uint16_t cipher_suite,
                                 uint64_t packet_number,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, uint8_t tag[16]);

int crisptls_quic_packet_decrypt(const crisptls_quic_dir_keys_t *keys,
                                 uint16_t cipher_suite,
                                 uint64_t packet_number,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[16],
                                 uint8_t *pt);

/* ---- Header protection (RFC 9001 §5.4) ----
 *
 * sample = first 16 bytes of ciphertext starting at offset
 *          (packet_number_offset + 4).
 *
 * For AES ciphers:
 *    mask = AES-ECB(hp_key, sample)
 * For ChaCha20:
 *    counter = sample[0..3] (LE uint32)
 *    mask = ChaCha20(hp_key, counter, sample[4..15])
 *           (16-byte keystream for first byte, 5 bytes for the rest)
 *
 * Then:
 *    first_byte ^= mask[0] & 0x0f (long header) or 0x1f (short header)
 *    packet_number_bytes ^= mask[1..pn_len]
 */

/* Apply header protection in place.
 * `first_byte` — pointer to the first byte of the packet header.
 * `pn_offset`  — byte offset of the packet number field in the packet.
 * `pn_len`     — 1..4 bytes of packet number on the wire.
 * `sample`     — 16-byte sample starting at pn_offset + 4.
 * `long_header` — 1 if this is a long header packet (Initial/Handshake/0-RTT).
 */
int crisptls_quic_apply_hp(const uint8_t *hp_key,
                            uint16_t cipher_suite,
                            uint8_t *first_byte,
                            uint8_t *pn_bytes, size_t pn_len,
                            const uint8_t sample[16],
                            int long_header);

/* Remove header protection (same operation, symmetric). */
int crisptls_quic_remove_hp(const uint8_t *hp_key,
                             uint16_t cipher_suite,
                             uint8_t *first_byte,
                             uint8_t *pn_bytes, size_t pn_len,
                             const uint8_t sample[16],
                             int long_header);

#endif /* CRISPTLS_QUIC_H */
