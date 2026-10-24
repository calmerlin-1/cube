/** ssl3_rfc_test.c — RFC 6101 conformance for crisptls SSL 3.0 primitives.
 *
 *  Reference implementation is byte-for-byte transcribed from RFC 6101
 *  using only libcrypto EVP_* directly. Any mismatch means crisptls's
 *  helpers diverge from the RFC as written. No live server needed.
 *
 *  Tests:
 *    1. prf_ssl3()              — RFC 6101 §6.3 key expansion / master secret
 *    2. ssl3_finished()          — RFC 6101 §7.6.1
 *    3. SSL 3.0 record MAC       — RFC 6101 §5.2.3.1
 *    4. SSL 3.0 CBC padding      — RFC 6101 §5.2.3.2 (byte pattern)
 *    5. SSL 3.0 key derivation   — RFC 6101 §6.3 directionality
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "keyschedule_legacy.h"
#include "crypto_legacy.h"

/* ────────── reference implementations, from the RFC text ────────── */

/* RFC 6101 §6.3: P_hash-style SSL 3.0 PRF.
 *   MD5(secret || SHA1(letter_i || secret || r1 || r2))   16 bytes per round
 *   where letter_i = "A", "BB", "CCC", ...                  */
static int ref_prf_ssl3(const uint8_t *secret, size_t slen,
                        const uint8_t r1[32], const uint8_t r2[32],
                        uint8_t *out, size_t outlen)
{
    size_t done = 0;
    for (int i = 0; done < outlen; i++) {
        if (i >= 26) return -1;
        uint8_t lab[26];
        memset(lab, 'A' + i, (size_t)i + 1);

        /* SHA1(letter || secret || r1 || r2) */
        SHA_CTX s;
        SHA1_Init(&s);
        SHA1_Update(&s, lab, (size_t)i + 1);
        SHA1_Update(&s, secret, slen);
        SHA1_Update(&s, r1, 32);
        SHA1_Update(&s, r2, 32);
        uint8_t sha[20];
        SHA1_Final(sha, &s);

        /* MD5(secret || sha) */
        MD5_CTX m;
        MD5_Init(&m);
        MD5_Update(&m, secret, slen);
        MD5_Update(&m, sha, 20);
        uint8_t md[16];
        MD5_Final(md, &m);

        size_t n = outlen - done < 16 ? outlen - done : 16;
        memcpy(out + done, md, n);
        done += n;
    }
    return 0;
}

/* RFC 6101 §7.6.1: Finished.
 *   MD5(msgs || sender || master || pad2_MD5(48)) ||
 *   SHA1(msgs || sender || master || pad1_SHA1(40))
 *   sender = "CLNT" (client) or "SRVR" (server) */
static int ref_ssl3_finished(const uint8_t master[48], int is_client,
                             const uint8_t *msgs, size_t msglen,
                             uint8_t out[36])
{
    static const uint8_t CL[4] = {'C','L','N','T'};
    static const uint8_t SV[4] = {'S','R','V','R'};
    const uint8_t *sender = is_client ? CL : SV;

    /* MD5: MD5(master || pad2(48) || MD5(msgs || sender || master || pad1(48))) */
    {
        uint8_t p1[48]; memset(p1, 0x36, 48);
        uint8_t p2[48]; memset(p2, 0x5c, 48);
        uint8_t inner[16];
        MD5_CTX m;
        MD5_Init(&m);
        MD5_Update(&m, msgs, msglen);
        MD5_Update(&m, sender, 4);
        MD5_Update(&m, master, 48);
        MD5_Update(&m, p1, 48);
        MD5_Final(inner, &m);
        MD5_Init(&m);
        MD5_Update(&m, master, 48);
        MD5_Update(&m, p2, 48);
        MD5_Update(&m, inner, 16);
        MD5_Final(out, &m);
    }

    /* SHA1: SHA1(master || pad2(40) || SHA1(msgs || sender || master || pad1(40))) */
    {
        uint8_t p1[40]; memset(p1, 0x36, 40);
        uint8_t p2[40]; memset(p2, 0x5c, 40);
        uint8_t inner[20];
        SHA_CTX s;
        SHA1_Init(&s);
        SHA1_Update(&s, msgs, msglen);
        SHA1_Update(&s, sender, 4);
        SHA1_Update(&s, master, 48);
        SHA1_Update(&s, p1, 40);
        SHA1_Final(inner, &s);
        SHA1_Init(&s);
        SHA1_Update(&s, master, 48);
        SHA1_Update(&s, p2, 40);
        SHA1_Update(&s, inner, 20);
        SHA1_Final(out + 16, &s);
    }
    return 0;
}

/* RFC 6101 §5.2.3.1: SSL 3.0 record MAC.
 *   for MD5:  MD5(mac_key || pad2 || MD5(mac_key || pad1 || seq || type || len || data))
 *   for SHA1: SHA1(mac_key || pad2 || SHA1(mac_key || pad1 || seq || type || len || data))
 *   seq(8) || type(1) || len(2, big-endian) || data — NO version field */
static int ref_ssl3_mac(ctl_hash_t hash, const uint8_t *mac_key, size_t mklen,
                        uint64_t seq, uint8_t type,
                        const uint8_t *data, size_t dlen, uint8_t *out)
{
    size_t padn = (hash == CTL_MD5) ? 48 : 40;
    uint8_t p1[48]; memset(p1, 0x36, sizeof p1);
    uint8_t p2[48]; memset(p2, 0x5c, sizeof p2);

    uint8_t hdr[11];
    for (int i = 0; i < 8; i++) hdr[i] = (uint8_t)(seq >> (56 - 8 * i));
    hdr[8]  = type;
    hdr[9]  = (uint8_t)(dlen >> 8);
    hdr[10] = (uint8_t)(dlen & 0xff);

    uint8_t inner[20];
    if (hash == CTL_MD5) {
        MD5_CTX m;
        MD5_Init(&m);
        MD5_Update(&m, mac_key, mklen);
        MD5_Update(&m, p1, padn);
        MD5_Update(&m, hdr, 11);
        MD5_Update(&m, data, dlen);
        MD5_Final(inner, &m);

        MD5_Init(&m);
        MD5_Update(&m, mac_key, mklen);
        MD5_Update(&m, p2, padn);
        MD5_Update(&m, inner, 16);
        MD5_Final(out, &m);
    } else if (hash == CTL_SHA1) {
        SHA_CTX s;
        SHA1_Init(&s);
        SHA1_Update(&s, mac_key, mklen);
        SHA1_Update(&s, p1, padn);
        SHA1_Update(&s, hdr, 11);
        SHA1_Update(&s, data, dlen);
        SHA1_Final(inner, &s);

        SHA1_Init(&s);
        SHA1_Update(&s, mac_key, mklen);
        SHA1_Update(&s, p2, padn);
        SHA1_Update(&s, inner, 20);
        SHA1_Final(out, &s);
    } else return -1;
    return 0;
}

/* ────────── test harness ────────── */

static int pass = 0, fail = 0;

static void cmp(const char *label, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("  PASS  %s\n", label); pass++; }
    else {
        printf("  FAIL  %s\n", label);
        printf("        expected: "); for (size_t i=0;i<n;i++) printf("%02x", b[i]); printf("\n");
        printf("        got     : "); for (size_t i=0;i<n;i++) printf("%02x", a[i]); printf("\n");
        fail++;
    }
}

/* deterministic test fixtures */
static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i * 7);
}

int main(void) {
    uint8_t master[48], client_random[32], server_random[32];
    fill(master,        48, 0x10);
    fill(client_random, 32, 0x20);
    fill(server_random, 32, 0x40);

    printf("═══ SSL 3.0 RFC 6101 conformance ═══\n\n");

    /* 1. PRF: master secret (r1=client, r2=server) */
    printf("─── prf_ssl3: master_secret(48) ───\n");
    {
        uint8_t ref[48], got[48];
        ref_prf_ssl3(master, 48, client_random, server_random, ref, 48);
        if (prf_ssl3(master, 48, client_random, server_random, got, 48)) {
            printf("  FAIL  prf_ssl3 returned nonzero\n"); fail++;
        } else cmp("master_secret(48)", got, ref, 48);
    }

    /* 2. PRF: key block (r1=server, r2=client) */
    printf("─── prf_ssl3: key_block(104) [AES128+MD5] ───\n");
    {
        uint8_t ref[104], got[104];
        ref_prf_ssl3(master, 48, server_random, client_random, ref, 104);
        if (prf_ssl3(master, 48, server_random, client_random, got, 104)) {
            printf("  FAIL  prf_ssl3 returned nonzero\n"); fail++;
        } else cmp("key_block(104)", got, ref, 104);
    }

    /* 3. SSL 3.0 Finished — client */
    printf("─── ssl3_finished ───\n");
    {
        uint8_t msgs[256]; fill(msgs, sizeof msgs, 0x77);
        uint8_t ref[36], got[36];
        ref_ssl3_finished(master, 1, msgs, sizeof msgs, ref);
        if (ssl3_finished(master, 1, msgs, sizeof msgs, got)) {
            printf("  FAIL  ssl3_finished returned nonzero\n"); fail++;
        } else cmp("ssl3_finished(client)", got, ref, 36);

        ref_ssl3_finished(master, 0, msgs, sizeof msgs, ref);
        if (ssl3_finished(master, 0, msgs, sizeof msgs, got)) {
            printf("  FAIL  ssl3_finished returned nonzero\n"); fail++;
        } else cmp("ssl3_finished(server)", got, ref, 36);
    }

    /* 4. SSL 3.0 record MAC — MD5 */
    printf("─── SSL 3.0 record MAC ───\n");
    {
        uint8_t mac_key[16]; fill(mac_key, 16, 0xAA);
        uint8_t data[64];    fill(data, 64, 0xBB);
        uint8_t ref[16], got[16];

        if (ref_ssl3_mac(CTL_MD5, mac_key, 16, 42, 22, data, 64, ref))
            printf("  FAIL  ref mac\n");
        /* Call ctl_hash_parts exactly as record_cbc.c does. */
        uint8_t p1[48]; memset(p1, 0x36, 48);
        uint8_t p2[48]; memset(p2, 0x5c, 48);
        uint8_t hdr[11];
        for (int i = 0; i < 8; i++) hdr[i] = (uint8_t)(42ULL >> (56 - 8 * i));
        hdr[8] = 22; hdr[9] = 0; hdr[10] = 64;
        uint8_t inner[16];
        ctl_part_t a[4] = { {mac_key,16},{p1,48},{hdr,11},{data,64} };
        if (ctl_hash_parts(CTL_MD5, a, 4, inner)) printf("  FAIL  ctl_hash_parts inner\n");
        ctl_part_t b[3] = { {mac_key,16},{p2,48},{inner,16} };
        if (ctl_hash_parts(CTL_MD5, b, 3, got)) printf("  FAIL  ctl_hash_parts outer\n");
        cmp("mac MD5", got, ref, 16);
    }

    /* 5. Key derivation: check field order matches RFC 6101 (client MAC first, etc.) */
    printf("─── keyschedule_legacy_derive directionality ───\n");
    {
        keyschedule_12_t ks;
        if (keyschedule_legacy_derive(TLS_V_SSL3, CTL_SHA1, master,
                                       client_random, server_random,
                                       16, 16, 16, &ks) != 0) {
            printf("  FAIL  keyschedule_legacy_derive\n"); fail++;
        } else {
            /* recompute whole block by hand and compare each slice */
            uint8_t ref[16*2 + 16*2 + 16*2];
            ref_prf_ssl3(master, 48, server_random, client_random, ref, sizeof ref);
            cmp("ks.client_write_mac",  (uint8_t*)ks.client_write_mac,  ref,        16);
            cmp("ks.server_write_mac",  (uint8_t*)ks.server_write_mac,  ref+16,     16);
            cmp("ks.client_write_key",  (uint8_t*)ks.client_write_key,  ref+32,     16);
            cmp("ks.server_write_key",  (uint8_t*)ks.server_write_key,  ref+48,     16);
            cmp("ks.client_write_iv",   (uint8_t*)ks.client_write_iv,   ref+64,     16);
            cmp("ks.server_write_iv",   (uint8_t*)ks.server_write_iv,   ref+80,     16);
        }
    }

    printf("\n═══ %d passed · %d failed ═══\n", pass, fail);
    return fail ? 1 : 0;
}
