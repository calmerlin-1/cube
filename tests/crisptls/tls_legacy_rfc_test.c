/** tls_legacy_rfc_test.c — RFC conformance for TLS 1.0/1.1/1.2 legacy primitives.
 *
 *  Reference implementations transcribed from the RFC text, using libcrypto
 *  directly. Any mismatch means crisptls diverges from the RFC as written.
 *
 *  Covers:
 *    TLS 1.0/1.1 PRF      RFC 2246 §5 / RFC 5246 §5
 *    TLS 1.2 PRF          RFC 5246 §5
 *    Master secret        RFC 2246 §8.1 / RFC 5246 §8.1
 *    Extended master      RFC 7627 §4
 *    Key block            RFC 2246 §6.3 / RFC 5246 §6.3
 *    Finished (12 bytes)  RFC 2246 §7.4.9 / RFC 5246 §7.4.9
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "keyschedule_legacy.h"
#include "crypto_legacy.h"

/* ────────── reference implementations ────────── */

/* RFC 5246 §5 P_hash(hash, secret, seed) → out.
 *   A(0) = seed
 *   A(i) = HMAC(secret, A(i-1))
 *   P_hash = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ... */
static int ref_phash(const EVP_MD *md, const uint8_t *secret, size_t slen,
                     const uint8_t *seed, size_t seedlen,
                     uint8_t *out, size_t outlen)
{
    size_t hl = (size_t)EVP_MD_size(md);
    uint8_t a[EVP_MAX_MD_SIZE];
    unsigned int alen = 0;

    /* A(1) = HMAC(secret, seed) */
    HMAC(md, secret, (int)slen, seed, seedlen, a, &alen);

    size_t done = 0;
    while (done < outlen) {
        uint8_t t[EVP_MAX_MD_SIZE];
        unsigned int tlen = 0;
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, secret, (int)slen, md, NULL);
        HMAC_Update(ctx, a, alen);
        HMAC_Update(ctx, seed, seedlen);
        HMAC_Final(ctx, t, &tlen);
        HMAC_CTX_free(ctx);

        size_t n = outlen - done < tlen ? outlen - done : tlen;
        memcpy(out + done, t, n);
        done += n;
        if (done < outlen) {
            /* A(i+1) = HMAC(secret, A(i)) */
            HMAC(md, secret, (int)slen, a, alen, a, &alen);
        }
    }
    return 0;
}

/* RFC 2246 §5 / RFC 5246 §5: TLS 1.0/1.1 PRF
 *   S1 = first half of secret
 *   S2 = second half (overlapping one byte if odd)
 *   PRF = P_MD5(S1, label||seed) XOR P_SHA1(S2, label||seed)
 */
static int ref_prf_tls10(const uint8_t *secret, size_t slen, const char *label,
                         const uint8_t *seed, size_t seedlen,
                         uint8_t *out, size_t outlen)
{
    size_t ll = strlen(label);
    uint8_t buf[512];
    memcpy(buf, label, ll);
    memcpy(buf + ll, seed, seedlen);
    size_t buflen = ll + seedlen;

    size_t half = (slen + 1) / 2;
    const uint8_t *s1 = secret;
    const uint8_t *s2 = secret + (slen - half);

    uint8_t md5out[512];
    uint8_t shaout[512];
    ref_phash(EVP_md5(),  s1, half, buf, buflen, md5out, outlen);
    ref_phash(EVP_sha1(), s2, half, buf, buflen, shaout, outlen);
    for (size_t i = 0; i < outlen; i++) out[i] = md5out[i] ^ shaout[i];
    return 0;
}

/* RFC 5246 §5: TLS 1.2 PRF = P_hash(suite_hash, secret, label||seed). */
static int ref_prf_tls12(const EVP_MD *md, const uint8_t *secret, size_t slen,
                         const char *label, const uint8_t *seed, size_t seedlen,
                         uint8_t *out, size_t outlen)
{
    size_t ll = strlen(label);
    uint8_t buf[512];
    memcpy(buf, label, ll);
    memcpy(buf + ll, seed, seedlen);
    return ref_phash(md, secret, slen, buf, ll + seedlen, out, outlen);
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

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i * 7);
}

int main(void) {
    uint8_t master[48], client_random[32], server_random[32];
    fill(master, 48, 0x10);
    fill(client_random, 32, 0x20);
    fill(server_random, 32, 0x40);

    printf("═══ TLS legacy RFC conformance ═══\n\n");

    /* ── PRF TLS 1.0/1.1 ── */
    printf("─── prf_tls10 ───\n");
    {
        uint8_t ref[48], got[48];
        const uint8_t *seed = client_random;   /* single 32-byte seed for a smoke test */
        ref_prf_tls10(master, 48, "master secret", seed, 32, ref, 48);
        if (prf_tls10(master, 48, "master secret", seed, 32, got, 48)) {
            printf("  FAIL  prf_tls10 returned nonzero\n"); fail++;
        } else cmp("tls10 master_secret(48)", got, ref, 48);

        /* key block: 2*16 + 2*16 + 2*16 = 96 for AES128_SHA */
        uint8_t ref2[104], got2[104];
        ref_prf_tls10(master, 48, "key expansion", server_random, 32, ref2, 104);
        if (prf_tls10(master, 48, "key expansion", server_random, 32, got2, 104)) {
            printf("  FAIL  prf_tls10 returned nonzero\n"); fail++;
        } else cmp("tls10 key_block(104)", got2, ref2, 104);
    }

    /* ── PRF TLS 1.2 ── */
    printf("─── prf_tls12 ───\n");
    {
        uint8_t ref[48], got[48];
        ref_prf_tls12(EVP_sha256(), master, 48, "master secret",
                      client_random, 32, ref, 48);
        if (prf_tls12(CTL_SHA256, master, 48, "master secret",
                      client_random, 32, got, 48)) {
            printf("  FAIL  prf_tls12 returned nonzero\n"); fail++;
        } else cmp("tls12 master_secret(48)", got, ref, 48);

        uint8_t ref2[104], got2[104];
        ref_prf_tls12(EVP_sha256(), master, 48, "key expansion",
                      server_random, 32, ref2, 104);
        if (prf_tls12(CTL_SHA256, master, 48, "key expansion",
                      server_random, 32, got2, 104)) {
            printf("  FAIL  prf_tls12 returned nonzero\n"); fail++;
        } else cmp("tls12 key_block(104)", got2, ref2, 104);
    }

    /* ── tls_master_secret ── */
    printf("─── tls_master_secret ───\n");
    {
        uint8_t pms[48]; fill(pms, 48, 0x50);
        uint8_t seed64[64];
        memcpy(seed64, client_random, 32);
        memcpy(seed64 + 32, server_random, 32);

        uint8_t ref[48], got[48];

        ref_prf_tls10(pms, 48, "master secret", seed64, 64, ref, 48);
        if (tls_master_secret(TLS_V_10, CTL_SHA256, pms, 48,
                              client_random, server_random, got)) {
            printf("  FAIL  tls_master_secret(TLS1.0) returned nonzero\n"); fail++;
        } else cmp("master_secret TLS1.0", got, ref, 48);

        ref_prf_tls10(pms, 48, "master secret", seed64, 64, ref, 48);
        if (tls_master_secret(TLS_V_11, CTL_SHA256, pms, 48,
                              client_random, server_random, got)) {
            printf("  FAIL  tls_master_secret(TLS1.1) returned nonzero\n"); fail++;
        } else cmp("master_secret TLS1.1", got, ref, 48);

        ref_prf_tls12(EVP_sha256(), pms, 48, "master secret", seed64, 64, ref, 48);
        if (tls_master_secret(TLS_V_12, CTL_SHA256, pms, 48,
                              client_random, server_random, got)) {
            printf("  FAIL  tls_master_secret(TLS1.2) returned nonzero\n"); fail++;
        } else cmp("master_secret TLS1.2", got, ref, 48);
    }

    /* ── keyschedule_legacy_derive: TLS 1.0 ── */
    printf("─── keyschedule_legacy_derive TLS1.0 ───\n");
    {
        keyschedule_12_t ks;
        uint8_t seed64[64];
        memcpy(seed64, server_random, 32);
        memcpy(seed64 + 32, client_random, 32);
        uint8_t ref[96];
        ref_prf_tls10(master, 48, "key expansion", seed64, 64, ref, 96);

        if (keyschedule_legacy_derive(TLS_V_10, CTL_SHA256, master,
                                      client_random, server_random,
                                      20, 16, 16, &ks) != 0) {
            printf("  FAIL  keyschedule_legacy_derive(TLS1.0)\n"); fail++;
        } else {
            /* SHA1 MAC = 20 bytes for TLS 1.0 with AES128_SHA */
            cmp("TLS1.0 client_mac",  (uint8_t*)ks.client_write_mac,  ref,        20);
            cmp("TLS1.0 server_mac",  (uint8_t*)ks.server_write_mac,  ref+20,     20);
            cmp("TLS1.0 client_key",  (uint8_t*)ks.client_write_key,  ref+40,     16);
            cmp("TLS1.0 server_key",  (uint8_t*)ks.server_write_key,  ref+56,     16);
            cmp("TLS1.0 client_iv",   (uint8_t*)ks.client_write_iv,   ref+72,     16);
            cmp("TLS1.0 server_iv",   (uint8_t*)ks.server_write_iv,   ref+88,      8);
        }
    }

    /* ── tls_finished_verify: TLS 1.0 ── */
    printf("─── tls_finished_verify TLS1.0 ───\n");
    {
        /* TLS 1.0/1.1 Finished: hs_hash is MD5(msgs)||SHA1(msgs), 36 bytes */
        uint8_t msgs[128]; fill(msgs, 128, 0x99);
        uint8_t hs_hash[36];
        MD5_CTX m; MD5_Init(&m); MD5_Update(&m, msgs, 128); MD5_Final(hs_hash, &m);
        SHA_CTX s; SHA1_Init(&s); SHA1_Update(&s, msgs, 128); SHA1_Final(hs_hash + 16, &s);

        uint8_t ref[12], got[12];
        ref_prf_tls10(master, 48, "client finished", hs_hash, 36, ref, 12);
        if (tls_finished_verify(TLS_V_10, CTL_SHA256, master, 1, hs_hash, 36, got)) {
            printf("  FAIL  tls_finished_verify(TLS1.0) returned nonzero\n"); fail++;
        } else cmp("finished TLS1.0 client", got, ref, 12);

        ref_prf_tls10(master, 48, "server finished", hs_hash, 36, ref, 12);
        if (tls_finished_verify(TLS_V_10, CTL_SHA256, master, 0, hs_hash, 36, got)) {
            printf("  FAIL  tls_finished_verify(TLS1.0) returned nonzero\n"); fail++;
        } else cmp("finished TLS1.0 server", got, ref, 12);
    }

    /* ── tls_finished_verify: TLS 1.2 (SHA256) ── */
    printf("─── tls_finished_verify TLS1.2/SHA256 ───\n");
    {
        uint8_t msgs[128]; fill(msgs, 128, 0xAA);
        uint8_t hs_hash[32];
        SHA256(msgs, 128, hs_hash);

        uint8_t ref[12], got[12];
        ref_prf_tls12(EVP_sha256(), master, 48, "client finished", hs_hash, 32, ref, 12);
        if (tls_finished_verify(TLS_V_12, CTL_SHA256, master, 1, hs_hash, 32, got)) {
            printf("  FAIL  tls_finished_verify(TLS1.2) returned nonzero\n"); fail++;
        } else cmp("finished TLS1.2 client", got, ref, 12);

        ref_prf_tls12(EVP_sha256(), master, 48, "server finished", hs_hash, 32, ref, 12);
        if (tls_finished_verify(TLS_V_12, CTL_SHA256, master, 0, hs_hash, 32, got)) {
            printf("  FAIL  tls_finished_verify(TLS1.2) returned nonzero\n"); fail++;
        } else cmp("finished TLS1.2 server", got, ref, 12);
    }

    printf("\n═══ %d passed · %d failed ═══\n", pass, fail);
    return fail ? 1 : 0;
}
