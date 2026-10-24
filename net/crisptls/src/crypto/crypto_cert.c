/** crypto_cert.c — RFC 5280 chain validation + RFC 6125 hostname verify. */

#include "crypto_cert.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
    return NULL;
}

static STACK_OF(X509) *load_ca_bundle(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    STACK_OF(X509) *stack = sk_X509_new_null();
    if (!stack) { fclose(fp); return NULL; }
    X509 *cert = NULL;
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(stack, cert);
    }
    fclose(fp);
    ERR_clear_error();
    return stack;
}

static int is_self_signed(X509 *cert) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *iss  = X509_get_issuer_name(cert);
    if (!subj || !iss) return 0;
    if (X509_NAME_cmp(subj, iss) != 0) return 0;
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (!pk) return 0;
    int ok = X509_verify(cert, pk);
    EVP_PKEY_free(pk);
    return ok == 1;
}

static int is_signed_by(X509 *cert, X509 *issuer) {
    EVP_PKEY *pk = X509_get_pubkey(issuer);
    if (!pk) return 0;
    int ok = X509_verify(cert, pk);
    EVP_PKEY_free(pk);
    return ok == 1;
}
static int is_valid_now(X509 *cert) {
    return X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 &&
           X509_cmp_current_time(X509_get0_notAfter(cert))  > 0;
}

static int root_in_bundle(X509 *root, STACK_OF(X509) *bundle) {
    if (!bundle) return 0;
    X509_NAME *root_subj = X509_get_subject_name(root);
    if (!root_subj) return 0;
    for (int i = 0; i < sk_X509_num(bundle); i++) {
        X509 *ca = sk_X509_value(bundle, i);
        X509_NAME *ca_subj = X509_get_subject_name(ca);
        if (!ca_subj) continue;
        if (X509_NAME_cmp(root_subj, ca_subj) != 0) continue;
        EVP_PKEY *rk = X509_get_pubkey(root);
        EVP_PKEY *ck = X509_get_pubkey(ca);
        if (!rk || !ck) { EVP_PKEY_free(rk); EVP_PKEY_free(ck); continue; }
        int match = EVP_PKEY_eq(rk, ck) == 1;
        EVP_PKEY_free(rk);
        EVP_PKEY_free(ck);
        if (match) return 1;
    }
    return 0;
}

static int hostname_matches(X509 *leaf, const char *host) {
    if (!host || !*host) return 0;
    GENERAL_NAMES *sans = X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
    int has_san_dns = 0;
    if (sans) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type != GEN_DNS) continue;
            ASN1_IA5STRING *dns = gn->d.dNSName;
            if (!dns) continue;
            has_san_dns = 1;
            const unsigned char *p = ASN1_STRING_get0_data(dns);
            int len = ASN1_STRING_length(dns);
            char name[256];
            if (len <= 0 || len >= (int)sizeof(name)) continue;
            memcpy(name, p, (size_t)len);
            name[len] = 0;
            if (strcasecmp(name, host) == 0) { GENERAL_NAMES_free(sans); return 1; }
            if (name[0] == '*' && name[1] == '.') {
                const char *dot = strchr(host, '.');
                if (dot && strcasecmp(name + 1, dot) == 0) {
                    GENERAL_NAMES_free(sans); return 1;
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }
    if (!has_san_dns) {
        X509_NAME *subj = X509_get_subject_name(leaf);
        if (subj) {
            char cn[256];
            int n = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
            if (n > 0 && strcasecmp(cn, host) == 0) return 1;
        }
    }
    return 0;
}

int cert_verify_chain(const uint8_t *const *chain, const size_t *chain_lens, size_t n,
                      const char *host, const char *ca_bundle_path,
                      size_t *verified_chain_len_out) {
    if (!chain || n == 0 || !host) return CERT_ERR_ARGS;
    X509 *certs[16];
    size_t parsed = 0;
    for (size_t i = 0; i < n && i < 16; i++) {
        const unsigned char *p = chain[i];
        certs[parsed] = d2i_X509(NULL, &p, (long)chain_lens[i]);
        if (!certs[parsed]) {
            for (size_t j = 0; j < parsed; j++) X509_free(certs[j]);
            return CERT_ERR_PARSE;
        }
        parsed++;
    }
    int rc = CERT_OK;
    for (size_t i = 0; i < parsed; i++) {
        if (!is_valid_now(certs[i])) { rc = CERT_ERR_EXPIRED; goto done; }
    }
    for (size_t i = 0; i + 1 < parsed; i++) {
        if (!is_signed_by(certs[i], certs[i + 1])) { rc = CERT_ERR_SIG; goto done; }
    }
    const char *bundle_path = find_ca_bundle(ca_bundle_path);
    if (!bundle_path) { rc = CERT_ERR_CA_MISSING; goto done; }
    STACK_OF(X509) *ca = load_ca_bundle(bundle_path);
    if (!ca) { rc = CERT_ERR_CA_MISSING; goto done; }

    /* Accept the chain if ANY cert in it matches a trusted root in
     * subject+pubkey. This handles cross-signed roots: e.g., Google's
     * server sends "GTS Root R4 cross-signed by GlobalSign Root CA"
     * as an extra cert for old clients; modern clients use the
     * self-signed GTS Root R4 from the bundle directly. */
    X509 *last = certs[parsed - 1];

    int found = 0;

    /* Case 1: last is signed by some bundle root (classic chain walking).
     * Handles 2-cert chains (leaf + intermediate, root in bundle). */
    for (int i = 0; i < sk_X509_num(ca); i++) {
        if (is_signed_by(last, sk_X509_value(ca, i))) { found = 1; break; }
    }

    /* Case 2: any cert in the chain matches a bundle root in subject+pubkey.
     * Handles cross-signed roots where the TLS message contains an extra
     * cross-signed copy of the root (e.g., GTS Root R4 cross-signed by
     * GlobalSign Root CA, SSL.com TLS ECC Root CA 2022 cross-signed). */
    if (!found) {
        for (size_t idx = 0; idx < parsed && !found; idx++) {
            X509 *cand = certs[idx];
            X509_NAME *cand_subj = X509_get_subject_name(cand);
            EVP_PKEY *cand_pk = X509_get_pubkey(cand);
            if (!cand_subj || !cand_pk) { if (cand_pk) EVP_PKEY_free(cand_pk); continue; }
            for (int i = 0; i < sk_X509_num(ca); i++) {
                X509 *b = sk_X509_value(ca, i);
                X509_NAME *b_subj = X509_get_subject_name(b);
                if (!b_subj || X509_NAME_cmp(cand_subj, b_subj) != 0) continue;
                EVP_PKEY *b_pk = X509_get_pubkey(b);
                if (!b_pk) continue;
                int key_match = (EVP_PKEY_eq(cand_pk, b_pk) == 1);
                EVP_PKEY_free(b_pk);
                if (key_match) { found = 1; break; }
            }
            EVP_PKEY_free(cand_pk);
        }
    }

    if (!found) rc = CERT_ERR_CHAIN;
    if (rc != CERT_OK) goto done;
    if (!hostname_matches(certs[0], host)) { rc = CERT_ERR_HOST; goto done; }
    if (verified_chain_len_out) *verified_chain_len_out = parsed;
done:
    for (size_t i = 0; i < parsed; i++) X509_free(certs[i]);
    return rc;
}
