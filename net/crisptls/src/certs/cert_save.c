/** cert_save.c — PEM + JSON persistence of peer certs. */

#include "cert_save.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

/** Base64 encode (RFC 4648) for PEM. */
static size_t base64_encode(const uint8_t *in, size_t in_len,
                            char *out, size_t out_cap) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t w = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        if (w + 4 > out_cap) break;
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i+2];
        out[w++] = b64[(v >> 18) & 0x3F];
        out[w++] = b64[(v >> 12) & 0x3F];
        out[w++] = (i + 1 < in_len) ? b64[(v >> 6) & 0x3F] : '=';
        out[w++] = (i + 2 < in_len) ? b64[v & 0x3F] : '=';
    }
    out[w] = '\0';
    return w;
}

size_t cert_der_to_pem(const uint8_t *der, size_t der_len,
                       char *out, size_t out_cap) {
    size_t w = 0;
    const char *header = "-----BEGIN CERTIFICATE-----\n";
    const char *footer = "-----END CERTIFICATE-----\n";
    size_t hl = strlen(header);
    size_t fl = strlen(footer);
    if (hl + fl + 256 > out_cap) return 0;
    memcpy(out + w, header, hl); w += hl;

    /* base64 encode in one shot, then wrap at 64 chars */
    char b64buf[16384];
    size_t b64_len = base64_encode(der, der_len, b64buf, sizeof(b64buf));

    for (size_t i = 0; i < b64_len; i++) {
        if (w + 1 > out_cap - fl - 1) break;
        out[w++] = b64buf[i];
        if ((i + 1) % 64 == 0 && i + 1 < b64_len) {
            if (w + 1 > out_cap - fl - 1) break;
            out[w++] = '\n';
        }
    }
    if (w > hl && out[w-1] != '\n') out[w++] = '\n';
    memcpy(out + w, footer, fl); w += fl;
    out[w] = '\0';
    return w;
}

/** Compute SHA-256 fingerprint, lowercase hex, colon-separated. */
static void cert_fingerprint(const uint8_t *der, size_t der_len, char *out, size_t cap) {
    uint8_t hash[32];
    ct_sha256(der, der_len, hash);
    size_t w = 0;
    for (int i = 0; i < 32 && w + 4 < cap; i++) {
        w += (size_t)snprintf(out + w, cap - w, "%s%02x", i ? ":" : "", hash[i]);
    }
}

/** Create directory, ignoring if exists. */
static int ensure_dir(const char *path) {
    if (mkdir(path, 0755) == 0) return 0;
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    return -1;
}

int cert_save(const char *cert_dir, const char *hostname,
              const uint8_t *der, size_t der_len) {
    return cert_save_chain(cert_dir, hostname, &der, &der_len, 1);
}

int cert_save_chain(const char *cert_dir, const char *hostname,
                    const uint8_t **ders, const size_t *der_lens, size_t count) {
    if (!cert_dir || !hostname || !ders || count == 0) return -1;
    ensure_dir(cert_dir);

    /* PEM file: all certs concatenated */
    char pem_path[512];
    snprintf(pem_path, sizeof(pem_path), "%s/%s.pem", cert_dir, hostname);
    FILE *fp = fopen(pem_path, "w");
    if (!fp) return -1;
    for (size_t i = 0; i < count; i++) {
        char pem[16384];
        size_t pl = cert_der_to_pem(ders[i], der_lens[i], pem, sizeof(pem));
        if (pl) fwrite(pem, 1, pl, fp);
    }
    fclose(fp);

    /* JSON metadata sidecar */
    char json_path[512];
    snprintf(json_path, sizeof(json_path), "%s/%s.json", cert_dir, hostname);
    FILE *jf = fopen(json_path, "w");
    if (!jf) return 0;   /* PEM already saved; JSON optional */
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

    fprintf(jf, "{\n");
    fprintf(jf, "  \"hostname\": \"%s\",\n", hostname);
    fprintf(jf, "  \"observed_at\": \"%s\",\n", ts);
    fprintf(jf, "  \"chain_length\": %zu,\n", count);
    fprintf(jf, "  \"certificates\": [\n");
    for (size_t i = 0; i < count; i++) {
        char fp[128];
        cert_fingerprint(ders[i], der_lens[i], fp, sizeof(fp));
        fprintf(jf, "    {\n");
        fprintf(jf, "      \"index\": %zu,\n", i);
        fprintf(jf, "      \"role\": \"%s\",\n", i == 0 ? "leaf" : "intermediate");
        fprintf(jf, "      \"der_len\": %zu,\n", der_lens[i]);
        fprintf(jf, "      \"sha256\": \"%s\"\n", fp);
        fprintf(jf, "    }%s\n", (i + 1 < count) ? "," : "");
    }
    fprintf(jf, "  ]\n");
    fprintf(jf, "}\n");
    fclose(jf);
    return 0;
}
