/** profile_gen.c — turn crypto_caps.txt into a policy file.
 *
 * Standalone. Not linked into libcrisptls.a. Does not affect the client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int has_aes, has_pmull, has_sha1_hw, has_sha2_hw, has_crc32;
    double aes128gcm_mbps, aes256gcm_mbps, chacha20_mbps;
    double sha256_mbps, sha384_mbps, hmac_sha256_mbps;
    double x25519_ops_per_sec;
    int prefer_aes_gcm, prefer_sha256;
} caps_t;

static int parse_caps(const char *path, caps_t *c) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(c, 0, sizeof *c);
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char key[64] = {0}; char val[128] = {0};
        if (sscanf(line, "%63s %127s", key, val) != 2) continue;
        if (!strcmp(key, "has_aes"))            c->has_aes = atoi(val);
        else if (!strcmp(key, "has_pmull"))     c->has_pmull = atoi(val);
        else if (!strcmp(key, "has_sha1_hw"))   c->has_sha1_hw = atoi(val);
        else if (!strcmp(key, "has_sha2_hw"))   c->has_sha2_hw = atoi(val);
        else if (!strcmp(key, "has_crc32"))     c->has_crc32 = atoi(val);
        else if (!strcmp(key, "aes128gcm_mbps")) c->aes128gcm_mbps = atof(val);
        else if (!strcmp(key, "aes256gcm_mbps")) c->aes256gcm_mbps = atof(val);
        else if (!strcmp(key, "chacha20_mbps"))  c->chacha20_mbps = atof(val);
        else if (!strcmp(key, "sha256_mbps"))    c->sha256_mbps = atof(val);
        else if (!strcmp(key, "sha384_mbps"))    c->sha384_mbps = atof(val);
        else if (!strcmp(key, "hmac_sha256_mbps")) c->hmac_sha256_mbps = atof(val);
        else if (!strcmp(key, "x25519_ops_per_sec")) c->x25519_ops_per_sec = atof(val);
        else if (!strcmp(key, "prefer_aes_gcm")) c->prefer_aes_gcm = atoi(val);
        else if (!strcmp(key, "prefer_sha256"))  c->prefer_sha256 = atoi(val);
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    const char *caps_path = argc > 1 ? argv[1] : "../cache/crypto_caps.txt";
    const char *out_path  = argc > 2 ? argv[2] : "../cache/policy.generated.txt";

    caps_t c;
    if (parse_caps(caps_path, &c) != 0) {
        fprintf(stderr, "profile_gen: cannot read %s\n", caps_path);
        return 2;
    }

    int aes_wins    = (c.aes128gcm_mbps > c.chacha20_mbps);
    int sha256_wins = (c.sha256_mbps > c.sha384_mbps);

    const char *tls13_order =
        aes_wins ? "0x1301 0x1302 0x1303" : "0x1303 0x1301 0x1302";

    const char *tls12_order =
        aes_wins
        ? "0xC02B 0xC02F 0xC02C 0xC030 0xCCA9 0xCCA8"
        : "0xCCA9 0xCCA8 0xC02B 0xC02F 0xC02C 0xC030";

    FILE *out = fopen(out_path, "w");
    if (!out) {
        fprintf(stderr, "profile_gen: cannot write %s\n", out_path);
        return 2;
    }

    fprintf(out, "# crisptls generated policy\n");
    fprintf(out, "# source: %s\n", caps_path);
    fprintf(out, "# generated: %ld\n", (long)time(NULL));
    fprintf(out, "version 1\n");
    fprintf(out, "min_version 0x0303\n");
    fprintf(out, "max_version 0x0304\n");
    fprintf(out, "\n");
    fprintf(out, "# measured on this device:\n");
    fprintf(out, "#   aes128gcm  %8.2f MB/s\n", c.aes128gcm_mbps);
    fprintf(out, "#   aes256gcm  %8.2f MB/s\n", c.aes256gcm_mbps);
    fprintf(out, "#   chacha20   %8.2f MB/s\n", c.chacha20_mbps);
    fprintf(out, "#   sha256     %8.2f MB/s\n", c.sha256_mbps);
    fprintf(out, "#   sha384     %8.2f MB/s\n", c.sha384_mbps);
    fprintf(out, "#   x25519     %8.0f ops/s\n", c.x25519_ops_per_sec);
    fprintf(out, "\n");
    fprintf(out, "prefer_aes_gcm  %d\n", aes_wins);
    fprintf(out, "prefer_sha256   %d\n", sha256_wins);
    fprintf(out, "\n");
    fprintf(out, "cipher_suites_13  %s\n", tls13_order);
    fprintf(out, "cipher_suites_12  %s\n", tls12_order);
    fclose(out);

    fprintf(stderr, "profile_gen: %s -> %s\n", caps_path, out_path);
    fprintf(stderr, "  AES wins: %s (%.0f vs %.0f MB/s)\n",
            aes_wins ? "yes" : "no", c.aes128gcm_mbps, c.chacha20_mbps);
    fprintf(stderr, "  SHA256 wins: %s (%.0f vs %.0f MB/s)\n",
            sha256_wins ? "yes" : "no", c.sha256_mbps, c.sha384_mbps);
    return 0;
}
