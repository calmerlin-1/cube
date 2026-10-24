/** crypto_caps.c — probe once, cache forever. */

#include "crypto_caps.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "platform.h"

/* ---- process-wide cache ---- */
static crisptls_crypto_caps_t g_caps;
static int g_caps_ready = 0;
static char g_caps_path[512] = "net/crisptls/cache/crypto_caps.txt";

static uint64_t now_ns(void) { return plat_now_ns(); }

static uint64_t realtime_ns(void) { return plat_realtime_ns(); }

/* ---- benchmark helpers ---- */

static double bench_aes128gcm(void) {
    static uint8_t buf[65536], ct[65536 + 16];
    uint8_t key[16] = {0}, nonce[12] = {0}, tag[16];
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;   /* 300 ms */
    while (now_ns() < deadline) {
        for (int i = 0; i < 20; i++) {
            ct_aes128gcm_encrypt(key, nonce, NULL, 0, buf, sizeof(buf), ct, tag);
            total += sizeof(buf);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_aes256gcm(void) {
    static uint8_t buf[65536], ct[65536 + 16];
    uint8_t key[32] = {0}, nonce[12] = {0}, tag[16];
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 20; i++) {
            ct_aes256gcm_encrypt(key, nonce, NULL, 0, buf, sizeof(buf), ct, tag);
            total += sizeof(buf);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_chacha(void) {
    static uint8_t buf[65536], ct[65536 + 16];
    uint8_t key[32] = {0}, nonce[12] = {0}, tag[16];
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 20; i++) {
            ct_chacha20poly1305_encrypt(key, nonce, NULL, 0, buf, sizeof(buf), ct, tag);
            total += sizeof(buf);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_sha256(void) {
    static uint8_t buf[65536];
    uint8_t out[32];
    memset(buf, 0xAA, sizeof(buf));
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 20; i++) {
            ct_sha256(buf, sizeof(buf), out);
            total += sizeof(buf);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_sha384(void) {
    static uint8_t buf[65536];
    uint8_t out[48];
    memset(buf, 0xAA, sizeof(buf));
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 20; i++) {
            ct_sha384(buf, sizeof(buf), out);
            total += sizeof(buf);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_hmac_sha256(void) {
    static uint8_t msg[4096];
    uint8_t key[32] = {0}, out[32];
    memset(msg, 0x77, sizeof(msg));
    size_t total = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 100; i++) {
            ct_hmac_sha256(key, 32, msg, sizeof(msg), out);
            total += sizeof(msg);
        }
    }
    uint64_t dt = now_ns() - t0;
    return ((double)total / (1024.0*1024.0)) / ((double)dt / 1e9);
}

static double bench_x25519(void) {
    /* Measure pure scalarmult — no randombytes syscall per op */
    uint8_t priv[32], pub[32], shared[32];
    uint8_t peer[32] = {9};
    ct_x25519_keypair(priv, pub);   /* one-time */
    int ops = 0;
    uint64_t t0 = now_ns();
    uint64_t deadline = t0 + 300000000ull;
    while (now_ns() < deadline) {
        for (int i = 0; i < 100; i++) {
            ct_x25519(shared, priv, peer);
            ops++;
        }
    }
    uint64_t dt = now_ns() - t0;
    return (double)ops / ((double)dt / 1e9);
}

/* ---- probe ---- */

int crypto_caps_probe(crisptls_crypto_caps_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    uint64_t t_start = now_ns();

    plat_cpu_t cpu;
    plat_cpu_detect(&cpu);
    out->has_aes     = cpu.has_aes;
    out->has_pmull   = cpu.has_pmull;
    out->has_sha1_hw = cpu.has_sha1;
    out->has_sha2_hw = cpu.has_sha2;
    out->has_crc32   = cpu.has_crc32;
    out->hwcap = 0;   /* deprecated — see plat_cpu_detect */

    out->aes128gcm_mbps    = bench_aes128gcm();
    out->aes256gcm_mbps    = bench_aes256gcm();
    out->chacha20_mbps     = bench_chacha();
    out->sha256_mbps       = bench_sha256();
    out->sha384_mbps       = bench_sha384();
    out->hmac_sha256_mbps  = bench_hmac_sha256();
    out->x25519_ops_per_sec = bench_x25519();

    out->prefer_aes_gcm = (out->aes128gcm_mbps > out->chacha20_mbps) ? 1 : 0;
    out->prefer_sha256  = (out->sha256_mbps > out->sha384_mbps) ? 1 : 0;

    out->probed_at_ns = realtime_ns();
    out->probe_duration_ms = (uint32_t)((now_ns() - t_start) / 1000000ull);
    out->valid = 1;
    return 0;
}

/* ---- persistence ---- */

int crypto_caps_save(const crisptls_crypto_caps_t *caps, const char *path) {
    if (!caps || !path || !caps->valid) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "# crisptls crypto capabilities\n");
    fprintf(f, "version 1\n");
    fprintf(f, "hwcap %lu\n", caps->hwcap);
    fprintf(f, "has_aes %d\n", caps->has_aes);
    fprintf(f, "has_pmull %d\n", caps->has_pmull);
    fprintf(f, "has_sha1_hw %d\n", caps->has_sha1_hw);
    fprintf(f, "has_sha2_hw %d\n", caps->has_sha2_hw);
    fprintf(f, "has_crc32 %d\n", caps->has_crc32);
    fprintf(f, "aes128gcm_mbps %.2f\n", caps->aes128gcm_mbps);
    fprintf(f, "aes256gcm_mbps %.2f\n", caps->aes256gcm_mbps);
    fprintf(f, "chacha20_mbps %.2f\n", caps->chacha20_mbps);
    fprintf(f, "sha256_mbps %.2f\n", caps->sha256_mbps);
    fprintf(f, "sha384_mbps %.2f\n", caps->sha384_mbps);
    fprintf(f, "hmac_sha256_mbps %.2f\n", caps->hmac_sha256_mbps);
    fprintf(f, "x25519_ops_per_sec %.0f\n", caps->x25519_ops_per_sec);
    fprintf(f, "prefer_aes_gcm %d\n", caps->prefer_aes_gcm);
    fprintf(f, "prefer_sha256 %d\n", caps->prefer_sha256);
    fprintf(f, "probed_at_ns %llu\n", (unsigned long long)caps->probed_at_ns);
    fprintf(f, "probe_duration_ms %u\n", caps->probe_duration_ms);
    fclose(f);
    return 0;
}

int crypto_caps_load(crisptls_crypto_caps_t *caps, const char *path) {
    if (!caps || !path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(caps, 0, sizeof(*caps));

    char key[64];
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s", key) != 1) continue;

        /* find the value: skip key + whitespace */
        const char *val = line + strlen(key);
        while (*val == ' ' || *val == '\t') val++;

        if      (!strcmp(key, "hwcap"))               caps->hwcap = strtoul(val, NULL, 10);
        else if (!strcmp(key, "has_aes"))             caps->has_aes = atoi(val);
        else if (!strcmp(key, "has_pmull"))           caps->has_pmull = atoi(val);
        else if (!strcmp(key, "has_sha1_hw"))         caps->has_sha1_hw = atoi(val);
        else if (!strcmp(key, "has_sha2_hw"))         caps->has_sha2_hw = atoi(val);
        else if (!strcmp(key, "has_crc32"))           caps->has_crc32 = atoi(val);
        else if (!strcmp(key, "aes128gcm_mbps"))      caps->aes128gcm_mbps = atof(val);
        else if (!strcmp(key, "aes256gcm_mbps"))      caps->aes256gcm_mbps = atof(val);
        else if (!strcmp(key, "chacha20_mbps"))       caps->chacha20_mbps = atof(val);
        else if (!strcmp(key, "sha256_mbps"))         caps->sha256_mbps = atof(val);
        else if (!strcmp(key, "sha384_mbps"))         caps->sha384_mbps = atof(val);
        else if (!strcmp(key, "hmac_sha256_mbps"))    caps->hmac_sha256_mbps = atof(val);
        else if (!strcmp(key, "x25519_ops_per_sec"))  caps->x25519_ops_per_sec = atof(val);
        else if (!strcmp(key, "prefer_aes_gcm"))      caps->prefer_aes_gcm = atoi(val);
        else if (!strcmp(key, "prefer_sha256"))       caps->prefer_sha256 = atoi(val);
        else if (!strcmp(key, "probed_at_ns"))        caps->probed_at_ns = strtoull(val, NULL, 10);
        else if (!strcmp(key, "probe_duration_ms"))   caps->probe_duration_ms = (uint32_t)atoi(val);
    }
    fclose(f);

    /* Re-derive CPU flags — they might be stale if hardware changed */
    plat_cpu_t cpu;
    plat_cpu_detect(&cpu);
    caps->has_aes     = cpu.has_aes;
    caps->has_pmull   = cpu.has_pmull;
    caps->has_sha1_hw = cpu.has_sha1;
    caps->has_sha2_hw = cpu.has_sha2;
    caps->has_crc32   = cpu.has_crc32;

    /* check age — 30 days max */
    uint64_t now = realtime_ns();
    uint64_t max_age = 30ull * 24 * 60 * 60 * 1000000000ull;
    if (caps->probed_at_ns && (now - caps->probed_at_ns) > max_age) {
        return -2;  /* stale */
    }
    caps->valid = 1;
    return 0;
}

/* ---- public API ---- */

void crypto_caps_set_path(const char *path) {
    if (path) snprintf(g_caps_path, sizeof(g_caps_path), "%s", path);
}

const crisptls_crypto_caps_t *crypto_caps_get(void) {
    if (g_caps_ready) return &g_caps;

    /* Try cache first */
    int r = crypto_caps_load(&g_caps, g_caps_path);
    if (r == 0) {
        g_caps_ready = 1;
        return &g_caps;
    }

    /* Stale or missing — probe */
    crypto_caps_probe(&g_caps);

    /* Ensure parent dir exists */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", g_caps_path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        plat_mkdir_p(dir);
    }

    crypto_caps_save(&g_caps, g_caps_path);
    g_caps_ready = 1;
    return &g_caps;
}

void crypto_caps_refresh(void) {
    g_caps_ready = 0;
    crypto_caps_probe(&g_caps);
    crypto_caps_save(&g_caps, g_caps_path);
    g_caps_ready = 1;
}

void crypto_caps_format(const crisptls_crypto_caps_t *caps,
                        char *out, size_t cap) {
    if (!caps || !out || !caps->valid) { if (out) out[0] = '\0'; return; }
    snprintf(out, cap,
             "AES-128-GCM %.0f MB/s | AES-256-GCM %.0f MB/s | "
             "ChaCha20 %.0f MB/s | SHA-256 %.0f MB/s | SHA-384 %.0f MB/s | "
             "X25519 %.0f ops/s",
             caps->aes128gcm_mbps, caps->aes256gcm_mbps,
             caps->chacha20_mbps, caps->sha256_mbps, caps->sha384_mbps,
             caps->x25519_ops_per_sec);
}
