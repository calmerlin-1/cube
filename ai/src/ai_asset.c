#include "ai_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int copy_string(char *out, size_t out_size, const char *value)
{
    size_t len;

    if (!out || out_size == 0 || !value)
        return CUBE_AI_ERR_INVALID;
    len = strlen(value);
    if (len >= out_size)
        return CUBE_AI_ERR_LIMIT;
    memcpy(out, value, len + 1);
    return CUBE_AI_OK;
}

int cube_ai_asset_exists(const char *path)
{
    struct stat st;

    if (!path || !*path)
        return 0;
    return stat(path, &st) == 0;
}

int cube_ai_asset_is_dir(const char *path)
{
    struct stat st;

    if (!path || !*path)
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int cube_ai_asset_is_file(const char *path)
{
    struct stat st;

    if (!path || !*path)
        return 0;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int cube_ai_asset_join(const char *base, const char *asset, char *out, size_t out_size)
{
    size_t base_len;
    int written;

    if (!out || out_size == 0 || !asset || !*asset)
        return CUBE_AI_ERR_INVALID;
    if (asset[0] == '/')
        return copy_string(out, out_size, asset);
    if (!base || !*base)
        return copy_string(out, out_size, asset);

    base_len = strlen(base);
    while (base_len > 1 && base[base_len - 1] == '/')
        base_len--;

    if (base_len == 1 && base[0] == '/')
        written = snprintf(out, out_size, "/%s", asset);
    else
        written = snprintf(out, out_size, "%.*s/%s", (int)base_len, base, asset);
    if (written < 0 || (size_t)written >= out_size)
        return CUBE_AI_ERR_LIMIT;
    return CUBE_AI_OK;
}

int cube_ai_asset_home(char *out, size_t out_size)
{
    const char *env = getenv("CUBE_AI_HOME");
    const char *home = getenv("HOME");
    char user_home[CUBE_AI_PATH_MAX];
    char user_manifest[CUBE_AI_PATH_MAX];
    int have_user_home = 0;

    if (env && *env)
        return copy_string(out, out_size, env);

    if (home && *home) {
        int written = snprintf(user_home, sizeof(user_home),
                               "%s/.local/share/cube/ai", home);
        if (written > 0 && (size_t)written < sizeof(user_home)) {
            have_user_home = 1;
            if (cube_ai_asset_join(user_home, "manifest.jsonc",
                                   user_manifest, sizeof(user_manifest)) == CUBE_AI_OK &&
                cube_ai_asset_is_file(user_manifest))
                return copy_string(out, out_size, user_home);
        }
    }

    if (cube_ai_asset_is_file("./ai/models/manifest.jsonc"))
        return copy_string(out, out_size, "./ai/models");
    if (have_user_home && cube_ai_asset_is_dir(user_home))
        return copy_string(out, out_size, user_home);
    if (cube_ai_asset_is_dir("./ai/models"))
        return copy_string(out, out_size, "./ai/models");
    if (have_user_home)
        return copy_string(out, out_size, user_home);
    return copy_string(out, out_size, "./ai/models");
}

int cube_ai_asset_resolve_home(const char *home, const char *asset,
                               char *out, size_t out_size)
{
    if (!asset || !*asset)
        return CUBE_AI_ERR_INVALID;
    return cube_ai_asset_join(home, asset, out, out_size);
}

int cube_ai_asset_resolve(const char *asset, char *out, size_t out_size)
{
    char home[CUBE_AI_PATH_MAX];
    char primary[CUBE_AI_PATH_MAX];
    char fallback[CUBE_AI_PATH_MAX];
    int rc;

    if (!asset || !*asset || !out || out_size == 0)
        return CUBE_AI_ERR_INVALID;
    if (asset[0] == '/')
        return copy_string(out, out_size, asset);

    rc = cube_ai_asset_home(home, sizeof(home));
    if (rc != CUBE_AI_OK)
        return rc;
    rc = cube_ai_asset_resolve_home(home, asset, primary, sizeof(primary));
    if (rc != CUBE_AI_OK)
        return rc;
    if (cube_ai_asset_exists(primary))
        return copy_string(out, out_size, primary);

    rc = cube_ai_asset_join("./ai/models", asset, fallback, sizeof(fallback));
    if (rc == CUBE_AI_OK && strcmp(home, "./ai/models") != 0 &&
        cube_ai_asset_exists(fallback))
        return copy_string(out, out_size, fallback);

    rc = copy_string(out, out_size, primary);
    return rc == CUBE_AI_OK ? CUBE_AI_ERR_NOT_FOUND : rc;
}

typedef struct sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_len;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bit_count += (uint64_t)len * 8u;

    while (len > 0) {
        size_t room = sizeof(ctx->buffer) - ctx->buffer_len;
        size_t take = len < room ? len : room;

        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == sizeof(ctx->buffer)) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32])
{
    uint64_t bit_count = ctx->bit_count;
    uint8_t padding[64];
    uint8_t length_bytes[8];
    size_t padding_len;
    size_t i;

    padding_len = ctx->buffer_len < 56 ? 56 - ctx->buffer_len : 120 - ctx->buffer_len;
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    sha256_update(ctx, padding, padding_len);

    for (i = 0; i < 8; i++)
        length_bytes[7 - i] = (uint8_t)(bit_count >> (i * 8));
    sha256_update(ctx, length_bytes, sizeof(length_bytes));

    for (i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

int cube_ai_asset_sha256(const char *path, char out_hex[CUBE_AI_SHA256_HEX + 1])
{
    static const char hex[] = "0123456789abcdef";
    sha256_ctx ctx;
    uint8_t buffer[8192];
    uint8_t digest[32];
    FILE *file;
    size_t got;
    size_t i;

    if (!path || !*path || !out_hex)
        return CUBE_AI_ERR_INVALID;

    file = fopen(path, "rb");
    if (!file) {
        out_hex[0] = '\0';
        return errno == ENOENT ? CUBE_AI_ERR_NOT_FOUND : CUBE_AI_ERR_IO;
    }

    sha256_init(&ctx);
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
        sha256_update(&ctx, buffer, got);
    if (ferror(file)) {
        fclose(file);
        out_hex[0] = '\0';
        return CUBE_AI_ERR_IO;
    }
    fclose(file);

    sha256_final(&ctx, digest);
    for (i = 0; i < sizeof(digest); i++) {
        out_hex[i * 2] = hex[digest[i] >> 4];
        out_hex[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out_hex[CUBE_AI_SHA256_HEX] = '\0';
    return CUBE_AI_OK;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

int cube_ai_asset_verify_sha256(const char *path, const char *expected_hex)
{
    char actual[CUBE_AI_SHA256_HEX + 1];
    size_t i;
    int rc;

    if (!expected_hex || !*expected_hex)
        return CUBE_AI_OK;
    if (strlen(expected_hex) != CUBE_AI_SHA256_HEX)
        return CUBE_AI_ERR_INVALID;
    for (i = 0; i < CUBE_AI_SHA256_HEX; i++) {
        if (hex_nibble(expected_hex[i]) < 0)
            return CUBE_AI_ERR_INVALID;
    }

    rc = cube_ai_asset_sha256(path, actual);
    if (rc != CUBE_AI_OK)
        return rc;

    for (i = 0; i < CUBE_AI_SHA256_HEX; i++) {
        if (hex_nibble(actual[i]) != hex_nibble(expected_hex[i]))
            return CUBE_AI_ERR_CHECKSUM;
    }
    return CUBE_AI_OK;
}
