#ifndef CUBE_AI_H
#define CUBE_AI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CUBE_AI_API_VERSION 1

#define CUBE_AI_NAME_MAX 64
#define CUBE_AI_VERSION_MAX 32
#define CUBE_AI_BACKEND_MAX 32
#define CUBE_AI_FORMAT_MAX 32
#define CUBE_AI_PATH_MAX 1024
#define CUBE_AI_SHA256_HEX 64
#define CUBE_AI_MAX_MODELS 64
#define CUBE_AI_MAX_METADATA 16
#define CUBE_AI_METADATA_KEY_MAX 48
#define CUBE_AI_METADATA_VALUE_MAX 192
#define CUBE_AI_MAX_MANIFEST_BYTES (1024u * 1024u)
#define CUBE_AI_MAX_INPUT_BYTES (64u * 1024u * 1024u)
#define CUBE_AI_MAX_OUTPUT_BYTES (64u * 1024u * 1024u)

typedef enum cube_ai_capability {
    CUBE_AI_CAP_OCR = 0,
    CUBE_AI_CAP_IMAGE_CLASSIFY = 1,
    CUBE_AI_CAP_SPEECH = 2,
    CUBE_AI_CAP_CAPTCHA_SLIDER = 3,
    CUBE_AI_CAP_COUNT = 4,
    CUBE_AI_CAP_UNKNOWN = -1
} cube_ai_capability;

typedef enum cube_ai_status {
    CUBE_AI_OK = 0,
    CUBE_AI_ERR_INVALID = -1,
    CUBE_AI_ERR_NOMEM = -2,
    CUBE_AI_ERR_IO = -3,
    CUBE_AI_ERR_PARSE = -4,
    CUBE_AI_ERR_NOT_FOUND = -5,
    CUBE_AI_ERR_NOT_INSTALLED = -6,
    CUBE_AI_ERR_CHECKSUM = -7,
    CUBE_AI_ERR_UNSUPPORTED = -8,
    CUBE_AI_ERR_LIMIT = -9,
    CUBE_AI_ERR_BACKEND = -10,
    CUBE_AI_ERR_BUSY = -11
} cube_ai_status;

typedef enum cube_ai_model_flag {
    CUBE_AI_MODEL_FLAG_NONE = 0,
    CUBE_AI_MODEL_FLAG_OPTIONAL = 1u << 0,
    CUBE_AI_MODEL_FLAG_QUANTIZED = 1u << 1,
    CUBE_AI_MODEL_FLAG_REQUIRES_NET = 1u << 2,
    CUBE_AI_MODEL_FLAG_INSTALLED = 1u << 3
} cube_ai_model_flag;

typedef struct cube_ai_model {
    char name[CUBE_AI_NAME_MAX];
    cube_ai_capability capability;
    char version[CUBE_AI_VERSION_MAX];
    char backend[CUBE_AI_BACKEND_MAX];
    char weights_path[CUBE_AI_PATH_MAX];
    char config_path[CUBE_AI_PATH_MAX];
    char sha256[CUBE_AI_SHA256_HEX + 1];
    char input_format[CUBE_AI_FORMAT_MAX];
    char output_format[CUBE_AI_FORMAT_MAX];
    uint32_t flags;
    int installed;
    uint64_t size_bytes;
} cube_ai_model;

typedef struct cube_ai_registry cube_ai_registry;
typedef struct cube_ai_model_handle cube_ai_model_handle;

typedef struct cube_ai_metadata {
    char key[CUBE_AI_METADATA_KEY_MAX];
    char value[CUBE_AI_METADATA_VALUE_MAX];
} cube_ai_metadata;

typedef struct cube_ai_request {
    const uint8_t *data;
    size_t size;
    const char *input_format;
    const cube_ai_metadata *metadata;
    size_t metadata_count;
    uint32_t flags;
} cube_ai_request;

typedef struct cube_ai_response {
    uint8_t *data;
    size_t size;
    size_t capacity;
    char output_format[CUBE_AI_FORMAT_MAX];
    cube_ai_metadata metadata[CUBE_AI_MAX_METADATA];
    size_t metadata_count;
} cube_ai_response;

const char *cube_ai_capability_name(cube_ai_capability capability);
int cube_ai_capability_from_name(const char *name, cube_ai_capability *out);
const char *cube_ai_status_string(int status);

cube_ai_registry *cube_ai_registry_init(const char *home);
void cube_ai_registry_free(cube_ai_registry *registry);
int cube_ai_registry_scan(cube_ai_registry *registry, const char *manifest_path);
int cube_ai_registry_refresh(cube_ai_registry *registry);
size_t cube_ai_registry_count(const cube_ai_registry *registry);
const cube_ai_model *cube_ai_registry_at(const cube_ai_registry *registry, size_t index);
const cube_ai_model *cube_ai_registry_find(const cube_ai_registry *registry, const char *name);
const cube_ai_model *cube_ai_registry_find_capability(const cube_ai_registry *registry,
                                                      cube_ai_capability capability);
const char *cube_ai_registry_home(const cube_ai_registry *registry);
const char *cube_ai_registry_manifest(const cube_ai_registry *registry);
int cube_ai_registry_resolve_asset(const cube_ai_registry *registry, const char *asset,
                                   char *out, size_t out_size);

int cube_ai_asset_home(char *out, size_t out_size);
int cube_ai_asset_resolve(const char *asset, char *out, size_t out_size);
int cube_ai_asset_resolve_home(const char *home, const char *asset,
                               char *out, size_t out_size);
int cube_ai_asset_sha256(const char *path, char out_hex[CUBE_AI_SHA256_HEX + 1]);
int cube_ai_asset_verify_sha256(const char *path, const char *expected_hex);

int cube_ai_model_load(cube_ai_registry *registry, const char *name,
                       cube_ai_model_handle **out);
void cube_ai_model_unload(cube_ai_model_handle *handle);
const cube_ai_model *cube_ai_model_descriptor(const cube_ai_model_handle *handle);
const char *cube_ai_model_weights_path(const cube_ai_model_handle *handle);

void cube_ai_response_init(cube_ai_response *response);
void cube_ai_response_free(cube_ai_response *response);
int cube_ai_model_infer(cube_ai_model_handle *handle, const cube_ai_request *request,
                        cube_ai_response *response);

#ifdef __cplusplus
}
#endif

#endif
