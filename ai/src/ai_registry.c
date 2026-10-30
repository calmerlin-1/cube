#include "ai_internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CUBE_AI_PARSE_MAX_DEPTH 32

const char *cube_ai_capability_name(cube_ai_capability capability)
{
    switch (capability) {
    case CUBE_AI_CAP_OCR:
        return "ocr";
    case CUBE_AI_CAP_IMAGE_CLASSIFY:
        return "image_classify";
    case CUBE_AI_CAP_SPEECH:
        return "speech";
    case CUBE_AI_CAP_CAPTCHA_SLIDER:
        return "captcha_slider";
    default:
        return "unknown";
    }
}

int cube_ai_capability_from_name(const char *name, cube_ai_capability *out)
{
    if (!name || !out)
        return CUBE_AI_ERR_INVALID;

    if (strcmp(name, "ocr") == 0 || strcmp(name, "text_ocr") == 0) {
        *out = CUBE_AI_CAP_OCR;
    } else if (strcmp(name, "image_classify") == 0 ||
               strcmp(name, "image-classify") == 0 ||
               strcmp(name, "image_classification") == 0 ||
               strcmp(name, "classification") == 0 ||
               strcmp(name, "image") == 0) {
        *out = CUBE_AI_CAP_IMAGE_CLASSIFY;
    } else if (strcmp(name, "speech") == 0 ||
               strcmp(name, "speech_to_text") == 0 ||
               strcmp(name, "asr") == 0 ||
               strcmp(name, "stt") == 0) {
        *out = CUBE_AI_CAP_SPEECH;
    } else if (strcmp(name, "captcha_slider") == 0 ||
               strcmp(name, "captcha-slider") == 0 ||
               strcmp(name, "slider_captcha") == 0 ||
               strcmp(name, "slider") == 0 ||
               strcmp(name, "captcha") == 0) {
        *out = CUBE_AI_CAP_CAPTCHA_SLIDER;
    } else {
        *out = CUBE_AI_CAP_UNKNOWN;
        return CUBE_AI_ERR_NOT_FOUND;
    }
    return CUBE_AI_OK;
}

const char *cube_ai_status_string(int status)
{
    switch (status) {
    case CUBE_AI_OK:
        return "ok";
    case CUBE_AI_ERR_INVALID:
        return "invalid";
    case CUBE_AI_ERR_NOMEM:
        return "out of memory";
    case CUBE_AI_ERR_IO:
        return "io error";
    case CUBE_AI_ERR_PARSE:
        return "parse error";
    case CUBE_AI_ERR_NOT_FOUND:
        return "not found";
    case CUBE_AI_ERR_NOT_INSTALLED:
        return "not installed";
    case CUBE_AI_ERR_CHECKSUM:
        return "checksum mismatch";
    case CUBE_AI_ERR_UNSUPPORTED:
        return "unsupported";
    case CUBE_AI_ERR_LIMIT:
        return "limit exceeded";
    case CUBE_AI_ERR_BACKEND:
        return "backend error";
    case CUBE_AI_ERR_BUSY:
        return "busy";
    default:
        return "unknown error";
    }
}

static int copy_field(char *dst, size_t dst_size, const char *src)
{
    size_t len;

    if (!dst || dst_size == 0 || !src)
        return CUBE_AI_ERR_INVALID;
    len = strlen(src);
    if (len >= dst_size)
        return CUBE_AI_ERR_LIMIT;
    memcpy(dst, src, len + 1);
    return CUBE_AI_OK;
}

static int token_equals(const char *token, size_t token_len, const char *literal)
{
    size_t i;

    if (strlen(literal) != token_len)
        return 0;
    for (i = 0; i < token_len; i++) {
        if (tolower((unsigned char)token[i]) != (unsigned char)literal[i])
            return 0;
    }
    return 1;
}

static uint32_t flag_from_token(const char *token, size_t token_len)
{
    if (token_equals(token, token_len, "optional"))
        return CUBE_AI_MODEL_FLAG_OPTIONAL;
    if (token_equals(token, token_len, "quantized"))
        return CUBE_AI_MODEL_FLAG_QUANTIZED;
    if (token_equals(token, token_len, "requires_net") ||
        token_equals(token, token_len, "requires_network") ||
        token_equals(token, token_len, "network"))
        return CUBE_AI_MODEL_FLAG_REQUIRES_NET;
    return CUBE_AI_MODEL_FLAG_NONE;
}

static uint32_t flags_from_string(const char *value)
{
    uint32_t flags = CUBE_AI_MODEL_FLAG_NONE;
    const char *cursor = value;

    while (cursor && *cursor) {
        const char *start;
        size_t len;

        while (*cursor == ',' || isspace((unsigned char)*cursor))
            cursor++;
        start = cursor;
        while (*cursor && *cursor != ',' && !isspace((unsigned char)*cursor))
            cursor++;
        len = (size_t)(cursor - start);
        if (len > 0)
            flags |= flag_from_token(start, len);
    }
    return flags;
}

static int set_model_field(cube_ai_model *model, const char *key, const char *value)
{
    if (strcmp(key, "name") == 0)
        return copy_field(model->name, sizeof(model->name), value);
    if (strcmp(key, "capability") == 0) {
        cube_ai_capability capability;
        if (cube_ai_capability_from_name(value, &capability) != CUBE_AI_OK)
            capability = CUBE_AI_CAP_UNKNOWN;
        model->capability = capability;
        return CUBE_AI_OK;
    }
    if (strcmp(key, "version") == 0)
        return copy_field(model->version, sizeof(model->version), value);
    if (strcmp(key, "backend") == 0)
        return copy_field(model->backend, sizeof(model->backend), value);
    if (strcmp(key, "weights") == 0 || strcmp(key, "weights_path") == 0)
        return copy_field(model->weights_path, sizeof(model->weights_path), value);
    if (strcmp(key, "config") == 0 || strcmp(key, "config_path") == 0)
        return copy_field(model->config_path, sizeof(model->config_path), value);
    if (strcmp(key, "sha256") == 0)
        return copy_field(model->sha256, sizeof(model->sha256), value);
    if (strcmp(key, "input") == 0 || strcmp(key, "input_format") == 0)
        return copy_field(model->input_format, sizeof(model->input_format), value);
    if (strcmp(key, "output") == 0 || strcmp(key, "output_format") == 0)
        return copy_field(model->output_format, sizeof(model->output_format), value);
    if (strcmp(key, "flags") == 0) {
        model->flags |= flags_from_string(value);
        return CUBE_AI_OK;
    }
    if (strcmp(key, "size_bytes") == 0) {
        model->size_bytes = strtoull(value, NULL, 10);
        return CUBE_AI_OK;
    }
    return CUBE_AI_OK;
}

typedef struct parser {
    const char *src;
    size_t len;
    size_t pos;
    int line;
} parser;

static void parser_skip_space(parser *p)
{
    while (p->pos < p->len) {
        char ch = p->src[p->pos];

        if (isspace((unsigned char)ch)) {
            if (ch == '\n')
                p->line++;
            p->pos++;
        } else if (ch == '/' && p->pos + 1 < p->len && p->src[p->pos + 1] == '/') {
            p->pos += 2;
            while (p->pos < p->len && p->src[p->pos] != '\n')
                p->pos++;
        } else if (ch == '/' && p->pos + 1 < p->len && p->src[p->pos + 1] == '*') {
            p->pos += 2;
            while (p->pos + 1 < p->len &&
                   !(p->src[p->pos] == '*' && p->src[p->pos + 1] == '/')) {
                if (p->src[p->pos] == '\n')
                    p->line++;
                p->pos++;
            }
            if (p->pos + 1 < p->len)
                p->pos += 2;
        } else {
            break;
        }
    }
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static int parser_string(parser *p, char *out, size_t out_size)
{
    size_t used = 0;

    parser_skip_space(p);
    if (p->pos >= p->len || p->src[p->pos] != '"')
        return CUBE_AI_ERR_PARSE;
    p->pos++;

    while (p->pos < p->len) {
        unsigned char ch = (unsigned char)p->src[p->pos++];

        if (ch == '"') {
            out[used] = '\0';
            return CUBE_AI_OK;
        }
        if (ch == '\\') {
            char escape;
            if (p->pos >= p->len)
                return CUBE_AI_ERR_PARSE;
            escape = p->src[p->pos++];
            switch (escape) {
            case '"':
            case '\\':
            case '/':
                ch = (unsigned char)escape;
                break;
            case 'b':
                ch = '\b';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            case 'u': {
                uint32_t code = 0;
                size_t i;
                if (p->pos + 4 > p->len)
                    return CUBE_AI_ERR_PARSE;
                for (i = 0; i < 4; i++) {
                    int digit = hex_value(p->src[p->pos + i]);
                    if (digit < 0)
                        return CUBE_AI_ERR_PARSE;
                    code = (code << 4) | (uint32_t)digit;
                }
                p->pos += 4;
                if (code <= 0x7f) {
                    ch = (unsigned char)code;
                } else if (code <= 0x7ff) {
                    if (used + 3 > out_size)
                        return CUBE_AI_ERR_LIMIT;
                    out[used++] = (char)(0xc0 | (code >> 6));
                    out[used++] = (char)(0x80 | (code & 0x3f));
                    continue;
                } else {
                    if (used + 4 > out_size)
                        return CUBE_AI_ERR_LIMIT;
                    out[used++] = (char)(0xe0 | (code >> 12));
                    out[used++] = (char)(0x80 | ((code >> 6) & 0x3f));
                    out[used++] = (char)(0x80 | (code & 0x3f));
                    continue;
                }
                break;
            }
            default:
                return CUBE_AI_ERR_PARSE;
            }
        } else if (ch == '\n') {
            p->line++;
        }

        if (used + 2 > out_size)
            return CUBE_AI_ERR_LIMIT;
        out[used++] = (char)ch;
    }
    return CUBE_AI_ERR_PARSE;
}

static int parser_skip_scalar(parser *p)
{
    size_t start;

    parser_skip_space(p);
    start = p->pos;
    while (p->pos < p->len) {
        char ch = p->src[p->pos];
        if (ch == ',' || ch == '}' || ch == ']' || isspace((unsigned char)ch) ||
            ch == '/')
            break;
        p->pos++;
    }
    return p->pos == start ? CUBE_AI_ERR_PARSE : CUBE_AI_OK;
}

static int registry_add_model(cube_ai_registry *registry, const cube_ai_model *model)
{
    size_t i;

    if (!model->name[0])
        return CUBE_AI_OK;
    for (i = 0; i < registry->count; i++) {
        if (strcmp(registry->models[i].name, model->name) == 0)
            return CUBE_AI_OK;
    }
    if (registry->count >= CUBE_AI_MAX_MODELS)
        return CUBE_AI_ERR_LIMIT;
    registry->models[registry->count++] = *model;
    return CUBE_AI_OK;
}

static int parser_value(parser *p, cube_ai_registry *registry, int depth,
                        const char *key, cube_ai_model *model);

static int parser_array(parser *p, cube_ai_registry *registry, int depth,
                        const char *key, cube_ai_model *model)
{
    if (depth > CUBE_AI_PARSE_MAX_DEPTH)
        return CUBE_AI_ERR_LIMIT;

    parser_skip_space(p);
    if (p->pos >= p->len || p->src[p->pos] != '[')
        return CUBE_AI_ERR_PARSE;
    p->pos++;

    for (;;) {
        int rc;

        parser_skip_space(p);
        if (p->pos >= p->len)
            return CUBE_AI_ERR_PARSE;
        if (p->src[p->pos] == ']') {
            p->pos++;
            return CUBE_AI_OK;
        }
        if (p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }

        if (model && key && strcmp(key, "flags") == 0 &&
            p->src[p->pos] == '"') {
            char value[CUBE_AI_PATH_MAX];
            rc = parser_string(p, value, sizeof(value));
            if (rc != CUBE_AI_OK)
                return rc;
            model->flags |= flags_from_string(value);
        } else {
            rc = parser_value(p, registry, depth + 1, NULL, NULL);
            if (rc != CUBE_AI_OK)
                return rc;
        }

        parser_skip_space(p);
        if (p->pos < p->len && p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (p->pos < p->len && p->src[p->pos] == ']') {
            p->pos++;
            return CUBE_AI_OK;
        }
        return CUBE_AI_ERR_PARSE;
    }
}

static int parser_object(parser *p, cube_ai_registry *registry, int depth)
{
    cube_ai_model model;
    int rc;

    if (depth > CUBE_AI_PARSE_MAX_DEPTH)
        return CUBE_AI_ERR_LIMIT;

    parser_skip_space(p);
    if (p->pos >= p->len || p->src[p->pos] != '{')
        return CUBE_AI_ERR_PARSE;
    p->pos++;

    memset(&model, 0, sizeof(model));
    model.capability = CUBE_AI_CAP_UNKNOWN;

    for (;;) {
        char key[CUBE_AI_NAME_MAX];

        parser_skip_space(p);
        if (p->pos >= p->len)
            return CUBE_AI_ERR_PARSE;
        if (p->src[p->pos] == '}') {
            p->pos++;
            break;
        }
        if (p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }

        rc = parser_string(p, key, sizeof(key));
        if (rc != CUBE_AI_OK)
            return rc;
        parser_skip_space(p);
        if (p->pos >= p->len || p->src[p->pos] != ':')
            return CUBE_AI_ERR_PARSE;
        p->pos++;

        rc = parser_value(p, registry, depth + 1, key, &model);
        if (rc != CUBE_AI_OK)
            return rc;

        parser_skip_space(p);
        if (p->pos < p->len && p->src[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (p->pos < p->len && p->src[p->pos] == '}') {
            p->pos++;
            break;
        }
        return CUBE_AI_ERR_PARSE;
    }

    return registry_add_model(registry, &model);
}

static int parser_value(parser *p, cube_ai_registry *registry, int depth,
                        const char *key, cube_ai_model *model)
{
    char ch;

    if (depth > CUBE_AI_PARSE_MAX_DEPTH)
        return CUBE_AI_ERR_LIMIT;

    parser_skip_space(p);
    if (p->pos >= p->len)
        return CUBE_AI_ERR_PARSE;
    ch = p->src[p->pos];

    if (ch == '"') {
        char value[CUBE_AI_PATH_MAX];
        int rc = parser_string(p, value, sizeof(value));
        if (rc != CUBE_AI_OK)
            return rc;
        if (model && key)
            return set_model_field(model, key, value);
        return CUBE_AI_OK;
    }
    if (ch == '{')
        return parser_object(p, registry, depth);
    if (ch == '[')
        return parser_array(p, registry, depth, key, model);
    return parser_skip_scalar(p);
}

static int read_text_file(const char *path, char **out, size_t *out_size)
{
    FILE *file;
    long length;
    char *buffer;
    size_t got;

    if (!path || !out || !out_size)
        return CUBE_AI_ERR_INVALID;
    *out = NULL;
    *out_size = 0;

    file = fopen(path, "rb");
    if (!file)
        return CUBE_AI_ERR_IO;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return CUBE_AI_ERR_IO;
    }
    length = ftell(file);
    if (length < 0) {
        fclose(file);
        return CUBE_AI_ERR_IO;
    }
    if ((unsigned long)length > CUBE_AI_MAX_MANIFEST_BYTES) {
        fclose(file);
        return CUBE_AI_ERR_LIMIT;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return CUBE_AI_ERR_IO;
    }

    buffer = malloc((size_t)length + 1);
    if (!buffer) {
        fclose(file);
        return CUBE_AI_ERR_NOMEM;
    }
    got = fread(buffer, 1, (size_t)length, file);
    if (got != (size_t)length || ferror(file)) {
        free(buffer);
        fclose(file);
        return CUBE_AI_ERR_IO;
    }
    fclose(file);
    buffer[got] = '\0';
    *out = buffer;
    *out_size = got;
    return CUBE_AI_OK;
}

cube_ai_registry *cube_ai_registry_init(const char *home)
{
    cube_ai_registry *registry = calloc(1, sizeof(*registry));

    if (!registry)
        return NULL;
    if (home && *home) {
        if (copy_field(registry->home, sizeof(registry->home), home) != CUBE_AI_OK) {
            free(registry);
            return NULL;
        }
    } else if (cube_ai_asset_home(registry->home, sizeof(registry->home)) != CUBE_AI_OK) {
        free(registry);
        return NULL;
    }
    return registry;
}

void cube_ai_registry_free(cube_ai_registry *registry)
{
    free(registry);
}

int cube_ai_registry_refresh(cube_ai_registry *registry)
{
    size_t i;

    if (!registry)
        return CUBE_AI_ERR_INVALID;

    for (i = 0; i < registry->count; i++) {
        cube_ai_model *model = &registry->models[i];
        char resolved[CUBE_AI_PATH_MAX];
        struct stat st;

        model->flags &= ~(uint32_t)CUBE_AI_MODEL_FLAG_INSTALLED;
        model->installed = 0;
        model->size_bytes = 0;

        if (!model->weights_path[0])
            continue;
        if (cube_ai_registry_resolve_asset(registry, model->weights_path,
                                           resolved, sizeof(resolved)) != CUBE_AI_OK)
            continue;
        if (!cube_ai_asset_is_file(resolved))
            continue;

        model->installed = 1;
        model->flags |= CUBE_AI_MODEL_FLAG_INSTALLED;
        if (stat(resolved, &st) == 0 && st.st_size > 0)
            model->size_bytes = (uint64_t)st.st_size;
    }
    return CUBE_AI_OK;
}

int cube_ai_registry_scan(cube_ai_registry *registry, const char *manifest_path)
{
    char *text = NULL;
    size_t text_size = 0;
    parser p;
    int rc;

    if (!registry)
        return CUBE_AI_ERR_INVALID;

    registry->count = 0;
    if (manifest_path && *manifest_path) {
        rc = copy_field(registry->manifest_path, sizeof(registry->manifest_path),
                        manifest_path);
    } else {
        rc = cube_ai_asset_join(registry->home, "manifest.jsonc",
                                registry->manifest_path,
                                sizeof(registry->manifest_path));
    }
    if (rc != CUBE_AI_OK)
        return rc;

    rc = read_text_file(registry->manifest_path, &text, &text_size);
    if (rc != CUBE_AI_OK)
        return rc;

    p.src = text;
    p.len = text_size;
    p.pos = 0;
    p.line = 1;

    parser_skip_space(&p);
    if (p.pos >= p.len) {
        rc = CUBE_AI_ERR_PARSE;
    } else if (p.src[p.pos] == '{') {
        rc = parser_object(&p, registry, 0);
    } else if (p.src[p.pos] == '[') {
        rc = parser_array(&p, registry, 0, NULL, NULL);
    } else {
        rc = CUBE_AI_ERR_PARSE;
    }

    if (rc == CUBE_AI_OK) {
        parser_skip_space(&p);
        if (p.pos != p.len)
            rc = CUBE_AI_ERR_PARSE;
    }
    free(text);

    if (rc != CUBE_AI_OK) {
        registry->count = 0;
        return rc;
    }
    return cube_ai_registry_refresh(registry);
}

size_t cube_ai_registry_count(const cube_ai_registry *registry)
{
    return registry ? registry->count : 0;
}

const cube_ai_model *cube_ai_registry_at(const cube_ai_registry *registry, size_t index)
{
    if (!registry || index >= registry->count)
        return NULL;
    return &registry->models[index];
}

const cube_ai_model *cube_ai_registry_find(const cube_ai_registry *registry, const char *name)
{
    size_t i;

    if (!registry || !name)
        return NULL;
    for (i = 0; i < registry->count; i++) {
        if (strcmp(registry->models[i].name, name) == 0)
            return &registry->models[i];
    }
    return NULL;
}

const cube_ai_model *cube_ai_registry_find_capability(const cube_ai_registry *registry,
                                                      cube_ai_capability capability)
{
    size_t i;

    if (!registry)
        return NULL;
    for (i = 0; i < registry->count; i++) {
        if (registry->models[i].capability == capability)
            return &registry->models[i];
    }
    return NULL;
}

const char *cube_ai_registry_home(const cube_ai_registry *registry)
{
    return registry ? registry->home : NULL;
}

const char *cube_ai_registry_manifest(const cube_ai_registry *registry)
{
    return registry ? registry->manifest_path : NULL;
}

int cube_ai_registry_resolve_asset(const cube_ai_registry *registry, const char *asset,
                                   char *out, size_t out_size)
{
    if (!registry)
        return CUBE_AI_ERR_INVALID;
    return cube_ai_asset_resolve_home(registry->home, asset, out, out_size);
}

int cube_ai_model_load(cube_ai_registry *registry, const char *name,
                       cube_ai_model_handle **out)
{
    const cube_ai_model *model;
    cube_ai_model_handle *handle;
    char weights[CUBE_AI_PATH_MAX];
    int rc;

    if (!registry || !name || !out)
        return CUBE_AI_ERR_INVALID;
    *out = NULL;

    model = cube_ai_registry_find(registry, name);
    if (!model)
        return CUBE_AI_ERR_NOT_FOUND;

    /* TODO: an explicit installer may populate CUBE_AI_HOME in the future.
     * Scan/load must never download models or fetch missing weights implicitly.
     */
    rc = cube_ai_registry_resolve_asset(registry, model->weights_path,
                                        weights, sizeof(weights));
    if (rc != CUBE_AI_OK)
        return rc;
    if (!cube_ai_asset_is_file(weights))
        return CUBE_AI_ERR_NOT_INSTALLED;

    if (model->sha256[0]) {
        rc = cube_ai_asset_verify_sha256(weights, model->sha256);
        if (rc != CUBE_AI_OK)
            return rc;
    }

    handle = calloc(1, sizeof(*handle));
    if (!handle)
        return CUBE_AI_ERR_NOMEM;
    handle->model = *model;
    if (copy_field(handle->weights_path, sizeof(handle->weights_path), weights) !=
        CUBE_AI_OK) {
        free(handle);
        return CUBE_AI_ERR_LIMIT;
    }
    handle->backend_loaded = 0;

    /* TODO: load the selected backend (tflite/onnx/ggml/custom) explicitly.
     * The scaffold deliberately performs no dlopen, subprocess, or network I/O.
     * A future backend vtable should populate backend_ctx and backend_loaded here.
     */
    *out = handle;
    return CUBE_AI_OK;
}

void cube_ai_model_unload(cube_ai_model_handle *handle)
{
    if (!handle)
        return;
    /* TODO: release backend_ctx through the registered backend vtable. */
    free(handle);
}

const cube_ai_model *cube_ai_model_descriptor(const cube_ai_model_handle *handle)
{
    return handle ? &handle->model : NULL;
}

const char *cube_ai_model_weights_path(const cube_ai_model_handle *handle)
{
    return handle ? handle->weights_path : NULL;
}

void cube_ai_response_init(cube_ai_response *response)
{
    if (!response)
        return;
    memset(response, 0, sizeof(*response));
}

void cube_ai_response_free(cube_ai_response *response)
{
    if (!response)
        return;
    free(response->data);
    memset(response, 0, sizeof(*response));
}

int cube_ai_model_infer(cube_ai_model_handle *handle, const cube_ai_request *request,
                        cube_ai_response *response)
{
    if (!handle || !request || !response)
        return CUBE_AI_ERR_INVALID;
    if (request->size > CUBE_AI_MAX_INPUT_BYTES)
        return CUBE_AI_ERR_LIMIT;
    if (!cube_ai_asset_is_file(handle->weights_path))
        return CUBE_AI_ERR_NOT_INSTALLED;

    /* TODO: dispatch to the loaded backend. Backends must enforce
     * CUBE_AI_MAX_INPUT_BYTES/CUBE_AI_MAX_OUTPUT_BYTES, validate tensor shapes,
     * and never download weights implicitly.
     */
    if (!handle->backend_loaded)
        return CUBE_AI_ERR_UNSUPPORTED;
    return CUBE_AI_ERR_UNSUPPORTED;
}
