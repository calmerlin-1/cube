#ifndef CUBE_AI_INTERNAL_H
#define CUBE_AI_INTERNAL_H

#include "cube_ai.h"

struct cube_ai_registry {
    cube_ai_model models[CUBE_AI_MAX_MODELS];
    size_t count;
    char home[CUBE_AI_PATH_MAX];
    char manifest_path[CUBE_AI_PATH_MAX];
};

struct cube_ai_model_handle {
    cube_ai_model model;
    char weights_path[CUBE_AI_PATH_MAX];
    int backend_loaded;
    void *backend_ctx;
};

int cube_ai_asset_exists(const char *path);
int cube_ai_asset_is_dir(const char *path);
int cube_ai_asset_is_file(const char *path);
int cube_ai_asset_join(const char *base, const char *asset, char *out, size_t out_size);

#endif
