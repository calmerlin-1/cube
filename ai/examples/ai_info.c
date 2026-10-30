#include "cube_ai.h"

#include <stdio.h>

int main(void)
{
    cube_ai_registry *registry;
    size_t i;
    int capability;
    int rc;

    registry = cube_ai_registry_init(NULL);
    if (!registry) {
        fprintf(stderr, "ai_info: failed to initialize registry\n");
        return 1;
    }

    rc = cube_ai_registry_scan(registry, NULL);
    printf("CUBE AI capability layer v%d\n", CUBE_AI_API_VERSION);
    printf("home:     %s\n", cube_ai_registry_home(registry));
    printf("manifest: %s\n", cube_ai_registry_manifest(registry));
    if (rc != CUBE_AI_OK) {
        fprintf(stderr, "ai_info: scan failed: %s\n", cube_ai_status_string(rc));
        cube_ai_registry_free(registry);
        return 1;
    }

    printf("models:   %zu\n\n", cube_ai_registry_count(registry));

    for (capability = 0; capability < CUBE_AI_CAP_COUNT; capability++) {
        const cube_ai_model *model =
            cube_ai_registry_find_capability(registry,
                                             (cube_ai_capability)capability);
        printf("capability %-16s %s\n",
               cube_ai_capability_name((cube_ai_capability)capability),
               model ? model->name : "(not configured)");
    }

    for (i = 0; i < cube_ai_registry_count(registry); i++) {
        const cube_ai_model *model = cube_ai_registry_at(registry, i);
        char weights[CUBE_AI_PATH_MAX];

        printf("\n[%zu] %s\n", i + 1, model->name);
        printf("  capability: %s\n", cube_ai_capability_name(model->capability));
        printf("  version:    %s\n", model->version);
        printf("  backend:    %s\n", model->backend);
        printf("  state:      %s\n", model->installed ? "installed" : "not installed");
        if (cube_ai_registry_resolve_asset(registry, model->weights_path,
                                           weights, sizeof(weights)) == CUBE_AI_OK)
            printf("  weights:    %s\n", weights);
        else
            printf("  weights:    %s\n", model->weights_path);
        printf("  config:     %s\n",
               model->config_path[0] ? model->config_path : "(none)");
        printf("  sha256:     %s\n", model->sha256[0] ? model->sha256 : "unpinned");
        printf("  formats:    %s -> %s\n",
               model->input_format, model->output_format);
        printf("  flags:      %s%s%s\n",
               (model->flags & CUBE_AI_MODEL_FLAG_OPTIONAL) ? "optional " : "",
               (model->flags & CUBE_AI_MODEL_FLAG_QUANTIZED) ? "quantized " : "",
               (model->flags & CUBE_AI_MODEL_FLAG_REQUIRES_NET) ? "requires-net " : "");
    }

    cube_ai_registry_free(registry);
    return 0;
}
