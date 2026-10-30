# CUBE AI capability layer

A dependency-free scaffold for plugging local AI models into cube later. It
builds a standalone static library, parses a model manifest, resolves model
assets, verifies optional checksums, and exposes load/infer hooks. It does not
download, bundle, or load any model or shared library today.

## Build

```sh
make -C ai          # build/libcube_ai.a
make -C ai info     # build and run the ai_info example
make -C ai clean
```

`make -C ai info` points `CUBE_AI_HOME` at `ai/models` so the example can run
from inside `ai/`. The library itself is not linked into the root build.

## Layout

```text
ai/
  include/cube_ai.h       public API
  src/ai_registry.c       manifest parser, registry, lookup, load/infer hooks
  src/ai_asset.c          path resolution, existence checks, SHA-256
  src/ai_internal.h       private registry/handle layout
  models/manifest.jsonc   model descriptors (no weights included)
  examples/ai_info.c      manifest inspection example
  Makefile                static library + info example
```

## Architecture

The layer is split into four pieces:

1. **Manifest and registry.** `cube_ai_registry_scan()` reads a JSONC-compatible
   manifest with a small built-in parser. It supports comments, trailing
   commas, strings, arrays, nested objects, and ignores unknown fields. Each
   model object is added to a bounded registry.
2. **Asset resolution.** `cube_ai_asset_home()` selects the model root in this
   order: `$CUBE_AI_HOME`, then `$HOME/.local/share/cube/ai`, then
   `./ai/models`. `cube_ai_asset_resolve_home()` and
   `cube_ai_registry_resolve_asset()` join relative model paths to that root.
3. **Install state and integrity.** `cube_ai_registry_refresh()` marks a model
   installed only when its weights file exists. `cube_ai_asset_verify_sha256()`
   computes SHA-256 locally and compares a pinned manifest digest. An empty
   digest means "not pinned yet" and is accepted for now.
4. **Load and infer hooks.** `cube_ai_model_load()` checks the weights path and
   checksum, then creates an opaque handle. Backend loading is intentionally a
   TODO in this scaffold. `cube_ai_model_infer()` returns
   `CUBE_AI_ERR_UNSUPPORTED` until a backend is registered.

Capabilities are `CUBE_AI_CAP_OCR`, `CUBE_AI_CAP_IMAGE_CLASSIFY`,
`CUBE_AI_CAP_SPEECH`, and `CUBE_AI_CAP_CAPTCHA_SLIDER`.

## Manifest

`models/manifest.jsonc` describes the intended models:

| name | capability | backend | weights |
| --- | --- | --- | --- |
| `ppocr-v4` | OCR | `onnx` | `ppocr-v4/ppocr-v4.onnx` |
| `mobilenetv2` | image classification | `tflite` | `mobilenetv2/mobilenetv2.tflite` |
| `whisper-base` | speech-to-text | `ggml` | `whisper-base/ggml-base.bin` |
| `slider-captcha-v1` | slider captcha | `custom` | `slider-captcha-v1/slider-captcha-v1.bin` |

Fields per model:

- `name`, `capability`, `version`, `backend`
- `weights`, `config` (relative to the model root)
- `sha256` (64 lowercase hex characters, or empty until pinned)
- `input`, `output` (format names understood by the future backend)
- `flags` (`optional`, `quantized`, `requires_net`)

Installed state is never trusted from the manifest. It is derived from the
filesystem during scan/refresh. The `CUBE_AI_MODEL_FLAG_INSTALLED` flag and
`installed` field are updated dynamically.

## Adding a model

1. Create `ai/models/<model-name>/` and place the weights/config there. This is
   an explicit operator action; cube must never fetch them automatically.
2. Add a descriptor to `ai/models/manifest.jsonc` with the correct capability,
   backend, input/output formats, and weights path.
3. Pin the weights digest with:

   ```sh
   sha256sum ai/models/<model-name>/<weights-file>
   ```

   Put the result in the descriptor's `sha256` field.
4. Run `make -C ai info` and confirm the model appears with state `installed`.

## Adding a backend later

The current load path deliberately contains no `dlopen`, subprocess, or network
code. A future backend should be added behind the TODO hooks in
`ai/src/ai_registry.c`:

- register a backend vtable keyed by the descriptor's `backend` name;
- open only an explicitly configured local backend/library path;
- populate `cube_ai_model_handle.backend_ctx` and `backend_loaded`;
- implement `cube_ai_model_infer()` dispatch for the request/response structs;
- release `backend_ctx` from `cube_ai_model_unload()`;
- enforce input/output byte limits and validate all tensor shapes.

Adding a new capability means extending `cube_ai_capability` and its name
mapping. Keep manifest parsing and asset handling independent of any one model
family so future capabilities can reuse them.

## How cube will consume it

A future cube integration should link `ai/build/libcube_ai.a` and:

```c
cube_ai_registry *registry = cube_ai_registry_init(NULL);
cube_ai_registry_scan(registry, NULL);

const cube_ai_model *model =
    cube_ai_registry_find_capability(registry, CUBE_AI_CAP_OCR);

cube_ai_model_handle *handle = NULL;
if (cube_ai_model_load(registry, model->name, &handle) == CUBE_AI_OK) {
    cube_ai_request request = {0};
    cube_ai_response response;
    cube_ai_response_init(&response);

    request.data = image_bytes;
    request.size = image_size;
    request.input_format = model->input_format;

    if (cube_ai_model_infer(handle, &request, &response) == CUBE_AI_OK) {
        /* use response.data / response.size / response.metadata */
    }

    cube_ai_response_free(&response);
    cube_ai_model_unload(handle);
}
cube_ai_registry_free(registry);
```

The current example only inspects the manifest and never loads weights.

## Security rules

- **Explicit install only.** Models are installed by the operator or package
  manager. There is no auto-download and no background update path.
- **Checksums before use.** Pin SHA-256 digests in the manifest. Empty digests
  are placeholders and must be filled before production use.
- **No implicit network or dynamic loading.** This scaffold contains neither.
  Future backends must require an explicit local library path and must not fetch
  model files or code at inference time.
- **Treat models as untrusted input.** Validate manifests, paths, tensor shapes,
  and metadata. Reject absolute or escaping asset paths if a manifest is not
  trusted.
- **Memory caps.** Requests are limited by `CUBE_AI_MAX_INPUT_BYTES` (64 MiB),
  responses by `CUBE_AI_MAX_OUTPUT_BYTES` (64 MiB), and manifests by
  `CUBE_AI_MAX_MANIFEST_BYTES` (1 MiB). Backends must enforce these and reject
  oversized allocations.
- **Least privilege.** Run inference with only the model directory readable and
  no network access unless a capability explicitly requires it.
