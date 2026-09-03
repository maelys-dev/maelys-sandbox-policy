#include <maelys/mir.h>

#include <emscripten/emscripten.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *result_mir;
static size_t result_mir_size;
static char *result_mir_hex;
static uint8_t *result_inspection;
static size_t result_inspection_size;
static char result_digest[MAELYS_MIR_DIGEST_HEX_SIZE];
static char *result_error;

EMSCRIPTEN_KEEPALIVE void maelys_wasm_reset(void) {
  maelys_mir_bytes_free(result_mir);
  free(result_mir_hex);
  maelys_mir_bytes_free(result_inspection);
  maelys_mir_error_free(result_error);
  result_mir = NULL;
  result_mir_size = 0u;
  result_mir_hex = NULL;
  result_inspection = NULL;
  result_inspection_size = 0u;
  result_digest[0] = '\0';
  result_error = NULL;
}

EMSCRIPTEN_KEEPALIVE int maelys_wasm_compile_text(const char *json) {
  maelys_wasm_reset();
  if (!json)
    return (int)MAELYS_MIR_ERR_ARGUMENT;
  maelys_mir_t *mir = NULL;
  maelys_mir_result_t result = maelys_mir_compile_json(
      (const uint8_t *)json, strlen(json), &mir, &result_error);
  if (result == MAELYS_MIR_OK)
    result = maelys_mir_encode(mir, &result_mir, &result_mir_size,
                               &result_error);
  if (result == MAELYS_MIR_OK) {
    static const char hex[] = "0123456789abcdef";
    if (result_mir_size > (SIZE_MAX - 1u) / 2u) {
      result = MAELYS_MIR_ERR_LIMIT;
    } else {
      result_mir_hex = malloc(result_mir_size * 2u + 1u);
      if (!result_mir_hex) {
        result = MAELYS_MIR_ERR_MEMORY;
      } else {
        for (size_t i = 0; i < result_mir_size; ++i) {
          result_mir_hex[2u * i] = hex[result_mir[i] >> 4];
          result_mir_hex[2u * i + 1u] = hex[result_mir[i] & 15u];
        }
        result_mir_hex[result_mir_size * 2u] = '\0';
      }
    }
  }
  if (result == MAELYS_MIR_OK)
    result = maelys_mir_digest_hex(mir, result_digest, &result_error);
  if (result == MAELYS_MIR_OK)
    result = maelys_mir_inspect_json(mir, &result_inspection,
                                     &result_inspection_size, &result_error);
  maelys_mir_destroy(mir);
  if (result != MAELYS_MIR_OK) {
    maelys_mir_bytes_free(result_mir);
    maelys_mir_bytes_free(result_inspection);
    free(result_mir_hex);
    result_mir = NULL;
    result_mir_size = 0u;
    result_mir_hex = NULL;
    result_inspection = NULL;
    result_inspection_size = 0u;
    result_digest[0] = '\0';
  }
  return (int)result;
}

EMSCRIPTEN_KEEPALIVE const char *maelys_wasm_mir_hex(void) {
  return result_mir_hex ? result_mir_hex : "";
}

EMSCRIPTEN_KEEPALIVE uint32_t maelys_wasm_mir_size(void) {
  return (uint32_t)result_mir_size;
}

EMSCRIPTEN_KEEPALIVE const char *maelys_wasm_digest(void) {
  return result_digest;
}

EMSCRIPTEN_KEEPALIVE const char *maelys_wasm_inspection(void) {
  return result_inspection ? (const char *)result_inspection : "";
}

EMSCRIPTEN_KEEPALIVE const char *maelys_wasm_error(void) {
  return result_error ? result_error : "";
}
