#include <maelys/mir.h>

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  maelys_mir_t *mir = NULL;
  char *error = NULL;
  if (maelys_mir_decode(data, size, &mir, &error) == MAELYS_MIR_OK) {
    uint8_t *encoded = NULL;
    size_t encoded_size = 0;
    if (maelys_mir_encode(mir, &encoded, &encoded_size, NULL) ==
        MAELYS_MIR_OK) {
      maelys_mir_bytes_free(encoded);
    }
  }
  maelys_mir_destroy(mir);
  maelys_mir_error_free(error);
  return 0;
}
