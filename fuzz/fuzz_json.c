#include <maelys/mir.h>

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  maelys_mir_t *mir = NULL;
  char *error = NULL;
  (void)maelys_mir_compile_json(data, size, &mir, &error);
  maelys_mir_destroy(mir);
  maelys_mir_error_free(error);
  return 0;
}
