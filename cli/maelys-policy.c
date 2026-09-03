#include <maelys/mir.h>
#include <maelys/sandbox_policy.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **out, size_t *out_size) {
  *out = NULL;
  *out_size = 0;
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "maelys-policy: %s: %s\n", path, strerror(errno));
    return 0;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  long end = ftell(f);
  if (end < 0 || (unsigned long)end > MAELYS_MIR_MAX_BYTES) {
    fprintf(stderr, "maelys-policy: input exceeds limit\n");
    fclose(f);
    return 0;
  }
  rewind(f);
  uint8_t *data = malloc((size_t)end + (end == 0));
  if (!data) {
    fclose(f);
    return 0;
  }
  size_t got = fread(data, 1, (size_t)end, f);
  if (got != (size_t)end || fclose(f) != 0) {
    free(data);
    return 0;
  }
  *out = data;
  *out_size = got;
  return 1;
}
static int write_file(const char *path, const uint8_t *data, size_t size) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    fprintf(stderr, "maelys-policy: %s: %s\n", path, strerror(errno));
    return 0;
  }
  int ok = fwrite(data, 1, size, f) == size && fclose(f) == 0;
  if (!ok)
    fprintf(stderr, "maelys-policy: failed writing %s\n", path);
  return ok;
}
static int report(maelys_mir_result_t r, char *error) {
  if (r == MAELYS_MIR_OK)
    return 1;
  fprintf(stderr, "maelys-policy: %s: %s\n", maelys_mir_result_name(r),
          error ? error : "no diagnostic");
  maelys_mir_error_free(error);
  return 0;
}
static void usage(FILE *out) {
  fprintf(out,
          "usage:\n"
          "  maelys-policy compile SOURCE.json -o POLICY.mir\n"
          "  maelys-policy validate POLICY.mir\n"
          "  maelys-policy hash POLICY.mir\n"
          "  maelys-policy inspect POLICY.mir\n"
          "  maelys-policy artifact-hash FILE\n");
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    puts(MAELYS_SANDBOX_POLICY_VERSION);
    return 0;
  }
  if (argc < 3) {
    usage(stderr);
    return 2;
  }
  uint8_t *input = NULL;
  size_t input_size = 0;
  if (!read_file(argv[2], &input, &input_size))
    return 1;
  char *error = NULL;
  maelys_mir_t *mir = NULL;
  maelys_mir_result_t r;
  if (strcmp(argv[1], "compile") == 0) {
    if (argc != 5 || strcmp(argv[3], "-o") != 0) {
      free(input);
      usage(stderr);
      return 2;
    }
    r = maelys_mir_compile_json(input, input_size, &mir, &error);
    free(input);
    if (!report(r, error))
      return 1;
    uint8_t *bytes = NULL;
    size_t size = 0;
    error = NULL;
    r = maelys_mir_encode(mir, &bytes, &size, &error);
    maelys_mir_destroy(mir);
    if (!report(r, error))
      return 1;
    int ok = write_file(argv[4], bytes, size);
    maelys_mir_bytes_free(bytes);
    return ok ? 0 : 1;
  }
  if (argc != 3) {
    free(input);
    usage(stderr);
    return 2;
  }
  if (strcmp(argv[1], "artifact-hash") == 0) {
    char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
    r = maelys_mir_artifact_digest_hex(input, input_size, digest, &error);
    free(input);
    if (!report(r, error))
      return 1;
    printf("sha256:%s\n", digest);
    return 0;
  }
  r = maelys_mir_decode(input, input_size, &mir, &error);
  free(input);
  if (!report(r, error))
    return 1;
  if (strcmp(argv[1], "validate") == 0) {
    printf("valid MIR v%u\n", MAELYS_MIR_FORMAT_VERSION);
  } else if (strcmp(argv[1], "hash") == 0) {
    char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
    error = NULL;
    r = maelys_mir_digest_hex(mir, digest, &error);
    if (!report(r, error)) {
      maelys_mir_destroy(mir);
      return 1;
    }
    printf("sha256:%s\n", digest);
  } else if (strcmp(argv[1], "inspect") == 0) {
    uint8_t *json = NULL;
    size_t size = 0;
    error = NULL;
    r = maelys_mir_inspect_json(mir, &json, &size, &error);
    if (!report(r, error)) {
      maelys_mir_destroy(mir);
      return 1;
    }
    if (fwrite(json, 1u, size, stdout) != size) {
      fprintf(stderr, "maelys-policy: failed writing inspection output\n");
      maelys_mir_bytes_free(json);
      maelys_mir_destroy(mir);
      return 1;
    }
    maelys_mir_bytes_free(json);
  } else {
    maelys_mir_destroy(mir);
    usage(stderr);
    return 2;
  }
  maelys_mir_destroy(mir);
  return 0;
}
