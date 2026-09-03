#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void maelys_mir_error_free(char *error) { free(error); }
void maelys_mir_bytes_free(uint8_t *bytes) { free(bytes); }

const char *maelys_mir_result_name(maelys_mir_result_t result) {
  switch (result) {
  case MAELYS_MIR_OK:
    return "ok";
  case MAELYS_MIR_ERR_ARGUMENT:
    return "argument";
  case MAELYS_MIR_ERR_MEMORY:
    return "memory";
  case MAELYS_MIR_ERR_FORMAT:
    return "format";
  case MAELYS_MIR_ERR_LIMIT:
    return "limit";
  case MAELYS_MIR_ERR_NON_CANONICAL:
    return "non_canonical";
  case MAELYS_MIR_ERR_IO:
    return "io";
  case MAELYS_MIR_ERR_UNSUPPORTED:
    return "unsupported";
  case MAELYS_MIR_ERR_MISSING:
    return "missing";
  }
  return "unknown";
}

void maelys_set_error(char **out_error, const char *format, ...) {
  if (!out_error || *out_error)
    return;
  va_list args;
  va_start(args, format);
  va_list copy;
  va_copy(copy, args);
  int size = vsnprintf(NULL, 0, format, copy);
  va_end(copy);
  if (size >= 0) {
    char *message = malloc((size_t)size + 1u);
    if (message && vsnprintf(message, (size_t)size + 1u, format, args) >= 0) {
      *out_error = message;
    } else {
      free(message);
    }
  }
  va_end(args);
}

char *maelys_strdup(const char *value) {
  if (!value)
    return NULL;
  size_t size = strlen(value) + 1u;
  char *copy = malloc(size);
  if (copy)
    memcpy(copy, value, size);
  return copy;
}

int maelys_valid_utf8_no_nul(const uint8_t *s, size_t size) {
  size_t i = 0;
  while (i < size) {
    uint8_t c = s[i++];
    if (c == 0)
      return 0;
    if (c < 0x80)
      continue;
    unsigned need;
    uint32_t value;
    uint32_t minimum;
    if ((c & 0xe0u) == 0xc0u) {
      need = 1;
      value = c & 0x1fu;
      minimum = 0x80u;
    } else if ((c & 0xf0u) == 0xe0u) {
      need = 2;
      value = c & 0x0fu;
      minimum = 0x800u;
    } else if ((c & 0xf8u) == 0xf0u) {
      need = 3;
      value = c & 0x07u;
      minimum = 0x10000u;
    } else {
      return 0;
    }
    if (size - i < need)
      return 0;
    for (unsigned j = 0; j < need; ++j) {
      uint8_t d = s[i++];
      if ((d & 0xc0u) != 0x80u)
        return 0;
      value = (value << 6) | (uint32_t)(d & 0x3fu);
    }
    if (value < minimum || value > 0x10ffffu ||
        (value >= 0xd800u && value <= 0xdfffu))
      return 0;
  }
  return 1;
}

maelys_mir_result_t maelys_normalize_relative(maelys_mir_path_root_t root,
                                              const char *input, char **out,
                                              char **out_error) {
  if (out)
    *out = NULL;
  if (!out || !input) {
    maelys_set_error(out_error, "path and output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  size_t size = strlen(input);
  if (size > MAELYS_MIR_MAX_STRING_BYTES) {
    maelys_set_error(out_error, "path exceeds %u bytes",
                     MAELYS_MIR_MAX_STRING_BYTES);
    return MAELYS_MIR_ERR_LIMIT;
  }
  if (!maelys_valid_utf8_no_nul((const uint8_t *)input, size)) {
    maelys_set_error(out_error, "path must be valid UTF-8 without NUL");
    return MAELYS_MIR_ERR_FORMAT;
  }
  int host = root == MAELYS_MIR_ROOT_HOST;
  if ((host && (size == 0 || input[0] != '/')) ||
      (!host && size && input[0] == '/')) {
    maelys_set_error(out_error, host ? "host path must be absolute"
                                     : "symbolic-root path must be relative");
    return MAELYS_MIR_ERR_FORMAT;
  }
  char *normalized = malloc(size + 2u);
  if (!normalized)
    return MAELYS_MIR_ERR_MEMORY;
  size_t n = 0, i = host ? 1u : 0u;
  if (host)
    normalized[n++] = '/';
  while (i < size) {
    while (i < size && input[i] == '/')
      ++i;
    size_t start = i;
    while (i < size && input[i] != '/')
      ++i;
    size_t part = i - start;
    if (!part || (part == 1 && input[start] == '.'))
      continue;
    if (part == 2 && input[start] == '.' && input[start + 1] == '.') {
      free(normalized);
      maelys_set_error(out_error, "parent path components are forbidden");
      return MAELYS_MIR_ERR_FORMAT;
    }
    if (n && normalized[n - 1] != '/')
      normalized[n++] = '/';
    memcpy(normalized + n, input + start, part);
    n += part;
  }
  if (host && n > 1 && normalized[n - 1] == '/')
    --n;
  normalized[n] = '\0';
  *out = normalized;
  return MAELYS_MIR_OK;
}
