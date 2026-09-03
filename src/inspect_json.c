#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct json_buffer {
  uint8_t *data;
  size_t size;
  size_t capacity;
} json_buffer_t;

static int reserve(json_buffer_t *buffer, size_t extra) {
  if (extra > SIZE_MAX - buffer->size - 1u)
    return 0;
  size_t required = buffer->size + extra + 1u;
  if (required <= buffer->capacity)
    return 1;
  size_t capacity = buffer->capacity ? buffer->capacity : 512u;
  while (capacity < required) {
    if (capacity > SIZE_MAX / 2u) {
      capacity = required;
      break;
    }
    capacity *= 2u;
  }
  uint8_t *grown = realloc(buffer->data, capacity);
  if (!grown)
    return 0;
  buffer->data = grown;
  buffer->capacity = capacity;
  return 1;
}

static int append_bytes(json_buffer_t *buffer, const char *value, size_t size) {
  if (!reserve(buffer, size))
    return 0;
  memcpy(buffer->data + buffer->size, value, size);
  buffer->size += size;
  buffer->data[buffer->size] = '\0';
  return 1;
}

static int append(json_buffer_t *buffer, const char *value) {
  return append_bytes(buffer, value, strlen(value));
}

static int append_json_string(json_buffer_t *buffer, const char *value) {
  if (!append(buffer, "\""))
    return 0;
  for (const unsigned char *at = (const unsigned char *)value; *at; ++at) {
    char escaped[7];
    if (*at == '"' || *at == '\\') {
      escaped[0] = '\\';
      escaped[1] = (char)*at;
      if (!append_bytes(buffer, escaped, 2u))
        return 0;
    } else if (*at < 0x20u || *at == 0x7fu) {
      (void)snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned)*at);
      if (!append_bytes(buffer, escaped, 6u))
        return 0;
    } else if (!append_bytes(buffer, (const char *)at, 1u)) {
      return 0;
    }
  }
  return append(buffer, "\"");
}

static const char *access_name(maelys_mir_fs_access_t access) {
  switch (access) {
  case MAELYS_MIR_FS_READ:
    return "read";
  case MAELYS_MIR_FS_WRITE:
    return "write";
  case MAELYS_MIR_FS_DENY:
    return "deny";
  }
  return "unknown";
}

static const char *root_name(maelys_mir_path_root_t root) {
  switch (root) {
  case MAELYS_MIR_ROOT_MINIMAL_RUNTIME:
    return "minimal-runtime";
  case MAELYS_MIR_ROOT_WORKSPACE:
    return "workspace";
  case MAELYS_MIR_ROOT_TEMP:
    return "temp";
  case MAELYS_MIR_ROOT_HOST:
    return "host";
  }
  return "unknown";
}

static const char *network_name(maelys_mir_network_mode_t network) {
  switch (network) {
  case MAELYS_MIR_NETWORK_NONE:
    return "none";
  case MAELYS_MIR_NETWORK_DIRECT:
    return "direct";
  case MAELYS_MIR_NETWORK_MEDIATED:
    return "mediated";
  }
  return "unknown";
}

static const char *root_mode_name(maelys_mir_root_mode_t mode) {
  return mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE ? "ephemeral-write"
                                                  : "read-only";
}

maelys_mir_result_t maelys_mir_inspect_json(const maelys_mir_t *mir,
                                            uint8_t **out_json,
                                            size_t *out_size, char **err) {
  if (out_json)
    *out_json = NULL;
  if (out_size)
    *out_size = 0u;
  if (!mir || !out_json || !out_size) {
    maelys_set_error(err, "MIR and inspection outputs are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }

  char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
  maelys_mir_result_t result = maelys_mir_digest_hex(mir, digest, err);
  if (result != MAELYS_MIR_OK)
    return result;

  json_buffer_t output = {0};
  if (!append(&output,
              "{\n  \"inspectionVersion\": 1,\n  \"mirFormatVersion\": 3,\n"
              "  \"identity\": {\n    \"algorithm\": \"sha256\",\n"
              "    \"basis\": \"canonical-mir-v3-bytes\",\n"
              "    \"decisionDigest\": \"") ||
      !append(&output, digest) ||
      !append(&output,
              "\"\n  },\n  \"filesystem\": {\n    \"default\": \"deny\",\n"
              "    \"rules\": ["))
    goto memory;

  for (size_t i = 0; i < mir->rule_count; ++i) {
    const maelys_mir_fs_rule_t *rule = &mir->rules[i];
    if (!append(&output, i == 0u ? "\n      {\n" : ",\n      {\n") ||
        !append(&output, "        \"access\": ") ||
        !append_json_string(&output, access_name(rule->access)) ||
        !append(&output, ",\n        \"root\": ") ||
        !append_json_string(&output, root_name(rule->root)) ||
        !append(&output, ",\n        \"path\": ") ||
        !append_json_string(&output, rule->relative) ||
        !append(&output, ",\n        \"scope\": ") ||
        !append_json_string(&output, rule->scope == MAELYS_MIR_SCOPE_TREE
                                         ? "tree"
                                         : "exact") ||
        !append(&output, ",\n        \"missing\": ") ||
        !append_json_string(&output,
                            rule->missing == MAELYS_MIR_MISSING_SKIP
                                ? "skip"
                                : "error") ||
        !append(&output, "\n      }"))
      goto memory;
  }
  if (mir->rule_count && !append(&output, "\n    "))
    goto memory;
  if (!append(&output, "]\n  },\n  \"network\": {\n    \"mode\": ") ||
      !append_json_string(&output, network_name(mir->network)))
    goto memory;

  if (mir->network_destination_count) {
    if (!append(&output, ",\n    \"allow\": ["))
      goto memory;
    for (size_t i = 0; i < mir->network_destination_count; ++i) {
      const maelys_mir_network_destination_t *destination =
          &mir->network_destinations[i];
      char port[16];
      (void)snprintf(port, sizeof(port), "%u", (unsigned)destination->port);
      if (!append(&output, i == 0u ? "\n      {\n" : ",\n      {\n") ||
          !append(&output, "        \"protocol\": \"tcp\",\n") ||
          !append(&output, "        \"host\": ") ||
          !append_json_string(&output, destination->host) ||
          !append(&output, ",\n        \"port\": ") || !append(&output, port) ||
          !append(&output, "\n      }"))
        goto memory;
    }
    if (!append(&output, "\n    ]"))
      goto memory;
  }
  if (!append(&output, "\n  },\n  \"root\": {\n    \"mode\": ") ||
      !append_json_string(&output, root_mode_name(mir->root_mode)) ||
      !append(&output,
              "\n  },\n  \"process\": {\n    \"treeConfinement\": ") ||
      !append_json_string(&output,
                          mir->process_tree_required ? "required" : "disabled") ||
      !append(&output, "\n  }\n}\n"))
    goto memory;

  *out_json = output.data;
  *out_size = output.size;
  return MAELYS_MIR_OK;

memory:
  free(output.data);
  maelys_set_error(err, "out of memory while rendering MIR inspection JSON");
  return MAELYS_MIR_ERR_MEMORY;
}
