#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 20u
#define RECORD_FIXED_SIZE 12u
#define NETWORK_RECORD_FIXED_SIZE 8u

static int valid_access(maelys_mir_fs_access_t v) {
  return v >= MAELYS_MIR_FS_READ && v <= MAELYS_MIR_FS_DENY;
}
static int valid_root(maelys_mir_path_root_t v) {
  return v >= MAELYS_MIR_ROOT_MINIMAL_RUNTIME && v <= MAELYS_MIR_ROOT_HOST;
}
static int valid_scope(maelys_mir_path_scope_t v) {
  return v == MAELYS_MIR_SCOPE_EXACT || v == MAELYS_MIR_SCOPE_TREE;
}
static int valid_missing(maelys_mir_missing_path_t v) {
  return v == MAELYS_MIR_MISSING_ERROR || v == MAELYS_MIR_MISSING_SKIP;
}
static int valid_network(maelys_mir_network_mode_t v) {
  return v >= MAELYS_MIR_NETWORK_NONE && v <= MAELYS_MIR_NETWORK_MEDIATED;
}
static int valid_network_protocol(maelys_mir_network_protocol_t v) {
  return v == MAELYS_MIR_NETWORK_PROTOCOL_TCP;
}
static int valid_root_mode(maelys_mir_root_mode_t v) {
  return v == MAELYS_MIR_ROOT_READ_ONLY ||
         v == MAELYS_MIR_ROOT_EPHEMERAL_WRITE;
}

static int valid_dns_host(const char *host) {
  if (!host)
    return 0;
  size_t length = strlen(host);
  if (length == 0 || length > MAELYS_MIR_MAX_NETWORK_HOST_BYTES ||
      host[0] == '.' || host[length - 1u] == '.')
    return 0;
  size_t label_length = 0;
  for (size_t i = 0; i < length; ++i) {
    unsigned char c = (unsigned char)host[i];
    if (c == '.') {
      if (label_length == 0 || label_length > 63u || host[i - 1u] == '-')
        return 0;
      label_length = 0;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-'))
      return 0;
    if (label_length == 0 && c == '-')
      return 0;
    ++label_length;
  }
  return label_length > 0 && label_length <= 63u && host[length - 1u] != '-';
}

static char *canonical_dns_host(const char *host) {
  if (!valid_dns_host(host))
    return NULL;
  char *copy = maelys_strdup(host);
  if (!copy)
    return NULL;
  for (size_t i = 0; copy[i]; ++i) {
    if (copy[i] >= 'A' && copy[i] <= 'Z')
      copy[i] = (char)(copy[i] - 'A' + 'a');
  }
  return copy;
}

static int rule_key_compare(const void *left, const void *right) {
  const maelys_mir_fs_rule_t *a = left, *b = right;
  if (a->root != b->root)
    return a->root < b->root ? -1 : 1;
  int path = strcmp(a->relative, b->relative);
  if (path)
    return path;
  if (a->scope != b->scope)
    return a->scope < b->scope ? -1 : 1;
  if (a->missing != b->missing)
    return a->missing < b->missing ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  return 0;
}

static int same_target(const maelys_mir_fs_rule_t *a,
                       const maelys_mir_fs_rule_t *b) {
  return a->root == b->root && a->scope == b->scope &&
         a->missing == b->missing && strcmp(a->relative, b->relative) == 0;
}

static int network_destination_compare(const void *left, const void *right) {
  const maelys_mir_network_destination_t *a = left, *b = right;
  int host = strcmp(a->host, b->host);
  if (host)
    return host;
  if (a->protocol != b->protocol)
    return a->protocol < b->protocol ? -1 : 1;
  if (a->port != b->port)
    return a->port < b->port ? -1 : 1;
  return 0;
}

static void free_rules(maelys_mir_fs_rule_t *rules, size_t count) {
  if (!rules)
    return;
  for (size_t i = 0; i < count; ++i)
    free(rules[i].relative);
  free(rules);
}

static void free_network_destinations(maelys_mir_network_destination_t *items,
                                      size_t count) {
  if (!items)
    return;
  for (size_t i = 0; i < count; ++i)
    free(items[i].host);
  free(items);
}

maelys_mir_result_t maelys_mir_builder_create(maelys_mir_builder_t **out,
                                              char **err) {
  if (out)
    *out = NULL;
  if (!out) {
    maelys_set_error(err, "builder output is required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_mir_builder_t *b = calloc(1, sizeof(*b));
  if (!b)
    return MAELYS_MIR_ERR_MEMORY;
  b->network = MAELYS_MIR_NETWORK_NONE;
  b->root_mode = MAELYS_MIR_ROOT_READ_ONLY;
  b->process_tree_required = 1;
  *out = b;
  return MAELYS_MIR_OK;
}

void maelys_mir_builder_destroy(maelys_mir_builder_t *b) {
  if (!b)
    return;
  free_rules(b->rules, b->rule_count);
  free_network_destinations(b->network_destinations,
                            b->network_destination_count);
  free(b);
}

maelys_mir_result_t maelys_mir_builder_add_fs_rule(
    maelys_mir_builder_t *b, maelys_mir_fs_access_t access,
    maelys_mir_path_root_t root, const char *relative,
    maelys_mir_path_scope_t scope, maelys_mir_missing_path_t missing,
    char **err) {
  if (!b || !valid_access(access) || !valid_root(root) || !valid_scope(scope) ||
      !valid_missing(missing)) {
    maelys_set_error(err, "invalid filesystem rule");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  char *normalized = NULL;
  maelys_mir_result_t result = maelys_normalize_relative(
      root, relative ? relative : "", &normalized, err);
  if (result != MAELYS_MIR_OK)
    return result;
  for (size_t i = 0; i < b->rule_count; ++i) {
    maelys_mir_fs_rule_t candidate = {access, root, scope, missing, normalized};
    if (same_target(&b->rules[i], &candidate)) {
      /* Codex conflict precedence: deny > write > read. */
      if (access > b->rules[i].access)
        b->rules[i].access = access;
      free(normalized);
      return MAELYS_MIR_OK;
    }
  }
  if (b->rule_count == MAELYS_MIR_MAX_RULES) {
    free(normalized);
    maelys_set_error(err, "MIR exceeds %u rules", MAELYS_MIR_MAX_RULES);
    return MAELYS_MIR_ERR_LIMIT;
  }
  if (b->rule_count == b->rule_capacity) {
    size_t next = b->rule_capacity ? b->rule_capacity * 2u : 16u;
    maelys_mir_fs_rule_t *grown = realloc(b->rules, next * sizeof(*grown));
    if (!grown) {
      free(normalized);
      return MAELYS_MIR_ERR_MEMORY;
    }
    b->rules = grown;
    b->rule_capacity = next;
  }
  b->rules[b->rule_count++] =
      (maelys_mir_fs_rule_t){access, root, scope, missing, normalized};
  return MAELYS_MIR_OK;
}

maelys_mir_result_t
maelys_mir_builder_set_network(maelys_mir_builder_t *b,
                               maelys_mir_network_mode_t mode, char **err) {
  if (!b || !valid_network(mode)) {
    maelys_set_error(err, "invalid network mode");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  b->network = mode;
  return MAELYS_MIR_OK;
}

maelys_mir_result_t
maelys_mir_builder_set_root_mode(maelys_mir_builder_t *b,
                                 maelys_mir_root_mode_t mode, char **err) {
  if (!b || !valid_root_mode(mode)) {
    maelys_set_error(err, "invalid root mode");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  b->root_mode = mode;
  return MAELYS_MIR_OK;
}

maelys_mir_result_t maelys_mir_builder_add_network_destination(
    maelys_mir_builder_t *b, maelys_mir_network_protocol_t protocol,
    const char *host, uint16_t port, char **err) {
  if (!b || !valid_network_protocol(protocol) || port == 0 ||
      !valid_dns_host(host)) {
    maelys_set_error(err, "invalid mediated network destination");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  char *canonical = canonical_dns_host(host);
  if (!canonical)
    return MAELYS_MIR_ERR_MEMORY;
  for (size_t i = 0; i < b->network_destination_count; ++i) {
    maelys_mir_network_destination_t *existing = &b->network_destinations[i];
    if (existing->protocol == protocol && existing->port == port &&
        strcmp(existing->host, canonical) == 0) {
      free(canonical);
      return MAELYS_MIR_OK;
    }
  }
  if (b->network_destination_count == MAELYS_MIR_MAX_NETWORK_DESTINATIONS) {
    free(canonical);
    maelys_set_error(err, "MIR exceeds %u network destinations",
                     MAELYS_MIR_MAX_NETWORK_DESTINATIONS);
    return MAELYS_MIR_ERR_LIMIT;
  }
  if (b->network_destination_count == b->network_destination_capacity) {
    size_t next = b->network_destination_capacity
                      ? b->network_destination_capacity * 2u
                      : 8u;
    maelys_mir_network_destination_t *grown =
        realloc(b->network_destinations, next * sizeof(*grown));
    if (!grown) {
      free(canonical);
      return MAELYS_MIR_ERR_MEMORY;
    }
    b->network_destinations = grown;
    b->network_destination_capacity = next;
  }
  b->network_destinations[b->network_destination_count++] =
      (maelys_mir_network_destination_t){protocol, canonical, port};
  return MAELYS_MIR_OK;
}

maelys_mir_result_t
maelys_mir_builder_set_process_tree_required(maelys_mir_builder_t *b,
                                             int required, char **err) {
  if (!b || (required != 0 && required != 1)) {
    maelys_set_error(err, "process-tree requirement must be boolean");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  b->process_tree_required = required;
  return MAELYS_MIR_OK;
}

maelys_mir_result_t maelys_mir_builder_build(maelys_mir_builder_t *b,
                                             maelys_mir_t **out, char **err) {
  if (out)
    *out = NULL;
  if (!b || !out) {
    maelys_set_error(err, "builder and output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  if ((b->network == MAELYS_MIR_NETWORK_MEDIATED) !=
      (b->network_destination_count > 0u)) {
    maelys_set_error(
        err,
        "mediated network requires a non-empty allowlist and other modes forbid one");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_mir_t *mir = calloc(1, sizeof(*mir));
  if (!mir)
    return MAELYS_MIR_ERR_MEMORY;
  if (b->rule_count) {
    mir->rules = calloc(b->rule_count, sizeof(*mir->rules));
    if (!mir->rules) {
      free(mir);
      return MAELYS_MIR_ERR_MEMORY;
    }
    for (size_t i = 0; i < b->rule_count; ++i) {
      mir->rules[i] = b->rules[i];
      mir->rules[i].relative = maelys_strdup(b->rules[i].relative);
      if (!mir->rules[i].relative) {
        maelys_mir_destroy(mir);
        return MAELYS_MIR_ERR_MEMORY;
      }
      mir->rule_count++;
    }
    qsort(mir->rules, mir->rule_count, sizeof(*mir->rules), rule_key_compare);
  }
  mir->network = b->network;
  mir->root_mode = b->root_mode;
  if (b->network_destination_count) {
    mir->network_destinations =
        calloc(b->network_destination_count, sizeof(*mir->network_destinations));
    if (!mir->network_destinations) {
      maelys_mir_destroy(mir);
      return MAELYS_MIR_ERR_MEMORY;
    }
    for (size_t i = 0; i < b->network_destination_count; ++i) {
      mir->network_destinations[i] = b->network_destinations[i];
      mir->network_destinations[i].host =
          maelys_strdup(b->network_destinations[i].host);
      if (!mir->network_destinations[i].host) {
        maelys_mir_destroy(mir);
        return MAELYS_MIR_ERR_MEMORY;
      }
      ++mir->network_destination_count;
    }
    qsort(mir->network_destinations, mir->network_destination_count,
          sizeof(*mir->network_destinations), network_destination_compare);
  }
  mir->process_tree_required = b->process_tree_required;
  *out = mir;
  return MAELYS_MIR_OK;
}

void maelys_mir_destroy(maelys_mir_t *mir) {
  if (mir) {
    free_rules(mir->rules, mir->rule_count);
    free_network_destinations(mir->network_destinations,
                              mir->network_destination_count);
    free(mir);
  }
}
size_t maelys_mir_fs_rule_count(const maelys_mir_t *mir) {
  return mir ? mir->rule_count : 0;
}
maelys_mir_network_mode_t maelys_mir_network(const maelys_mir_t *mir) {
  return mir ? mir->network : 0;
}
maelys_mir_root_mode_t maelys_mir_root_mode(const maelys_mir_t *mir) {
  return mir ? mir->root_mode : 0;
}
size_t maelys_mir_network_destination_count(const maelys_mir_t *mir) {
  return mir ? mir->network_destination_count : 0u;
}
maelys_mir_result_t maelys_mir_network_destination_at(
    const maelys_mir_t *mir, size_t index,
    maelys_mir_network_destination_view_t *out) {
  if (!mir || !out || index >= mir->network_destination_count)
    return MAELYS_MIR_ERR_ARGUMENT;
  const maelys_mir_network_destination_t *destination =
      &mir->network_destinations[index];
  *out = (maelys_mir_network_destination_view_t){
      destination->protocol, destination->host, destination->port};
  return MAELYS_MIR_OK;
}
int maelys_mir_process_tree_required(const maelys_mir_t *mir) {
  return mir ? mir->process_tree_required : 0;
}
maelys_mir_result_t maelys_mir_fs_rule_at(const maelys_mir_t *mir, size_t i,
                                          maelys_mir_fs_rule_view_t *out) {
  if (!mir || !out || i >= mir->rule_count)
    return MAELYS_MIR_ERR_ARGUMENT;
  const maelys_mir_fs_rule_t *r = &mir->rules[i];
  *out = (maelys_mir_fs_rule_view_t){r->access, r->root, r->scope, r->missing,
                                     r->relative};
  return MAELYS_MIR_OK;
}

static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}
static uint16_t get16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t get32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

maelys_mir_result_t maelys_mir_encode(const maelys_mir_t *mir, uint8_t **out,
                                      size_t *out_size, char **err) {
  if (out)
    *out = NULL;
  if (out_size)
    *out_size = 0;
  if (!mir || !out || !out_size || mir->rule_count > UINT32_MAX ||
      mir->network_destination_count > UINT32_MAX) {
    maelys_set_error(err, "MIR and outputs are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  size_t size = HEADER_SIZE;
  for (size_t i = 0; i < mir->rule_count; ++i) {
    size_t n = strlen(mir->rules[i].relative);
    if (n > UINT32_MAX || size > MAELYS_MIR_MAX_BYTES - RECORD_FIXED_SIZE - n) {
      maelys_set_error(err, "encoded MIR exceeds limit");
      return MAELYS_MIR_ERR_LIMIT;
    }
    size += RECORD_FIXED_SIZE + n;
  }
  for (size_t i = 0; i < mir->network_destination_count; ++i) {
    size_t n = strlen(mir->network_destinations[i].host);
    if (n > UINT32_MAX ||
        size > MAELYS_MIR_MAX_BYTES - NETWORK_RECORD_FIXED_SIZE - n) {
      maelys_set_error(err, "encoded MIR exceeds limit");
      return MAELYS_MIR_ERR_LIMIT;
    }
    size += NETWORK_RECORD_FIXED_SIZE + n;
  }
  uint8_t *bytes = calloc(1, size);
  if (!bytes)
    return MAELYS_MIR_ERR_MEMORY;
  memcpy(bytes, "MMIR", 4);
  put16(bytes + 4, MAELYS_MIR_FORMAT_VERSION);
  put16(bytes + 6, 0);
  put32(bytes + 8, (uint32_t)mir->rule_count);
  bytes[12] = (uint8_t)mir->network;
  bytes[13] = (uint8_t)mir->process_tree_required;
  bytes[14] = (uint8_t)mir->root_mode;
  put32(bytes + 16, (uint32_t)mir->network_destination_count);
  size_t at = HEADER_SIZE;
  for (size_t i = 0; i < mir->rule_count; ++i) {
    const maelys_mir_fs_rule_t *r = &mir->rules[i];
    size_t n = strlen(r->relative);
    bytes[at] = 1;
    bytes[at + 1] = (uint8_t)r->access;
    bytes[at + 2] = (uint8_t)r->root;
    bytes[at + 3] = (uint8_t)r->scope;
    bytes[at + 4] = (uint8_t)r->missing;
    put32(bytes + at + 8, (uint32_t)n);
    memcpy(bytes + at + 12, r->relative, n);
    at += 12 + n;
  }
  for (size_t i = 0; i < mir->network_destination_count; ++i) {
    const maelys_mir_network_destination_t *destination =
        &mir->network_destinations[i];
    size_t n = strlen(destination->host);
    bytes[at] = 2;
    bytes[at + 1] = (uint8_t)destination->protocol;
    put16(bytes + at + 2, destination->port);
    put32(bytes + at + 4, (uint32_t)n);
    memcpy(bytes + at + NETWORK_RECORD_FIXED_SIZE, destination->host, n);
    at += NETWORK_RECORD_FIXED_SIZE + n;
  }
  *out = bytes;
  *out_size = size;
  return MAELYS_MIR_OK;
}

static maelys_mir_result_t decode_relaxed(const uint8_t *bytes, size_t size,
                                          maelys_mir_t **out, char **err) {
  if (out)
    *out = NULL;
  if (!bytes || !out || size < HEADER_SIZE || size > MAELYS_MIR_MAX_BYTES) {
    maelys_set_error(err, "invalid MIR size");
    return MAELYS_MIR_ERR_FORMAT;
  }
  if (memcmp(bytes, "MMIR", 4) ||
      get16(bytes + 4) != MAELYS_MIR_FORMAT_VERSION || get16(bytes + 6) != 0 ||
      bytes[15]) {
    maelys_set_error(err, "invalid MIR header");
    return MAELYS_MIR_ERR_FORMAT;
  }
  uint32_t count = get32(bytes + 8);
  uint32_t network_count = get32(bytes + 16);
  maelys_mir_network_mode_t network =
      (maelys_mir_network_mode_t)bytes[12];
  maelys_mir_root_mode_t root_mode = (maelys_mir_root_mode_t)bytes[14];
  if (count > MAELYS_MIR_MAX_RULES ||
      network_count > MAELYS_MIR_MAX_NETWORK_DESTINATIONS ||
      !valid_network(network) || !valid_root_mode(root_mode) || bytes[13] > 1 ||
      ((network == MAELYS_MIR_NETWORK_MEDIATED) != (network_count > 0u))) {
    maelys_set_error(err, "invalid MIR header values");
    return MAELYS_MIR_ERR_FORMAT;
  }
  maelys_mir_builder_t *b = NULL;
  maelys_mir_result_t result = maelys_mir_builder_create(&b, err);
  if (result)
    return result;
  b->network = network;
  b->root_mode = root_mode;
  b->process_tree_required = bytes[13];
  size_t at = HEADER_SIZE;
  for (uint32_t i = 0; i < count; ++i) {
    if (size - at < RECORD_FIXED_SIZE || bytes[at] != 1 || bytes[at + 5] ||
        bytes[at + 6] || bytes[at + 7]) {
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid MIR record %u", i);
      break;
    }
    if (!valid_access((maelys_mir_fs_access_t)bytes[at + 1]) ||
        !valid_root((maelys_mir_path_root_t)bytes[at + 2]) ||
        !valid_scope((maelys_mir_path_scope_t)bytes[at + 3]) ||
        !valid_missing((maelys_mir_missing_path_t)bytes[at + 4])) {
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid MIR record values at record %u", i);
      break;
    }
    uint32_t n = get32(bytes + at + 8);
    if (n > MAELYS_MIR_MAX_STRING_BYTES || size - at - RECORD_FIXED_SIZE < n) {
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "truncated MIR record %u", i);
      break;
    }
    char *s = malloc((size_t)n + 1u);
    if (!s) {
      result = MAELYS_MIR_ERR_MEMORY;
      break;
    }
    memcpy(s, bytes + at + 12, n);
    s[n] = '\0';
    if (!maelys_valid_utf8_no_nul((const uint8_t *)s, n)) {
      free(s);
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid UTF-8 in record %u", i);
      break;
    }
    result = maelys_mir_builder_add_fs_rule(
        b, (maelys_mir_fs_access_t)bytes[at + 1],
        (maelys_mir_path_root_t)bytes[at + 2], s,
        (maelys_mir_path_scope_t)bytes[at + 3],
        (maelys_mir_missing_path_t)bytes[at + 4], err);
    free(s);
    if (result)
      break;
    at += 12u + n;
  }
  for (uint32_t i = 0; result == MAELYS_MIR_OK && i < network_count; ++i) {
    if (size - at < NETWORK_RECORD_FIXED_SIZE || bytes[at] != 2) {
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid MIR network record %u", i);
      break;
    }
    maelys_mir_network_protocol_t protocol =
        (maelys_mir_network_protocol_t)bytes[at + 1];
    uint16_t port = get16(bytes + at + 2);
    uint32_t n = get32(bytes + at + 4);
    if (!valid_network_protocol(protocol) || port == 0 ||
        n == 0 || n > MAELYS_MIR_MAX_NETWORK_HOST_BYTES ||
        size - at - NETWORK_RECORD_FIXED_SIZE < n) {
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid MIR network record values at record %u", i);
      break;
    }
    char *host = malloc((size_t)n + 1u);
    if (!host) {
      result = MAELYS_MIR_ERR_MEMORY;
      break;
    }
    memcpy(host, bytes + at + NETWORK_RECORD_FIXED_SIZE, n);
    host[n] = '\0';
    if (!maelys_valid_utf8_no_nul((const uint8_t *)host, n) ||
        !valid_dns_host(host)) {
      free(host);
      result = MAELYS_MIR_ERR_FORMAT;
      maelys_set_error(err, "invalid host in MIR network record %u", i);
      break;
    }
    result = maelys_mir_builder_add_network_destination(
        b, protocol, host, port, err);
    free(host);
    if (result)
      break;
    at += NETWORK_RECORD_FIXED_SIZE + n;
  }
  if (result == MAELYS_MIR_OK && at != size) {
    result = MAELYS_MIR_ERR_FORMAT;
    maelys_set_error(err, "trailing bytes after MIR records");
  }
  if (result == MAELYS_MIR_OK)
    result = maelys_mir_builder_build(b, out, err);
  maelys_mir_builder_destroy(b);
  return result;
}

maelys_mir_result_t maelys_mir_check_canonical(const uint8_t *bytes,
                                               size_t size, char **err) {
  maelys_mir_t *mir = NULL;
  maelys_mir_result_t r = decode_relaxed(bytes, size, &mir, err);
  if (r)
    return r;
  uint8_t *canonical = NULL;
  size_t n = 0;
  r = maelys_mir_encode(mir, &canonical, &n, err);
  maelys_mir_destroy(mir);
  if (r)
    return r;
  if (n != size || memcmp(bytes, canonical, size)) {
    free(canonical);
    maelys_set_error(err, "MIR encoding is not canonical");
    return MAELYS_MIR_ERR_NON_CANONICAL;
  }
  free(canonical);
  return MAELYS_MIR_OK;
}
maelys_mir_result_t maelys_mir_decode(const uint8_t *bytes, size_t size,
                                      maelys_mir_t **out, char **err) {
  if (out)
    *out = NULL;
  maelys_mir_result_t r = maelys_mir_check_canonical(bytes, size, err);
  if (r)
    return r;
  return decode_relaxed(bytes, size, out, err);
}
maelys_mir_result_t maelys_mir_digest_hex(const maelys_mir_t *mir,
                                          char out[MAELYS_MIR_DIGEST_HEX_SIZE],
                                          char **err) {
  if (!mir || !out)
    return MAELYS_MIR_ERR_ARGUMENT;
  uint8_t *bytes = NULL, digest[32];
  size_t size = 0;
  maelys_mir_result_t r = maelys_mir_encode(mir, &bytes, &size, err);
  if (r)
    return r;
  maelys_sha256(bytes, size, digest);
  free(bytes);
  maelys_digest_to_hex(digest, out);
  return MAELYS_MIR_OK;
}

static int network_rank(maelys_mir_network_mode_t mode) {
  switch (mode) {
  case MAELYS_MIR_NETWORK_NONE:
    return 0;
  case MAELYS_MIR_NETWORK_MEDIATED:
    return 1;
  case MAELYS_MIR_NETWORK_DIRECT:
    return 2;
  }
  return 3;
}

static int destination_equal(const maelys_mir_network_destination_t *a,
                             const maelys_mir_network_destination_t *b) {
  return a->protocol == b->protocol && a->port == b->port &&
         strcmp(a->host, b->host) == 0;
}

static maelys_mir_result_t copy_network_destinations(
    maelys_mir_builder_t *builder, const maelys_mir_t *source, char **err) {
  for (size_t i = 0; i < source->network_destination_count; ++i) {
    const maelys_mir_network_destination_t *destination =
        &source->network_destinations[i];
    maelys_mir_result_t result = maelys_mir_builder_add_network_destination(
        builder, destination->protocol, destination->host, destination->port,
        err);
    if (result != MAELYS_MIR_OK)
      return result;
  }
  return MAELYS_MIR_OK;
}

maelys_mir_result_t maelys_mir_restrict(const maelys_mir_t *base,
                                        const maelys_mir_t *restriction,
                                        maelys_mir_t **out_effective,
                                        char **err) {
  if (out_effective)
    *out_effective = NULL;
  if (!base || !restriction || !out_effective) {
    maelys_set_error(err, "base, restriction, and output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  for (size_t i = 0; i < restriction->rule_count; ++i) {
    if (restriction->rules[i].access != MAELYS_MIR_FS_DENY) {
      maelys_set_error(err, "restrictive overlay contains a filesystem grant");
      return MAELYS_MIR_ERR_UNSUPPORTED;
    }
  }
  maelys_mir_builder_t *builder = NULL;
  maelys_mir_result_t result = maelys_mir_builder_create(&builder, err);
  if (result != MAELYS_MIR_OK)
    return result;
  for (size_t pass = 0; pass < 2 && result == MAELYS_MIR_OK; ++pass) {
    const maelys_mir_t *source = pass == 0 ? base : restriction;
    for (size_t i = 0; i < source->rule_count; ++i) {
      const maelys_mir_fs_rule_t *rule = &source->rules[i];
      result = maelys_mir_builder_add_fs_rule(builder, rule->access, rule->root,
                                              rule->relative, rule->scope,
                                              rule->missing, err);
      if (result != MAELYS_MIR_OK)
        break;
    }
  }
  if (result == MAELYS_MIR_OK) {
    maelys_mir_network_mode_t network =
        network_rank(base->network) <= network_rank(restriction->network)
            ? base->network
            : restriction->network;
    result = maelys_mir_builder_set_network(builder, network, err);
    if (result == MAELYS_MIR_OK && network == MAELYS_MIR_NETWORK_MEDIATED) {
      if (base->network == MAELYS_MIR_NETWORK_MEDIATED &&
          restriction->network == MAELYS_MIR_NETWORK_MEDIATED) {
        size_t intersection_count = 0;
        for (size_t i = 0; i < base->network_destination_count; ++i) {
          for (size_t j = 0; j < restriction->network_destination_count; ++j) {
            if (destination_equal(&base->network_destinations[i],
                                  &restriction->network_destinations[j])) {
              const maelys_mir_network_destination_t *destination =
                  &base->network_destinations[i];
              result = maelys_mir_builder_add_network_destination(
                  builder, destination->protocol, destination->host,
                  destination->port, err);
              ++intersection_count;
              break;
            }
          }
          if (result != MAELYS_MIR_OK)
            break;
        }
        if (result == MAELYS_MIR_OK && intersection_count == 0u) {
          result = maelys_mir_builder_set_network(
              builder, MAELYS_MIR_NETWORK_NONE, err);
        }
      } else {
        const maelys_mir_t *mediated =
            base->network == MAELYS_MIR_NETWORK_MEDIATED ? base : restriction;
        result = copy_network_destinations(builder, mediated, err);
      }
    }
  }
  if (result == MAELYS_MIR_OK) {
    result = maelys_mir_builder_set_root_mode(
        builder,
        base->root_mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE &&
                restriction->root_mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE
            ? MAELYS_MIR_ROOT_EPHEMERAL_WRITE
            : MAELYS_MIR_ROOT_READ_ONLY,
        err);
  }
  if (result == MAELYS_MIR_OK) {
    result = maelys_mir_builder_set_process_tree_required(
        builder,
        base->process_tree_required || restriction->process_tree_required, err);
  }
  if (result == MAELYS_MIR_OK) {
    result = maelys_mir_builder_build(builder, out_effective, err);
  }
  maelys_mir_builder_destroy(builder);
  return result;
}
