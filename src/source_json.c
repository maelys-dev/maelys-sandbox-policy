#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct json_parser {
  const uint8_t *data;
  size_t size;
  size_t at;
  unsigned depth;
  char **error;
  maelys_mir_result_t result;
} json_parser_t;

static void ws(json_parser_t *p) {
  while (p->at < p->size && (p->data[p->at] == ' ' || p->data[p->at] == '\n' ||
                             p->data[p->at] == '\r' || p->data[p->at] == '\t'))
    ++p->at;
}
static int fail(json_parser_t *p, const char *message) {
  if (p->result != MAELYS_MIR_OK)
    return 0;
  p->result = MAELYS_MIR_ERR_FORMAT;
  maelys_set_error(p->error, "JSON byte %zu: %s", p->at, message);
  return 0;
}
static int fail_result(json_parser_t *p, maelys_mir_result_t result,
                       const char *message) {
  if (p->result != MAELYS_MIR_OK)
    return 0;
  p->result = result;
  maelys_set_error(p->error, "JSON byte %zu: %s", p->at, message);
  return 0;
}
static int take(json_parser_t *p, uint8_t c) {
  ws(p);
  if (p->at >= p->size || p->data[p->at] != c)
    return fail(p, "unexpected token");
  ++p->at;
  return 1;
}

static int hex4(json_parser_t *p, uint32_t *out) {
  if (p->size - p->at < 4)
    return fail(p, "truncated Unicode escape");
  uint32_t v = 0;
  for (unsigned i = 0; i < 4; ++i) {
    uint8_t c = p->data[p->at++];
    v <<= 4;
    if (c >= '0' && c <= '9')
      v |= c - '0';
    else if (c >= 'a' && c <= 'f')
      v |= c - 'a' + 10u;
    else if (c >= 'A' && c <= 'F')
      v |= c - 'A' + 10u;
    else
      return fail(p, "invalid Unicode escape");
  }
  *out = v;
  return 1;
}
static int append_utf8(char *out, size_t *n, uint32_t cp) {
  if (cp <= 0x7f) {
    out[(*n)++] = (char)cp;
  } else if (cp <= 0x7ff) {
    out[(*n)++] = (char)(0xc0u | (cp >> 6));
    out[(*n)++] = (char)(0x80u | (cp & 63u));
  } else if (cp <= 0xffff) {
    out[(*n)++] = (char)(0xe0u | (cp >> 12));
    out[(*n)++] = (char)(0x80u | ((cp >> 6) & 63u));
    out[(*n)++] = (char)(0x80u | (cp & 63u));
  } else {
    out[(*n)++] = (char)(0xf0u | (cp >> 18));
    out[(*n)++] = (char)(0x80u | ((cp >> 12) & 63u));
    out[(*n)++] = (char)(0x80u | ((cp >> 6) & 63u));
    out[(*n)++] = (char)(0x80u | (cp & 63u));
  }
  return 1;
}

static char *string(json_parser_t *p) {
  ws(p);
  if (p->at >= p->size || p->data[p->at++] != '"') {
    fail(p, "expected string");
    return NULL;
  }
  size_t capacity = p->size - p->at + 1u;
  char *out = malloc(capacity);
  if (!out) {
    fail_result(p, MAELYS_MIR_ERR_MEMORY, "out of memory");
    return NULL;
  }
  size_t n = 0;
  while (p->at < p->size) {
    uint8_t c = p->data[p->at++];
    if (c == '"') {
      out[n] = '\0';
      if (!maelys_valid_utf8_no_nul((const uint8_t *)out, n)) {
        free(out);
        fail(p, "string is not valid UTF-8");
        return NULL;
      }
      return out;
    }
    if (c < 0x20) {
      free(out);
      fail(p, "control character in string");
      return NULL;
    }
    if (c != '\\') {
      out[n++] = (char)c;
      continue;
    }
    if (p->at >= p->size) {
      free(out);
      fail(p, "truncated escape");
      return NULL;
    }
    c = p->data[p->at++];
    switch (c) {
    case '"':
    case '\\':
    case '/':
      out[n++] = (char)c;
      break;
    case 'b':
      out[n++] = '\b';
      break;
    case 'f':
      out[n++] = '\f';
      break;
    case 'n':
      out[n++] = '\n';
      break;
    case 'r':
      out[n++] = '\r';
      break;
    case 't':
      out[n++] = '\t';
      break;
    case 'u': {
      uint32_t cp = 0;
      if (!hex4(p, &cp)) {
        free(out);
        return NULL;
      }
      if (cp >= 0xd800u && cp <= 0xdbffu) {
        if (p->size - p->at < 6 || p->data[p->at] != '\\' ||
            p->data[p->at + 1] != 'u') {
          free(out);
          fail(p, "missing low surrogate");
          return NULL;
        }
        p->at += 2;
        uint32_t low = 0;
        if (!hex4(p, &low) || low < 0xdc00u || low > 0xdfffu) {
          free(out);
          fail(p, "invalid low surrogate");
          return NULL;
        }
        cp = 0x10000u + ((cp - 0xd800u) << 10) + (low - 0xdc00u);
      } else if (cp >= 0xdc00u && cp <= 0xdfffu) {
        free(out);
        fail(p, "unpaired low surrogate");
        return NULL;
      }
      if (cp == 0) {
        free(out);
        fail(p, "NUL is forbidden in strings");
        return NULL;
      }
      append_utf8(out, &n, cp);
      break;
    }
    default:
      free(out);
      fail(p, "invalid string escape");
      return NULL;
    }
  }
  free(out);
  fail(p, "unterminated string");
  return NULL;
}

static int integer_three(json_parser_t *p) {
  ws(p);
  if (p->at >= p->size || p->data[p->at++] != '3')
    return fail(p, "formatVersion must be 3");
  if (p->at < p->size && (isdigit(p->data[p->at]) || p->data[p->at] == '.' ||
                          p->data[p->at] == 'e' || p->data[p->at] == 'E'))
    return fail(p, "formatVersion must be integer 3");
  return 1;
}

static int integer_port(json_parser_t *p, uint16_t *out) {
  ws(p);
  if (p->at >= p->size || p->data[p->at] < '1' || p->data[p->at] > '9')
    return fail(p, "port must be an integer in 1..65535");
  unsigned long value = 0;
  while (p->at < p->size && isdigit(p->data[p->at])) {
    unsigned long digit = (unsigned long)(p->data[p->at] - '0');
    if (value > (UINT16_MAX - digit) / 10u)
      return fail(p, "port must be an integer in 1..65535");
    value = value * 10u + digit;
    ++p->at;
  }
  if (p->at < p->size &&
      (p->data[p->at] == '.' || p->data[p->at] == 'e' ||
       p->data[p->at] == 'E'))
    return fail(p, "port must be an integer in 1..65535");
  *out = (uint16_t)value;
  return 1;
}
static int key_sep(json_parser_t *p, char **out) {
  *out = string(p);
  if (!*out)
    return 0;
  if (!take(p, ':')) {
    free(*out);
    *out = NULL;
    return 0;
  }
  return 1;
}
static int next_member(json_parser_t *p, int *first) {
  ws(p);
  if (p->at < p->size && p->data[p->at] == '}') {
    ++p->at;
    return 0;
  }
  if (!*first && !take(p, ','))
    return -1;
  *first = 0;
  return 1;
}
static int next_item(json_parser_t *p, int *first) {
  ws(p);
  if (p->at < p->size && p->data[p->at] == ']') {
    ++p->at;
    return 0;
  }
  if (!*first && !take(p, ','))
    return -1;
  *first = 0;
  return 1;
}
static int seen_key(json_parser_t *p, unsigned *seen, unsigned bit,
                    const char *key) {
  if (*seen & bit) {
    maelys_set_error(p->error, "JSON byte %zu: duplicate key '%s'", p->at, key);
    return 0;
  }
  *seen |= bit;
  return 1;
}
static int equals(const char *a, const char *b) { return strcmp(a, b) == 0; }

static int parse_path(json_parser_t *p, maelys_mir_path_root_t *out_root,
                      char **out_relative) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  char *special = NULL, *root = NULL, *relative = NULL, *absolute = NULL;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (equals(k, "special")) {
      if (!seen_key(p, &seen, 1u, k)) {
        free(k);
        goto bad;
      }
      special = string(p);
      free(k);
      if (!special)
        goto bad;
    } else if (equals(k, "root")) {
      if (!seen_key(p, &seen, 2u, k)) {
        free(k);
        goto bad;
      }
      root = string(p);
      free(k);
      if (!root)
        goto bad;
    } else if (equals(k, "relative")) {
      if (!seen_key(p, &seen, 4u, k)) {
        free(k);
        goto bad;
      }
      relative = string(p);
      free(k);
      if (!relative)
        goto bad;
    } else if (equals(k, "absolute")) {
      if (!seen_key(p, &seen, 8u, k)) {
        free(k);
        goto bad;
      }
      absolute = string(p);
      free(k);
      if (!absolute)
        goto bad;
    } else {
      maelys_set_error(p->error, "unknown path key '%s'", k);
      free(k);
      goto bad;
    }
  }
  if (more < 0)
    goto bad;
  if (special) {
    if (seen != 1u || !equals(special, "minimal-runtime")) {
      fail(p, "special path must be exactly minimal-runtime");
      goto bad;
    }
    *out_root = MAELYS_MIR_ROOT_MINIMAL_RUNTIME;
    *out_relative = maelys_strdup("");
  } else if (absolute) {
    if (seen != 8u) {
      fail(p, "absolute path cannot be combined with root or relative");
      goto bad;
    }
    *out_root = MAELYS_MIR_ROOT_HOST;
    *out_relative = absolute;
    absolute = NULL;
  } else {
    if (!(seen & 2u) || (seen & ~6u)) {
      fail(p, "path requires root and optional relative");
      goto bad;
    }
    if (equals(root, "workspace"))
      *out_root = MAELYS_MIR_ROOT_WORKSPACE;
    else if (equals(root, "temp"))
      *out_root = MAELYS_MIR_ROOT_TEMP;
    else {
      fail(p, "root must be workspace or temp");
      goto bad;
    }
    *out_relative = relative ? relative : maelys_strdup("");
    relative = NULL;
  }
  free(special);
  free(root);
  free(relative);
  free(absolute);
  --p->depth;
  if (!*out_relative)
    p->result = MAELYS_MIR_ERR_MEMORY;
  return *out_relative != NULL;
bad:
  free(special);
  free(root);
  free(relative);
  free(absolute);
  --p->depth;
  return 0;
}

static int parse_rule(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  char *access = NULL, *scope = NULL, *missing = NULL, *relative = NULL;
  maelys_mir_path_root_t root = 0;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (equals(k, "access")) {
      if (!seen_key(p, &seen, 1u, k)) {
        free(k);
        goto bad;
      }
      access = string(p);
      free(k);
      if (!access)
        goto bad;
    } else if (equals(k, "path")) {
      if (!seen_key(p, &seen, 2u, k)) {
        free(k);
        goto bad;
      }
      free(k);
      if (!parse_path(p, &root, &relative))
        goto bad;
    } else if (equals(k, "scope")) {
      if (!seen_key(p, &seen, 4u, k)) {
        free(k);
        goto bad;
      }
      scope = string(p);
      free(k);
      if (!scope)
        goto bad;
    } else if (equals(k, "missing")) {
      if (!seen_key(p, &seen, 8u, k)) {
        free(k);
        goto bad;
      }
      missing = string(p);
      free(k);
      if (!missing)
        goto bad;
    } else {
      maelys_set_error(p->error, "unknown filesystem rule key '%s'", k);
      free(k);
      goto bad;
    }
  }
  if (more < 0)
    goto bad;
  if ((seen & 3u) != 3u) {
    fail(p, "filesystem rule requires access and path");
    goto bad;
  }
  maelys_mir_fs_access_t a = equals(access, "read")    ? MAELYS_MIR_FS_READ
                             : equals(access, "write") ? MAELYS_MIR_FS_WRITE
                             : equals(access, "deny")  ? MAELYS_MIR_FS_DENY
                                                       : 0;
  maelys_mir_path_scope_t s = !scope || equals(scope, "tree")
                                  ? MAELYS_MIR_SCOPE_TREE
                              : equals(scope, "exact") ? MAELYS_MIR_SCOPE_EXACT
                                                       : 0;
  maelys_mir_missing_path_t m =
      !missing || equals(missing, "error") ? MAELYS_MIR_MISSING_ERROR
      : equals(missing, "skip")            ? MAELYS_MIR_MISSING_SKIP
                                           : 0;
  if (!a || !s || !m) {
    fail(p, "invalid access, scope, or missing value");
    goto bad;
  }
  maelys_mir_result_t r =
      maelys_mir_builder_add_fs_rule(b, a, root, relative, s, m, p->error);
  if (r != MAELYS_MIR_OK)
    p->result = r;
  free(access);
  free(scope);
  free(missing);
  free(relative);
  --p->depth;
  return r == MAELYS_MIR_OK;
bad:
  free(access);
  free(scope);
  free(missing);
  free(relative);
  --p->depth;
  return 0;
}

static int parse_filesystem(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (equals(k, "default")) {
      if (!seen_key(p, &seen, 1u, k)) {
        free(k);
        goto bad;
      }
      char *v = string(p);
      free(k);
      if (!v)
        goto bad;
      int ok = equals(v, "deny");
      free(v);
      if (!ok) {
        fail(p, "filesystem default must be deny in v3");
        goto bad;
      }
    } else if (equals(k, "rules")) {
      if (!seen_key(p, &seen, 2u, k)) {
        free(k);
        goto bad;
      }
      free(k);
      if (!take(p, '['))
        goto bad;
      int afirst = 1, item;
      while ((item = next_item(p, &afirst)) > 0)
        if (!parse_rule(p, b))
          goto bad;
      if (item < 0)
        goto bad;
    } else {
      maelys_set_error(p->error, "unknown filesystem key '%s'", k);
      free(k);
      goto bad;
    }
  }
  if (more < 0)
    goto bad;
  if (seen != 3u) {
    fail(p, "filesystem requires default and rules");
    goto bad;
  }
  --p->depth;
  return 1;
bad:
  --p->depth;
  return 0;
}

static int parse_network_destination(json_parser_t *p,
                                     maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  char *protocol = NULL, *host = NULL;
  uint16_t port = 0;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (equals(k, "protocol")) {
      if (!seen_key(p, &seen, 1u, k)) {
        free(k);
        goto bad;
      }
      protocol = string(p);
    } else if (equals(k, "host")) {
      if (!seen_key(p, &seen, 2u, k)) {
        free(k);
        goto bad;
      }
      host = string(p);
    } else if (equals(k, "port")) {
      if (!seen_key(p, &seen, 4u, k)) {
        free(k);
        goto bad;
      }
      if (!integer_port(p, &port)) {
        free(k);
        goto bad;
      }
    } else {
      maelys_set_error(p->error, "unknown network destination key '%s'", k);
      free(k);
      goto bad;
    }
    free(k);
    if (p->result != MAELYS_MIR_OK ||
        ((seen & 1u) && !protocol) || ((seen & 2u) && !host))
      goto bad;
  }
  if (more < 0)
    goto bad;
  if (seen != 7u || !equals(protocol, "tcp")) {
    fail(p, "network destination requires protocol tcp, host, and port");
    goto bad;
  }
  maelys_mir_result_t result = maelys_mir_builder_add_network_destination(
      b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, host, port, p->error);
  free(protocol);
  free(host);
  --p->depth;
  if (result != MAELYS_MIR_OK)
    p->result = result;
  return result == MAELYS_MIR_OK;
bad:
  free(protocol);
  free(host);
  --p->depth;
  return 0;
}

static int parse_network_allow(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '['))
    return 0;
  int first = 1, more;
  size_t count = 0;
  while ((more = next_item(p, &first)) > 0) {
    if (!parse_network_destination(p, b)) {
      --p->depth;
      return 0;
    }
    ++count;
  }
  --p->depth;
  if (more < 0)
    return 0;
  if (count == 0u)
    return fail(p, "mediated network allowlist must not be empty");
  return 1;
}

static int parse_network(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  char *mode = NULL;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (equals(k, "mode")) {
      if (!seen_key(p, &seen, 1u, k)) {
        free(k);
        goto bad;
      }
      mode = string(p);
      free(k);
      if (!mode)
        goto bad;
    } else if (equals(k, "allow")) {
      if (!seen_key(p, &seen, 2u, k)) {
        free(k);
        goto bad;
      }
      free(k);
      if (!parse_network_allow(p, b))
        goto bad;
    } else {
      maelys_set_error(p->error, "unknown network key '%s'", k);
      free(k);
      goto bad;
    }
  }
  if (more < 0)
    goto bad;
  if ((seen & 1u) == 0u) {
    fail(p, "network requires mode");
    goto bad;
  }
  maelys_mir_network_mode_t network =
      equals(mode, "none")       ? MAELYS_MIR_NETWORK_NONE
      : equals(mode, "direct")   ? MAELYS_MIR_NETWORK_DIRECT
      : equals(mode, "mediated") ? MAELYS_MIR_NETWORK_MEDIATED
                                  : 0;
  if (!network ||
      ((network == MAELYS_MIR_NETWORK_MEDIATED) != ((seen & 2u) != 0u)) ||
      maelys_mir_builder_set_network(b, network, p->error) != MAELYS_MIR_OK) {
    fail(p, "allow is required exactly for mediated network mode");
    goto bad;
  }
  free(mode);
  --p->depth;
  return 1;
bad:
  free(mode);
  --p->depth;
  return 0;
}
static int parse_process(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (!equals(k, "treeConfinement")) {
      maelys_set_error(p->error, "unknown process key '%s'", k);
      free(k);
      goto bad;
    }
    if (!seen_key(p, &seen, 1u, k)) {
      free(k);
      goto bad;
    }
    free(k);
    char *v = string(p);
    if (!v)
      goto bad;
    int required = equals(v, "required"), disabled = equals(v, "disabled");
    free(v);
    if ((!required && !disabled) ||
        maelys_mir_builder_set_process_tree_required(b, required, p->error) !=
            MAELYS_MIR_OK)
      goto bad;
  }
  if (more < 0)
    goto bad;
  if (seen != 1u) {
    fail(p, "process requires treeConfinement");
    goto bad;
  }
  --p->depth;
  return 1;
bad:
  --p->depth;
  return 0;
}

static int parse_root(json_parser_t *p, maelys_mir_builder_t *b) {
  if (++p->depth > 32u)
    return fail(p, "nesting depth exceeds 32");
  if (!take(p, '{'))
    return 0;
  unsigned seen = 0;
  int first = 1, more;
  while ((more = next_member(p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(p, &k))
      goto bad;
    if (!equals(k, "mode") || !seen_key(p, &seen, 1u, k)) {
      if (k && !equals(k, "mode"))
        maelys_set_error(p->error, "unknown root key '%s'", k);
      free(k);
      goto bad;
    }
    free(k);
    char *v = string(p);
    if (!v)
      goto bad;
    maelys_mir_root_mode_t mode =
        equals(v, "read-only") ? MAELYS_MIR_ROOT_READ_ONLY
        : equals(v, "ephemeral-write") ? MAELYS_MIR_ROOT_EPHEMERAL_WRITE
                                         : 0;
    free(v);
    if (!mode || maelys_mir_builder_set_root_mode(b, mode, p->error) !=
                     MAELYS_MIR_OK)
      goto bad;
  }
  if (more < 0 || seen != 1u) {
    fail(p, "root requires mode");
    goto bad;
  }
  --p->depth;
  return 1;
bad:
  --p->depth;
  return 0;
}

maelys_mir_result_t maelys_mir_compile_json(const uint8_t *json, size_t size,
                                            maelys_mir_t **out, char **err) {
  if (out)
    *out = NULL;
  if (!json || !out || size == 0) {
    maelys_set_error(err, "JSON input and MIR output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  if (size > MAELYS_MIR_MAX_BYTES) {
    maelys_set_error(err, "JSON source exceeds %u bytes", MAELYS_MIR_MAX_BYTES);
    return MAELYS_MIR_ERR_LIMIT;
  }
  json_parser_t p = {json, size, 0, 0, err, MAELYS_MIR_OK};
  maelys_mir_builder_t *b = NULL;
  maelys_mir_result_t result = maelys_mir_builder_create(&b, err);
  if (result)
    return result;
  if (!take(&p, '{'))
    goto format;
  unsigned seen = 0;
  int first = 1, more;
  while ((more = next_member(&p, &first)) > 0) {
    char *k = NULL;
    if (!key_sep(&p, &k))
      goto format;
    if (equals(k, "$schema")) {
      if (!seen_key(&p, &seen, 1u, k)) {
        free(k);
        goto format;
      }
      char *v = string(&p);
      free(k);
      if (!v)
        goto format;
      int ok =
          equals(v, "https://schemas.maelys.dev/mir-source/v3/schema.json");
      free(v);
      if (!ok) {
        fail(&p, "unsupported $schema URI");
        goto format;
      }
    } else if (equals(k, "formatVersion")) {
      if (!seen_key(&p, &seen, 2u, k)) {
        free(k);
        goto format;
      }
      free(k);
      if (!integer_three(&p))
        goto format;
    } else if (equals(k, "filesystem")) {
      if (!seen_key(&p, &seen, 4u, k)) {
        free(k);
        goto format;
      }
      free(k);
      if (!parse_filesystem(&p, b))
        goto format;
    } else if (equals(k, "network")) {
      if (!seen_key(&p, &seen, 8u, k)) {
        free(k);
        goto format;
      }
      free(k);
      if (!parse_network(&p, b))
        goto format;
    } else if (equals(k, "process")) {
      if (!seen_key(&p, &seen, 16u, k)) {
        free(k);
        goto format;
      }
      free(k);
      if (!parse_process(&p, b))
        goto format;
    } else if (equals(k, "root")) {
      if (!seen_key(&p, &seen, 32u, k)) {
        free(k);
        goto format;
      }
      free(k);
      if (!parse_root(&p, b))
        goto format;
    } else {
      maelys_set_error(err, "unknown top-level key '%s'", k);
      free(k);
      goto format;
    }
  }
  if (more < 0)
    goto format;
  ws(&p);
  if (p.at != size) {
    fail(&p, "trailing input");
    goto format;
  }
  if ((seen & 62u) != 62u) {
    fail(&p,
         "formatVersion, filesystem, network, process, and root are required");
    goto format;
  }
  result = maelys_mir_builder_build(b, out, err);
  maelys_mir_builder_destroy(b);
  return result;
format:
  maelys_mir_builder_destroy(b);
  return p.result == MAELYS_MIR_OK ? MAELYS_MIR_ERR_FORMAT : p.result;
}
