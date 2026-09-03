#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static maelys_mir_result_t canonical_directory(const char *path, char **out,
                                               char **err) {
  if (out)
    *out = NULL;
  if (!path || !out) {
    maelys_set_error(err, "host path and output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  char *resolved = realpath(path, NULL);
  if (!resolved) {
    maelys_set_error(err, "cannot canonicalize host path '%s': %s", path,
                     strerror(errno));
    return MAELYS_MIR_ERR_IO;
  }
  struct stat st;
  if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode)) {
    maelys_set_error(err, "host path is not a directory: %s", resolved);
    free(resolved);
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  *out = resolved;
  return MAELYS_MIR_OK;
}

maelys_mir_result_t maelys_sandbox_policy_host_create(maelys_sandbox_policy_host_t **out,
                                               char **err) {
  if (out)
    *out = NULL;
  if (!out) {
    maelys_set_error(err, "host output is required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_sandbox_policy_host_t *h = calloc(1, sizeof(*h));
  if (!h)
    return MAELYS_MIR_ERR_MEMORY;
  *out = h;
  return MAELYS_MIR_OK;
}
void maelys_sandbox_policy_host_destroy(maelys_sandbox_policy_host_t *h) {
  if (!h)
    return;
  free(h->workspace);
  free(h->temp);
  free(h->network_mediator);
  for (size_t i = 0; i < h->minimal_root_count; ++i)
    free(h->minimal_roots[i]);
  free(h->minimal_roots);
  free(h);
}
static maelys_mir_result_t set_directory(char **slot, const char *path,
                                         char **err) {
  char *resolved = NULL;
  maelys_mir_result_t r = canonical_directory(path, &resolved, err);
  if (r)
    return r;
  free(*slot);
  *slot = resolved;
  return MAELYS_MIR_OK;
}
maelys_mir_result_t maelys_sandbox_policy_host_set_workspace(maelys_sandbox_policy_host_t *h,
                                                      const char *p, char **e) {
  if (!h)
    return MAELYS_MIR_ERR_ARGUMENT;
  return set_directory(&h->workspace, p, e);
}
maelys_mir_result_t maelys_sandbox_policy_host_set_temp(maelys_sandbox_policy_host_t *h,
                                                 const char *p, char **e) {
  if (!h)
    return MAELYS_MIR_ERR_ARGUMENT;
  return set_directory(&h->temp, p, e);
}
maelys_mir_result_t
maelys_sandbox_policy_host_add_minimal_runtime_root(maelys_sandbox_policy_host_t *h,
                                             const char *p, char **err) {
  if (!h)
    return MAELYS_MIR_ERR_ARGUMENT;
  char *resolved = NULL;
  maelys_mir_result_t r = canonical_directory(p, &resolved, err);
  if (r)
    return r;
  for (size_t i = 0; i < h->minimal_root_count; ++i)
    if (strcmp(h->minimal_roots[i], resolved) == 0) {
      free(resolved);
      return MAELYS_MIR_OK;
    }
  if (h->minimal_root_count == 64u) {
    free(resolved);
    maelys_set_error(err, "host exceeds 64 minimal runtime roots");
    return MAELYS_MIR_ERR_LIMIT;
  }
  if (h->minimal_root_count == h->minimal_root_capacity) {
    size_t next = h->minimal_root_capacity ? h->minimal_root_capacity * 2u : 8u;
    char **grown = realloc(h->minimal_roots, next * sizeof(*grown));
    if (!grown) {
      free(resolved);
      return MAELYS_MIR_ERR_MEMORY;
    }
    h->minimal_roots = grown;
    h->minimal_root_capacity = next;
  }
  h->minimal_roots[h->minimal_root_count++] = resolved;
  return MAELYS_MIR_OK;
}

maelys_mir_result_t
maelys_sandbox_policy_host_set_network_mediator(maelys_sandbox_policy_host_t *h,
                                         const char *mediator_id, char **err) {
  if (!h || !mediator_id || !mediator_id[0]) {
    maelys_set_error(err, "host and non-empty network mediator are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  size_t size = strlen(mediator_id);
  if (size > 255u ||
      !maelys_valid_utf8_no_nul((const uint8_t *)mediator_id, size)) {
    maelys_set_error(err,
                     "network mediator must be valid UTF-8 (1..255 bytes)");
    return size > 255u ? MAELYS_MIR_ERR_LIMIT : MAELYS_MIR_ERR_FORMAT;
  }
  for (size_t i = 0; i < size; ++i) {
    unsigned char c = (unsigned char)mediator_id[i];
    if (iscntrl(c) || isspace(c)) {
      maelys_set_error(
          err, "network mediator must not contain whitespace or controls");
      return MAELYS_MIR_ERR_FORMAT;
    }
  }
  char *copy = maelys_strdup(mediator_id);
  if (!copy)
    return MAELYS_MIR_ERR_MEMORY;
  free(h->network_mediator);
  h->network_mediator = copy;
  return MAELYS_MIR_OK;
}

maelys_sandbox_policy_capabilities_t
maelys_sandbox_policy_required_capabilities(const maelys_mir_t *mir) {
  if (!mir)
    return 0;
  maelys_sandbox_policy_capabilities_t c = 0;
  for (size_t i = 0; i < mir->rule_count; ++i) {
    switch (mir->rules[i].access) {
    case MAELYS_MIR_FS_READ:
      c |= MAELYS_SANDBOX_POLICY_CAP_FS_READ;
      break;
    case MAELYS_MIR_FS_WRITE:
      c |= MAELYS_SANDBOX_POLICY_CAP_FS_WRITE;
      break;
    case MAELYS_MIR_FS_DENY:
      c |= MAELYS_SANDBOX_POLICY_CAP_FS_DENY;
      break;
    }
  }
  switch (mir->network) {
  case MAELYS_MIR_NETWORK_NONE:
    c |= MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE;
    break;
  case MAELYS_MIR_NETWORK_DIRECT:
    c |= MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT;
    break;
  case MAELYS_MIR_NETWORK_MEDIATED:
    c |= MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED;
    break;
  }
  if (mir->process_tree_required)
    c |= MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE;
  if (mir->root_mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE)
    c |= MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE;
  return c;
}

static const char *cap_name(maelys_sandbox_policy_capabilities_t cap) {
  switch (cap) {
  case MAELYS_SANDBOX_POLICY_CAP_FS_READ:
    return "filesystem read";
  case MAELYS_SANDBOX_POLICY_CAP_FS_WRITE:
    return "filesystem write";
  case MAELYS_SANDBOX_POLICY_CAP_FS_DENY:
    return "filesystem deny";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE:
    return "network none";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT:
    return "direct network";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED:
    return "mediated network";
  case MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE:
    return "process-tree confinement";
  case MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE:
    return "ephemeral writable root";
  }
  return "unknown";
}
maelys_mir_result_t
maelys_sandbox_policy_check_support(const maelys_mir_t *mir,
                             maelys_sandbox_policy_capabilities_t available,
                             char **err) {
  if (!mir) {
    maelys_set_error(err, "MIR is required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_sandbox_policy_capabilities_t missing =
      maelys_sandbox_policy_required_capabilities(mir) & ~available;
  if (!missing)
    return MAELYS_MIR_OK;
  for (unsigned bit = 0; bit < 64; ++bit) {
    maelys_sandbox_policy_capabilities_t cap = UINT64_C(1) << bit;
    if (missing & cap) {
      maelys_set_error(err, "sandbox backend lacks required capability: %s",
                       cap_name(cap));
      break;
    }
  }
  return MAELYS_MIR_ERR_UNSUPPORTED;
}

static int under_root(const char *root, const char *path) {
  if (!root || !path)
    return 0;
  size_t n = strlen(root);
  if (n == 1u && root[0] == '/')
    return path[0] == '/';
  return strcmp(root, path) == 0 ||
         (strncmp(root, path, n) == 0 && path[n] == '/');
}
static maelys_mir_result_t resolve_candidate(const char *root,
                                             const char *relative,
                                             int enforce_root, char **out,
                                             char **err) {
  if (out)
    *out = NULL;
  size_t rn = root ? strlen(root) : 0, ln = strlen(relative);
  size_t size = rn + (rn && ln ? 1u : 0u) + ln + 1u;
  char *candidate = malloc(size);
  if (!candidate)
    return MAELYS_MIR_ERR_MEMORY;
  if (root && ln)
    snprintf(candidate, size, "%s/%s", root, relative);
  else if (root)
    snprintf(candidate, size, "%s", root);
  else
    snprintf(candidate, size, "%s", relative);
  char *resolved = realpath(candidate, NULL);
  if (!resolved) {
    int saved = errno;
    free(candidate);
    if (saved == ENOENT || saved == ENOTDIR)
      return MAELYS_MIR_ERR_MISSING;
    maelys_set_error(err, "cannot canonicalize sandbox path: %s",
                     strerror(saved));
    return MAELYS_MIR_ERR_IO;
  }
  free(candidate);
  if (enforce_root && !under_root(root, resolved)) {
    maelys_set_error(err,
                     "sandbox path escapes symbolic root through a symlink: %s",
                     resolved);
    free(resolved);
    return MAELYS_MIR_ERR_FORMAT;
  }
  *out = resolved;
  return MAELYS_MIR_OK;
}

static maelys_mir_result_t append_rule(maelys_sandbox_policy_plan_t *p,
                                       maelys_mir_fs_access_t access,
                                       maelys_mir_path_scope_t scope,
                                       char *path) {
  if (p->rule_count == p->rule_capacity) {
    size_t next = p->rule_capacity ? p->rule_capacity * 2u : 16u;
    maelys_sandbox_policy_resolved_rule_t *grown =
        realloc(p->rules, next * sizeof(*grown));
    if (!grown) {
      free(path);
      return MAELYS_MIR_ERR_MEMORY;
    }
    p->rules = grown;
    p->rule_capacity = next;
  }
  p->rules[p->rule_count++] =
      (maelys_sandbox_policy_resolved_rule_t){access, scope, path};
  return MAELYS_MIR_OK;
}
static int plan_rule_compare(const void *left, const void *right) {
  const maelys_sandbox_policy_resolved_rule_t *a = left, *b = right;
  size_t an = strlen(a->path), bn = strlen(b->path);
  if (an != bn)
    return an < bn ? -1 : 1;
  int path = strcmp(a->path, b->path);
  if (path)
    return path; /* tree is broader and must precede exact for last-match
                    backends. */
  if (a->scope != b->scope)
    return a->scope == MAELYS_MIR_SCOPE_TREE ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  return 0;
}

static maelys_mir_result_t compile_one(const maelys_mir_fs_rule_t *r,
                                       const char *root, int enforce_root,
                                       maelys_sandbox_policy_plan_t *p, char **err) {
  char *resolved = NULL;
  maelys_mir_result_t result =
      resolve_candidate(root, r->relative, enforce_root, &resolved, err);
  if (result == MAELYS_MIR_ERR_MISSING &&
      r->missing == MAELYS_MIR_MISSING_SKIP) {
    return MAELYS_MIR_OK;
  }
  if (result == MAELYS_MIR_ERR_MISSING)
    maelys_set_error(err, "required sandbox path does not exist");
  if (result)
    return result;
  return append_rule(p, r->access, r->scope, resolved);
}

maelys_mir_result_t
maelys_sandbox_policy_compile(const maelys_mir_t *mir,
                       const maelys_sandbox_policy_host_t *host,
                       maelys_sandbox_policy_capabilities_t available,
                       maelys_sandbox_policy_plan_t **out, char **err) {
  if (out)
    *out = NULL;
  if (!mir || !host || !out) {
    maelys_set_error(err, "MIR, host context, and plan output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_mir_result_t result =
      maelys_sandbox_policy_check_support(mir, available, err);
  if (result)
    return result;
  if (mir->network == MAELYS_MIR_NETWORK_MEDIATED && !host->network_mediator) {
    maelys_set_error(
        err,
        "mediated network requested but no trusted mediator is configured");
    return MAELYS_MIR_ERR_UNSUPPORTED;
  }
  maelys_sandbox_policy_plan_t *p = calloc(1, sizeof(*p));
  if (!p)
    return MAELYS_MIR_ERR_MEMORY;
  p->network = mir->network;
  p->root_mode = mir->root_mode;
  if (host->network_mediator && mir->network == MAELYS_MIR_NETWORK_MEDIATED) {
    p->network_mediator = maelys_strdup(host->network_mediator);
    if (!p->network_mediator) {
      result = MAELYS_MIR_ERR_MEMORY;
      goto bad;
    }
  }
  if (mir->network_destination_count) {
    p->network_destinations =
        calloc(mir->network_destination_count,
               sizeof(*p->network_destinations));
    if (!p->network_destinations) {
      result = MAELYS_MIR_ERR_MEMORY;
      goto bad;
    }
    for (size_t i = 0; i < mir->network_destination_count; ++i) {
      p->network_destinations[i] = mir->network_destinations[i];
      p->network_destinations[i].host =
          maelys_strdup(mir->network_destinations[i].host);
      if (!p->network_destinations[i].host) {
        result = MAELYS_MIR_ERR_MEMORY;
        goto bad;
      }
      ++p->network_destination_count;
    }
  }
  p->process_tree_required = mir->process_tree_required;
  result = maelys_mir_digest_hex(mir, p->digest, err);
  if (result)
    goto bad;
  for (size_t i = 0; i < mir->rule_count; ++i) {
    const maelys_mir_fs_rule_t *r = &mir->rules[i];
    if (r->root == MAELYS_MIR_ROOT_MINIMAL_RUNTIME) {
      if (!host->minimal_root_count) {
        maelys_set_error(err, "minimal-runtime has no host roots");
        result = MAELYS_MIR_ERR_UNSUPPORTED;
        goto bad;
      }
      for (size_t j = 0; j < host->minimal_root_count; ++j) {
        result = compile_one(r, host->minimal_roots[j], 1, p, err);
        if (result)
          goto bad;
      }
    } else if (r->root == MAELYS_MIR_ROOT_WORKSPACE) {
      if (!host->workspace) {
        maelys_set_error(err, "workspace root is not configured");
        result = MAELYS_MIR_ERR_UNSUPPORTED;
        goto bad;
      }
      result = compile_one(r, host->workspace, 1, p, err);
      if (result)
        goto bad;
    } else if (r->root == MAELYS_MIR_ROOT_TEMP) {
      if (!host->temp) {
        maelys_set_error(err, "temp root is not configured");
        result = MAELYS_MIR_ERR_UNSUPPORTED;
        goto bad;
      }
      result = compile_one(r, host->temp, 1, p, err);
      if (result)
        goto bad;
    } else {
      result = compile_one(r, NULL, 0, p, err);
      if (result)
        goto bad;
    }
  }
  if (p->rule_count > 1u)
    qsort(p->rules, p->rule_count, sizeof(*p->rules), plan_rule_compare);
  *out = p;
  return MAELYS_MIR_OK;
bad:
  maelys_sandbox_policy_plan_destroy(p);
  return result;
}

void maelys_sandbox_policy_plan_destroy(maelys_sandbox_policy_plan_t *p) {
  if (!p)
    return;
  for (size_t i = 0; i < p->rule_count; ++i)
    free(p->rules[i].path);
  free(p->rules);
  free(p->network_mediator);
  for (size_t i = 0; i < p->network_destination_count; ++i)
    free(p->network_destinations[i].host);
  free(p->network_destinations);
  free(p);
}
size_t maelys_sandbox_policy_plan_rule_count(const maelys_sandbox_policy_plan_t *p) {
  return p ? p->rule_count : 0;
}
maelys_mir_result_t
maelys_sandbox_policy_plan_rule_at(const maelys_sandbox_policy_plan_t *p, size_t i,
                            maelys_sandbox_policy_resolved_rule_view_t *out) {
  if (!p || !out || i >= p->rule_count)
    return MAELYS_MIR_ERR_ARGUMENT;
  *out = (maelys_sandbox_policy_resolved_rule_view_t){
      p->rules[i].access, p->rules[i].scope, p->rules[i].path};
  return MAELYS_MIR_OK;
}
maelys_mir_network_mode_t
maelys_sandbox_policy_plan_network(const maelys_sandbox_policy_plan_t *p) {
  return p ? p->network : 0;
}
maelys_mir_root_mode_t maelys_sandbox_policy_plan_root_mode(
    const maelys_sandbox_policy_plan_t *p) {
  return p ? p->root_mode : 0;
}
const char *
maelys_sandbox_policy_plan_network_mediator(const maelys_sandbox_policy_plan_t *p) {
  return p ? p->network_mediator : NULL;
}
size_t maelys_sandbox_policy_plan_network_destination_count(
    const maelys_sandbox_policy_plan_t *p) {
  return p ? p->network_destination_count : 0u;
}
maelys_mir_result_t maelys_sandbox_policy_plan_network_destination_at(
    const maelys_sandbox_policy_plan_t *p, size_t index,
    maelys_mir_network_destination_view_t *out) {
  if (!p || !out || index >= p->network_destination_count)
    return MAELYS_MIR_ERR_ARGUMENT;
  const maelys_mir_network_destination_t *destination =
      &p->network_destinations[index];
  *out = (maelys_mir_network_destination_view_t){
      destination->protocol, destination->host, destination->port};
  return MAELYS_MIR_OK;
}
int maelys_sandbox_policy_plan_process_tree_required(const maelys_sandbox_policy_plan_t *p) {
  return p ? p->process_tree_required : 0;
}
const char *maelys_sandbox_policy_plan_mir_digest(const maelys_sandbox_policy_plan_t *p) {
  return p ? p->digest : NULL;
}
