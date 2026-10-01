/*
 * What a policy requires of a backend, read from the MIR alone, and the
 * stable names of those capabilities. Nothing here touches the filesystem:
 * it lives apart from the host resolution so that a program which only
 * names or compares capabilities links none of it.
 */
#include "internal.h"

#include <stdio.h>

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
  for (size_t i = 0; i < mir->network_destination_count; ++i) {
    maelys_mir_network_destination_flags_t flags =
        mir->network_destinations[i].flags;
    if (flags & MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI)
      c |= MAELYS_SANDBOX_POLICY_CAP_NETWORK_REQUIRE_TLS_SNI;
    if (flags & MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES)
      c |= MAELYS_SANDBOX_POLICY_CAP_NETWORK_PRIVATE_ADDRESSES;
  }
  return c;
}

const char *maelys_sandbox_policy_capability_name(
    maelys_sandbox_policy_capabilities_t cap) {
  switch (cap) {
  case MAELYS_SANDBOX_POLICY_CAP_FS_READ:
    return "fs-read";
  case MAELYS_SANDBOX_POLICY_CAP_FS_WRITE:
    return "fs-write";
  case MAELYS_SANDBOX_POLICY_CAP_FS_DENY:
    return "fs-deny";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE:
    return "network-none";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT:
    return "network-direct";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED:
    return "network-mediated";
  case MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE:
    return "process-tree";
  case MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE:
    return "root-ephemeral-write";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_REQUIRE_TLS_SNI:
    return "network-require-tls-sni";
  case MAELYS_SANDBOX_POLICY_CAP_NETWORK_PRIVATE_ADDRESSES:
    return "network-private-addresses";
  case MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE:
    return "fs-protect-create";
  }
  return NULL;
}

/* Names every missing capability, never the first alone: a caller fixes
 * its backend selection once. */
maelys_mir_result_t
maelys_report_missing_capabilities(maelys_sandbox_policy_capabilities_t missing,
                                   char **err) {
  char names[512];
  size_t used = 0;
  names[0] = '\0';
  for (unsigned bit = 0; bit < 64; ++bit) {
    maelys_sandbox_policy_capabilities_t cap = UINT64_C(1) << bit;
    if (!(missing & cap))
      continue;
    const char *name = maelys_sandbox_policy_capability_name(cap);
    int written = snprintf(names + used, sizeof(names) - used, "%s%s",
                           used ? ", " : "", name ? name : "unknown");
    if (written < 0 || (size_t)written >= sizeof(names) - used)
      break;
    used += (size_t)written;
  }
  maelys_set_error(err, "sandbox backend lacks required capabilities: %s",
                   names);
  return MAELYS_MIR_ERR_UNSUPPORTED;
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
  return missing ? maelys_report_missing_capabilities(missing, err)
                 : MAELYS_MIR_OK;
}
