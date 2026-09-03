#ifndef MAELYS_SANDBOX_POLICY_INTERNAL_H
#define MAELYS_SANDBOX_POLICY_INTERNAL_H

#include <maelys/mir.h>
#include <maelys/sandbox_policy.h>

#include <stdarg.h>

typedef struct maelys_mir_fs_rule {
  maelys_mir_fs_access_t access;
  maelys_mir_path_root_t root;
  maelys_mir_path_scope_t scope;
  maelys_mir_missing_path_t missing;
  char *relative;
} maelys_mir_fs_rule_t;

typedef struct maelys_mir_network_destination {
  maelys_mir_network_protocol_t protocol;
  char *host;
  uint16_t port;
} maelys_mir_network_destination_t;

struct maelys_mir_builder {
  maelys_mir_fs_rule_t *rules;
  size_t rule_count;
  size_t rule_capacity;
  maelys_mir_network_mode_t network;
  maelys_mir_root_mode_t root_mode;
  maelys_mir_network_destination_t *network_destinations;
  size_t network_destination_count;
  size_t network_destination_capacity;
  int process_tree_required;
};

struct maelys_mir {
  maelys_mir_fs_rule_t *rules;
  size_t rule_count;
  maelys_mir_network_mode_t network;
  maelys_mir_root_mode_t root_mode;
  maelys_mir_network_destination_t *network_destinations;
  size_t network_destination_count;
  int process_tree_required;
};

struct maelys_sandbox_policy_host {
  char *workspace;
  char *temp;
  char *network_mediator;
  char **minimal_roots;
  size_t minimal_root_count;
  size_t minimal_root_capacity;
};

typedef struct maelys_sandbox_policy_resolved_rule {
  maelys_mir_fs_access_t access;
  maelys_mir_path_scope_t scope;
  char *path;
} maelys_sandbox_policy_resolved_rule_t;

struct maelys_sandbox_policy_plan {
  maelys_sandbox_policy_resolved_rule_t *rules;
  size_t rule_count;
  size_t rule_capacity;
  maelys_mir_network_mode_t network;
  maelys_mir_root_mode_t root_mode;
  char *network_mediator;
  maelys_mir_network_destination_t *network_destinations;
  size_t network_destination_count;
  int process_tree_required;
  char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
};

void maelys_set_error(char **out_error, const char *format, ...);
char *maelys_strdup(const char *value);
int maelys_valid_utf8_no_nul(const uint8_t *bytes, size_t size);
maelys_mir_result_t maelys_normalize_relative(maelys_mir_path_root_t root,
                                              const char *input, char **out,
                                              char **out_error);

void maelys_sha256(const uint8_t *data, size_t size, uint8_t out[32]);
void maelys_digest_to_hex(const uint8_t digest[32],
                          char out[MAELYS_MIR_DIGEST_HEX_SIZE]);

#endif
