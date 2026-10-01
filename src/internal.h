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
  maelys_mir_network_destination_flags_t flags;
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
  maelys_sandbox_policy_missing_t missing;
} maelys_sandbox_policy_resolved_rule_t;

typedef struct maelys_sandbox_policy_omitted_rule {
  maelys_mir_fs_access_t access;
  maelys_mir_path_scope_t scope;
  maelys_mir_path_root_t root;
  char *relative;
  char *host_root;
} maelys_sandbox_policy_omitted_rule_t;

struct maelys_sandbox_policy_plan {
  maelys_sandbox_policy_resolved_rule_t *rules;
  size_t rule_count;
  size_t rule_capacity;
  maelys_sandbox_policy_omitted_rule_t *omitted;
  size_t omitted_count;
  size_t omitted_capacity;
  maelys_mir_network_mode_t network;
  maelys_mir_root_mode_t root_mode;
  char *network_mediator;
  maelys_mir_network_destination_t *network_destinations;
  size_t network_destination_count;
  int process_tree_required;
  maelys_sandbox_policy_capabilities_t required;
  char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
};

/* Where the most-specific-wins order of ABI 4 and the permission contract
 * disagree: one path, what each grants there and the rule deciding each. */
typedef struct maelys_plan_conflict {
  char *witness;
  maelys_sandbox_policy_permission_t before;
  maelys_sandbox_policy_permission_t after;
  size_t legacy_rule;
  size_t contract_rule;
} maelys_plan_conflict_t;

int maelys_plan_path_is_canonical(const char *path);
int maelys_plan_rule_applies(const maelys_sandbox_policy_resolved_rule_t *rule,
                             const char *path);
void maelys_plan_evaluate(const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t count, const char *path,
                          maelys_sandbox_policy_evaluation_t *out);
maelys_mir_result_t
maelys_plan_find_conflict(const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t count, maelys_plan_conflict_t *out);
/* The same answer by the definition, in time quadratic in `count`. */
maelys_mir_result_t maelys_plan_find_conflict_reference(
    const maelys_sandbox_policy_resolved_rule_t *rules, size_t count,
    maelys_plan_conflict_t *out);
/* Paths in component order: '/' sorts before every other byte, so a path is
 * followed at once by everything under it. */
int maelys_path_component_order(const char *a, const char *b);
int maelys_path_strictly_above(const char *ancestor, const char *path);
/* A path strictly inside `base` that no rule names nor lies under; owned by
 * the caller, NULL when out of memory. */
char *maelys_plan_descendant_witness(
    const maelys_sandbox_policy_resolved_rule_t *rules, size_t count,
    const char *base);
/* The contract over a set of applicable accesses, one bit per access. */
#define MAELYS_ACCESS_BIT(access) (1u << (unsigned)(access))
maelys_sandbox_policy_permission_t maelys_contract_permission(unsigned accesses);
/* The first path, in component order, where the candidate rules grant more
 * than the boundary rules; *out_witness is NULL when there is none. The
 * reference decides by the definition, in quadratic time. */
maelys_mir_result_t maelys_plan_filesystem_excess(
    const maelys_sandbox_policy_resolved_rule_t *boundary, size_t boundary_count,
    const maelys_sandbox_policy_resolved_rule_t *candidate,
    size_t candidate_count, char **out_witness);
maelys_mir_result_t maelys_plan_filesystem_excess_reference(
    const maelys_sandbox_policy_resolved_rule_t *boundary, size_t boundary_count,
    const maelys_sandbox_policy_resolved_rule_t *candidate,
    size_t candidate_count, char **out_witness);
/* Refuses a precedence conflict, then puts the rules in plan order. */
maelys_mir_result_t
maelys_sandbox_policy_plan_finalize(maelys_sandbox_policy_plan_t *plan,
                                    char **out_error);

/* Names every capability of `missing` and returns ERR_UNSUPPORTED. */
maelys_mir_result_t
maelys_report_missing_capabilities(maelys_sandbox_policy_capabilities_t missing,
                                   char **out_error);

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
