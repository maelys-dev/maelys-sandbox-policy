#ifndef MAELYS_SANDBOX_POLICY_H
#define MAELYS_SANDBOX_POLICY_H

#include <maelys/mir.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct maelys_sandbox_policy_host maelys_sandbox_policy_host_t;
typedef struct maelys_sandbox_policy_plan maelys_sandbox_policy_plan_t;

#define MAELYS_SANDBOX_POLICY_ABI_VERSION 4u
#define MAELYS_SANDBOX_POLICY_VERSION "0.4.1"

typedef uint64_t maelys_sandbox_policy_capabilities_t;
enum {
  MAELYS_SANDBOX_POLICY_CAP_FS_READ = UINT64_C(1) << 0,
  MAELYS_SANDBOX_POLICY_CAP_FS_WRITE = UINT64_C(1) << 1,
  MAELYS_SANDBOX_POLICY_CAP_FS_DENY = UINT64_C(1) << 2,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE = UINT64_C(1) << 3,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT = UINT64_C(1) << 4,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED = UINT64_C(1) << 5,
  MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE = UINT64_C(1) << 6,
  MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE = UINT64_C(1) << 7
};

typedef struct maelys_sandbox_policy_resolved_rule_view {
  maelys_mir_fs_access_t access;
  maelys_mir_path_scope_t scope;
  const char *path;
} maelys_sandbox_policy_resolved_rule_view_t;

maelys_mir_result_t maelys_sandbox_policy_host_create(maelys_sandbox_policy_host_t **out_host,
                                               char **out_error);
void maelys_sandbox_policy_host_destroy(maelys_sandbox_policy_host_t *host);
maelys_mir_result_t
maelys_sandbox_policy_host_set_workspace(maelys_sandbox_policy_host_t *host, const char *path,
                                  char **out_error);
maelys_mir_result_t maelys_sandbox_policy_host_set_temp(maelys_sandbox_policy_host_t *host,
                                                 const char *path,
                                                 char **out_error);
maelys_mir_result_t maelys_sandbox_policy_host_add_minimal_runtime_root(
    maelys_sandbox_policy_host_t *host, const char *path, char **out_error);
maelys_mir_result_t maelys_sandbox_policy_host_set_network_mediator(
    maelys_sandbox_policy_host_t *host, const char *mediator_id, char **out_error);

maelys_sandbox_policy_capabilities_t
maelys_sandbox_policy_required_capabilities(const maelys_mir_t *mir);
maelys_mir_result_t
maelys_sandbox_policy_check_support(const maelys_mir_t *mir,
                             maelys_sandbox_policy_capabilities_t available,
                             char **out_error);

maelys_mir_result_t
maelys_sandbox_policy_compile(const maelys_mir_t *mir,
                       const maelys_sandbox_policy_host_t *host,
                       maelys_sandbox_policy_capabilities_t available,
                       maelys_sandbox_policy_plan_t **out_plan, char **out_error);
void maelys_sandbox_policy_plan_destroy(maelys_sandbox_policy_plan_t *plan);
size_t maelys_sandbox_policy_plan_rule_count(const maelys_sandbox_policy_plan_t *plan);
maelys_mir_result_t
maelys_sandbox_policy_plan_rule_at(const maelys_sandbox_policy_plan_t *plan, size_t index,
                            maelys_sandbox_policy_resolved_rule_view_t *out_rule);
maelys_mir_network_mode_t
maelys_sandbox_policy_plan_network(const maelys_sandbox_policy_plan_t *plan);
maelys_mir_root_mode_t maelys_sandbox_policy_plan_root_mode(
    const maelys_sandbox_policy_plan_t *plan);
const char *
maelys_sandbox_policy_plan_network_mediator(const maelys_sandbox_policy_plan_t *plan);
size_t maelys_sandbox_policy_plan_network_destination_count(
    const maelys_sandbox_policy_plan_t *plan);
maelys_mir_result_t maelys_sandbox_policy_plan_network_destination_at(
    const maelys_sandbox_policy_plan_t *plan,
    size_t index,
    maelys_mir_network_destination_view_t *out_destination);
int maelys_sandbox_policy_plan_process_tree_required(
    const maelys_sandbox_policy_plan_t *plan);
const char *maelys_sandbox_policy_plan_mir_digest(const maelys_sandbox_policy_plan_t *plan);

#ifdef __cplusplus
}
#endif

#endif
