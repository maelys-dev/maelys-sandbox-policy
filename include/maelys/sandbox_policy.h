#ifndef MAELYS_SANDBOX_POLICY_H
#define MAELYS_SANDBOX_POLICY_H

#include <maelys/mir.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct maelys_sandbox_policy_host maelys_sandbox_policy_host_t;
typedef struct maelys_sandbox_policy_plan maelys_sandbox_policy_plan_t;

#define MAELYS_SANDBOX_POLICY_ABI_VERSION 5u
/* The permission contract a SandboxPlan carries. Contract 2: a deny wins
 * over every overlapping grant, grants are additive, and a policy whose
 * permissions differ from the most-specific-wins order of contract 1 is
 * refused with MAELYS_MIR_ERR_CONFLICT instead of being reinterpreted. */
#define MAELYS_SANDBOX_POLICY_PERMISSION_CONTRACT 2u
#define MAELYS_SANDBOX_POLICY_VERSION "0.6.0"

typedef uint64_t maelys_sandbox_policy_capabilities_t;
enum {
  MAELYS_SANDBOX_POLICY_CAP_FS_READ = UINT64_C(1) << 0,
  MAELYS_SANDBOX_POLICY_CAP_FS_WRITE = UINT64_C(1) << 1,
  MAELYS_SANDBOX_POLICY_CAP_FS_DENY = UINT64_C(1) << 2,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE = UINT64_C(1) << 3,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT = UINT64_C(1) << 4,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED = UINT64_C(1) << 5,
  MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE = UINT64_C(1) << 6,
  MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE = UINT64_C(1) << 7,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_REQUIRE_TLS_SNI = UINT64_C(1) << 8,
  MAELYS_SANDBOX_POLICY_CAP_NETWORK_PRIVATE_ADDRESSES = UINT64_C(1) << 9,
  /* The backend keeps a denied path that does not exist yet from being
   * created, linked or renamed into place. Required by resolution, when a
   * deny names an absent target: it cannot be read from the MIR alone. */
  MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE = UINT64_C(1) << 10
};

/* What a backend must do about a resolved rule whose path is absent at
 * launch. ERROR: the path existed at resolution and the launch fails
 * without it. PROTECT_CREATE: a deny whose target did not exist at
 * resolution; the path is the canonical existing prefix followed by the
 * literal remaining components. That names the path and guarantees nothing:
 * protecting it against creation, links and renames is the backend's, which
 * must never downgrade this value to ERROR nor skip the rule. */
typedef enum maelys_sandbox_policy_missing {
  MAELYS_SANDBOX_POLICY_MISSING_ERROR = 1,
  MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE = 2
} maelys_sandbox_policy_missing_t;

typedef struct maelys_sandbox_policy_resolved_rule_view {
  maelys_mir_fs_access_t access;
  maelys_mir_path_scope_t scope;
  const char *path;
  maelys_sandbox_policy_missing_t missing;
} maelys_sandbox_policy_resolved_rule_view_t;

typedef enum maelys_sandbox_policy_permission {
  MAELYS_SANDBOX_POLICY_PERMISSION_NONE = 0,
  MAELYS_SANDBOX_POLICY_PERMISSION_READ = 1,
  MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE = 2
} maelys_sandbox_policy_permission_t;

typedef enum maelys_sandbox_policy_reason {
  MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY = 1,
  MAELYS_SANDBOX_POLICY_REASON_DENY_RULE = 2,
  MAELYS_SANDBOX_POLICY_REASON_WRITE_RULE = 3,
  MAELYS_SANDBOX_POLICY_REASON_READ_RULE = 4
} maelys_sandbox_policy_reason_t;

typedef struct maelys_sandbox_policy_evaluation {
  maelys_sandbox_policy_permission_t permission;
  maelys_sandbox_policy_reason_t reason;
  /* Index of one rule that decides, for maelys_sandbox_policy_plan_rule_at();
   * SIZE_MAX under REASON_DEFAULT_DENY. */
  size_t decisive_rule;
  size_t applicable_rule_count;
} maelys_sandbox_policy_evaluation_t;

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

/* The capabilities the MIR requires by itself. Resolution may require more:
 * see maelys_sandbox_policy_resolved_capabilities(). */
maelys_sandbox_policy_capabilities_t
maelys_sandbox_policy_required_capabilities(const maelys_mir_t *mir);
/* Every capability the policy requires on this host, those of the MIR and
 * those resolution discovers, so that a caller can report all the missing
 * ones at once. It resolves paths as compile does and returns no plan. */
maelys_mir_result_t maelys_sandbox_policy_resolved_capabilities(
    const maelys_mir_t *mir, const maelys_sandbox_policy_host_t *host,
    maelys_sandbox_policy_capabilities_t *out_required, char **out_error);
/* Stable identifier of one capability bit, such as "fs-protect-create";
 * NULL for a value that is not exactly one known capability. */
const char *
maelys_sandbox_policy_capability_name(maelys_sandbox_policy_capabilities_t capability);
/* The capabilities this plan requires, resolution included. */
maelys_sandbox_policy_capabilities_t maelys_sandbox_policy_plan_required_capabilities(
    const maelys_sandbox_policy_plan_t *plan);
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
/*
 * Reference evaluator of the filesystem permission contract: what the plan
 * grants on one resolved absolute path. It reads the rules only, never the
 * filesystem, and its answer does not depend on their order: any applicable
 * deny gives no access; otherwise any applicable write gives read and write;
 * otherwise an applicable read gives read; otherwise nothing. The root mode
 * grants nothing. A backend conforms when it enforces exactly this, or
 * refuses the plan before launch.
 */
maelys_mir_result_t maelys_sandbox_policy_plan_evaluate(
    const maelys_sandbox_policy_plan_t *plan, const char *absolute_path,
    maelys_sandbox_policy_evaluation_t *out_evaluation, char **out_error);
const char *
maelys_sandbox_policy_permission_name(maelys_sandbox_policy_permission_t value);
const char *
maelys_sandbox_policy_reason_name(maelys_sandbox_policy_reason_t value);
/* A grant that resolution left out of the plan: its target was absent and
 * its rule said missing: skip. It grants nothing; it is reported so that a
 * reader of the plan knows the rule was seen. A deny is never omitted.
 * host_root is the resolved root the path was looked up under, NULL for a
 * host path; one MIR rule on minimal-runtime may be omitted under some
 * roots and kept under others. */
typedef struct maelys_sandbox_policy_omitted_rule_view {
  maelys_mir_fs_access_t access;
  maelys_mir_path_scope_t scope;
  maelys_mir_path_root_t root;
  const char *relative;
  const char *host_root;
} maelys_sandbox_policy_omitted_rule_view_t;

size_t maelys_sandbox_policy_plan_omitted_rule_count(
    const maelys_sandbox_policy_plan_t *plan);
maelys_mir_result_t maelys_sandbox_policy_plan_omitted_rule_at(
    const maelys_sandbox_policy_plan_t *plan, size_t index,
    maelys_sandbox_policy_omitted_rule_view_t *out_rule);
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
maelys_mir_result_t maelys_sandbox_policy_plan_network_destination_at_ex(
    const maelys_sandbox_policy_plan_t *plan,
    size_t index,
    maelys_mir_network_destination_ex_view_t *out_destination);
int maelys_sandbox_policy_plan_process_tree_required(
    const maelys_sandbox_policy_plan_t *plan);
const char *maelys_sandbox_policy_plan_mir_digest(const maelys_sandbox_policy_plan_t *plan);

#ifdef __cplusplus
}
#endif

#endif
