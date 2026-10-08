#ifndef MAELYS_SANDBOX_POLICY_H
#define MAELYS_SANDBOX_POLICY_H

#include <maelys/mir.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct maelys_sandbox_policy_host maelys_sandbox_policy_host_t;
typedef struct maelys_sandbox_policy_plan maelys_sandbox_policy_plan_t;

/* The revision of this header, raised by every change to it, and the oldest
 * revision whose declarations all still hold unchanged. A consumer written
 * for revision N is served when COMPATIBLE_SINCE <= N <= VERSION. */
#define MAELYS_SANDBOX_POLICY_ABI_VERSION 7u
#define MAELYS_SANDBOX_POLICY_ABI_COMPATIBLE_SINCE 5u
/* The permission contract a SandboxPlan carries. Contract 2: a deny wins
 * over every overlapping grant, grants are additive, and a policy whose
 * permissions differ from the most-specific-wins order of contract 1 is
 * refused with MAELYS_MIR_ERR_CONFLICT instead of being reinterpreted. */
#define MAELYS_SANDBOX_POLICY_PERMISSION_CONTRACT 2u
#define MAELYS_SANDBOX_POLICY_VERSION "0.11.0"

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
  MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE = UINT64_C(1) << 10,
  /* The backend removes writing from a path while it keeps reading: no
   * change to its content, entries or metadata, and the path itself is
   * neither removed, renamed nor replaced. Required by a deny-write rule. */
  MAELYS_SANDBOX_POLICY_CAP_FS_DENY_WRITE = UINT64_C(1) << 11
};

/* What a backend must do about a resolved rule whose path is absent at
 * launch. ERROR: the path existed at resolution and the launch fails
 * without it. PROTECT_CREATE: a deny or deny-write whose target did not exist at
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
  MAELYS_SANDBOX_POLICY_REASON_READ_RULE = 4,
  /* read, because a deny-write rule removes what a write grant gave */
  MAELYS_SANDBOX_POLICY_REASON_DENY_WRITE_RULE = 5
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
 * deny gives no access; otherwise an applicable read or write gives read,
 * and an applicable write gives write too unless a deny-write applies;
 * otherwise nothing. The root mode
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
/* The dimensions in which a candidate plan may exceed a boundary plan. */
enum {
  MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM = 1u << 0,
  MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK = 1u << 1,
  MAELYS_SANDBOX_POLICY_DIMENSION_ROOT = 1u << 2,
  MAELYS_SANDBOX_POLICY_DIMENSION_PROCESS = 1u << 3
};

typedef enum maelys_sandbox_policy_network_excess {
  MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_NONE = 0,
  /* the candidate's network mode is broader than the boundary's */
  MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_MODE = 1,
  /* a candidate destination is not in the boundary's allowlist */
  MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_DESTINATION = 2,
  /* the boundary requires TLS SNI on that destination, the candidate not */
  MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_TLS_SNI = 3,
  /* the candidate allows private addresses there, the boundary not */
  MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_PRIVATE_ADDRESSES = 4
} maelys_sandbox_policy_network_excess_t;

/* The answer of maelys_sandbox_policy_plan_contains(). `exceeds` has one
 * DIMENSION bit per dimension in which the candidate grants more than the
 * boundary, zero when it is contained; each such dimension carries one
 * witness. Release with maelys_sandbox_policy_containment_clear(). */
typedef struct maelys_sandbox_policy_containment {
  unsigned exceeds;
  /* FILESYSTEM: one resolved path, what each plan grants on it, and the
   * rule deciding each (SIZE_MAX under the default deny). */
  char *path;
  maelys_sandbox_policy_permission_t boundary_permission;
  maelys_sandbox_policy_permission_t candidate_permission;
  size_t boundary_rule;
  size_t candidate_rule;
  /* NETWORK: why, and the candidate destination concerned (SIZE_MAX when
   * the mode itself exceeds). */
  maelys_sandbox_policy_network_excess_t network;
  size_t candidate_destination;
} maelys_sandbox_policy_containment_t;

/*
 * Does `candidate` grant nothing that `boundary` does not? Both plans must
 * have been resolved under the same host context, on the same state of the
 * filesystem: the function cannot check it. The comparison is exact for the
 * permissions of the two plans. A filesystem witness is a path of that
 * model: whether an access to it can be realised on the host is not
 * established, and what a backend enforces is not either.
 *
 * Filesystem: no path receives more from the candidate, with none < read <
 * read-write. Network: none < mediated < direct; under a mediated boundary
 * every candidate destination is one of the boundary's, requires TLS SNI
 * where the boundary does and allows private addresses only where the
 * boundary does. Root: read-only < ephemeral-write. Process: a boundary
 * that requires process-tree confinement is not contained by a candidate
 * that does not.
 */
maelys_mir_result_t maelys_sandbox_policy_plan_contains(
    const maelys_sandbox_policy_plan_t *boundary,
    const maelys_sandbox_policy_plan_t *candidate,
    maelys_sandbox_policy_containment_t *out_containment, char **out_error);
void maelys_sandbox_policy_containment_clear(
    maelys_sandbox_policy_containment_t *containment);

/*
 * What changes between two resolved plans, under the same conditions as
 * maelys_sandbox_policy_plan_contains(): same host context, same state of
 * the filesystem. The plans are equivalent exactly when the diff neither
 * widens nor narrows any dimension, whatever their rules.
 */
typedef struct maelys_sandbox_policy_diff maelys_sandbox_policy_diff_t;

/* One path where the difference between the plans changes. `self` is what
 * both plans grant on the path itself. `below` is what they grant under it,
 * down to the next entry, when its two permissions differ; equal `below`
 * permissions say only that nothing changes there. An entry overrides, for
 * its path and beneath, the entries of the paths above it, so an entry with
 * equal permissions is an unchanged exception inside a changed tree. A path
 * under no entry is unchanged. */
typedef struct maelys_sandbox_policy_diff_path_view {
  const char *path;
  maelys_sandbox_policy_permission_t self_before;
  maelys_sandbox_policy_permission_t self_after;
  maelys_sandbox_policy_permission_t below_before;
  maelys_sandbox_policy_permission_t below_after;
} maelys_sandbox_policy_diff_path_view_t;

maelys_mir_result_t maelys_sandbox_policy_plan_diff(
    const maelys_sandbox_policy_plan_t *before,
    const maelys_sandbox_policy_plan_t *after,
    maelys_sandbox_policy_diff_t **out_diff, char **out_error);
void maelys_sandbox_policy_diff_destroy(maelys_sandbox_policy_diff_t *diff);
/* DIMENSION bits in which `after` grants more, and in which it grants less.
 * Both zero: the plans are equivalent. One dimension may be in both. */
unsigned maelys_sandbox_policy_diff_widens(const maelys_sandbox_policy_diff_t *diff);
unsigned maelys_sandbox_policy_diff_narrows(const maelys_sandbox_policy_diff_t *diff);
size_t maelys_sandbox_policy_diff_path_count(const maelys_sandbox_policy_diff_t *diff);
maelys_mir_result_t maelys_sandbox_policy_diff_path_at(
    const maelys_sandbox_policy_diff_t *diff, size_t index,
    maelys_sandbox_policy_diff_path_view_t *out_path);
/* Mediated destinations of `after` that `before` does not hold with the same
 * flags, as indexes into `after`; and those of `before` that `after` does
 * not hold, as indexes into `before`. A destination whose flags changed is
 * in both. */
size_t maelys_sandbox_policy_diff_added_destination_count(
    const maelys_sandbox_policy_diff_t *diff);
size_t maelys_sandbox_policy_diff_added_destination_at(
    const maelys_sandbox_policy_diff_t *diff, size_t index);
size_t maelys_sandbox_policy_diff_removed_destination_count(
    const maelys_sandbox_policy_diff_t *diff);
size_t maelys_sandbox_policy_diff_removed_destination_at(
    const maelys_sandbox_policy_diff_t *diff, size_t index);

/* Is there an access both plans grant? `dimensions` has the FILESYSTEM bit
 * when some path is readable under both, and the NETWORK bit when some
 * connection is allowed by both. Root mode and process confinement are
 * constraints on the execution, not accesses: they have no overlap.
 * Release with maelys_sandbox_policy_overlap_clear(). */
typedef struct maelys_sandbox_policy_overlap {
  unsigned dimensions;
  /* A path both plans let read, and one both let write; NULL when none. */
  char *read_path;
  char *write_path;
  /* The common connection: a destination of each plan, SIZE_MAX for a plan
   * whose direct network allows every destination. */
  size_t first_destination;
  size_t second_destination;
} maelys_sandbox_policy_overlap_t;

maelys_mir_result_t maelys_sandbox_policy_plan_overlaps(
    const maelys_sandbox_policy_plan_t *first,
    const maelys_sandbox_policy_plan_t *second,
    maelys_sandbox_policy_overlap_t *out_overlap, char **out_error);
void maelys_sandbox_policy_overlap_clear(maelys_sandbox_policy_overlap_t *overlap);

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
