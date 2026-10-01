/*
 * Containment of one resolved plan in another: the candidate grants nothing
 * the boundary does not.
 *
 * For the filesystem, the rules applying to a path are, in each plan, its
 * exact rules naming the path and its tree rules at or above it. Take the
 * paths named by the rules of both plans. A path that is none of them
 * receives, from each plan, what the tree rules at or above its deepest
 * named ancestor grant, and nothing when it has none. Checking every named
 * path and one unnamed descendant of each therefore visits every region:
 * at most twice the number of distinct paths of the two plans.
 */
#include "internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { BOUNDARY = 0, CANDIDATE = 1 };

/* The rules of both plans in one array, boundary first; paths are borrowed. */
static maelys_sandbox_policy_resolved_rule_t *
merge_rules(const maelys_sandbox_policy_resolved_rule_t *boundary, size_t n,
            const maelys_sandbox_policy_resolved_rule_t *candidate, size_t m) {
  maelys_sandbox_policy_resolved_rule_t *merged =
      malloc((n + m) * sizeof(*merged));
  if (!merged)
    return NULL;
  if (n)
    memcpy(merged, boundary, n * sizeof(*merged));
  if (m)
    memcpy(merged + n, candidate, m * sizeof(*merged));
  return merged;
}

static int exceeds_at(const maelys_sandbox_policy_resolved_rule_t *boundary,
                      size_t n,
                      const maelys_sandbox_policy_resolved_rule_t *candidate,
                      size_t m, const char *path) {
  maelys_sandbox_policy_evaluation_t allowed, asked;
  maelys_plan_evaluate(boundary, n, path, &allowed);
  maelys_plan_evaluate(candidate, m, path, &asked);
  return asked.permission > allowed.permission;
}

/* The definition: every region against every rule. The witness is the
 * first in component order of the path it stands for, the path itself
 * before its descendant region. */
maelys_mir_result_t maelys_plan_filesystem_excess_reference(
    const maelys_sandbox_policy_resolved_rule_t *boundary, size_t n,
    const maelys_sandbox_policy_resolved_rule_t *candidate, size_t m,
    char **out) {
  *out = NULL;
  if (n + m == 0u)
    return MAELYS_MIR_OK;
  maelys_sandbox_policy_resolved_rule_t *merged =
      merge_rules(boundary, n, candidate, m);
  if (!merged)
    return MAELYS_MIR_ERR_MEMORY;
  const char *best_base = NULL;
  int best_below = 0;
  char *best = NULL;
  maelys_mir_result_t result = MAELYS_MIR_OK;
  for (size_t i = 0; i < n + m && result == MAELYS_MIR_OK; ++i) {
    for (int below = 0; below <= 1 && result == MAELYS_MIR_OK; ++below) {
      char *witness = below ? maelys_plan_descendant_witness(merged, n + m,
                                                             merged[i].path)
                            : maelys_strdup(merged[i].path);
      if (!witness) {
        result = MAELYS_MIR_ERR_MEMORY;
        break;
      }
      int order = best_base ? maelys_path_component_order(merged[i].path,
                                                          best_base)
                            : -1;
      if (exceeds_at(boundary, n, candidate, m, witness) &&
          (order < 0 || (order == 0 && below < best_below))) {
        free(best);
        best = witness;
        best_base = merged[i].path;
        best_below = below;
      } else {
        free(witness);
      }
    }
  }
  free(merged);
  if (result != MAELYS_MIR_OK) {
    free(best);
    return result;
  }
  *out = best;
  return MAELYS_MIR_OK;
}

typedef struct ordered_rule {
  const char *path;
  size_t index;
} ordered_rule_t;

static int by_component_order(const void *left, const void *right) {
  const ordered_rule_t *a = left, *b = right;
  int order = maelys_path_component_order(a->path, b->path);
  if (order)
    return order;
  return a->index < b->index ? -1 : a->index > b->index;
}

/* What the tree rules of a path and of every path above it grant, in each
 * plan. */
typedef struct tree_state {
  const char *path;
  unsigned accesses[2];
} tree_state_t;

/* The same answer in one pass over the paths in component order, with the
 * stack of the paths above the current one. */
maelys_mir_result_t maelys_plan_filesystem_excess(
    const maelys_sandbox_policy_resolved_rule_t *boundary, size_t n,
    const maelys_sandbox_policy_resolved_rule_t *candidate, size_t m,
    char **out) {
  *out = NULL;
  size_t total = n + m;
  if (total == 0u)
    return MAELYS_MIR_OK;
  maelys_sandbox_policy_resolved_rule_t *merged =
      merge_rules(boundary, n, candidate, m);
  ordered_rule_t *order = malloc(total * sizeof(*order));
  tree_state_t *stack = malloc(total * sizeof(*stack));
  if (!merged || !order || !stack) {
    free(merged);
    free(order);
    free(stack);
    return MAELYS_MIR_ERR_MEMORY;
  }
  for (size_t i = 0; i < total; ++i)
    order[i] = (ordered_rule_t){merged[i].path, i};
  qsort(order, total, sizeof(*order), by_component_order);

  const char *base = NULL;
  int below_base = 0;
  size_t depth = 0;
  for (size_t first = 0, next; first < total && !base; first = next) {
    const char *path = order[first].path;
    unsigned exact[2] = {0u, 0u}, tree[2] = {0u, 0u};
    for (next = first; next < total && strcmp(order[next].path, path) == 0;
         ++next) {
      const maelys_sandbox_policy_resolved_rule_t *rule =
          &merged[order[next].index];
      unsigned side = order[next].index < n ? BOUNDARY : CANDIDATE;
      if (rule->scope == MAELYS_MIR_SCOPE_TREE)
        tree[side] |= MAELYS_ACCESS_BIT(rule->access);
      else
        exact[side] |= MAELYS_ACCESS_BIT(rule->access);
    }
    while (depth && !maelys_path_strictly_above(stack[depth - 1u].path, path))
      --depth;
    unsigned inherited[2] = {depth ? stack[depth - 1u].accesses[BOUNDARY] : 0u,
                             depth ? stack[depth - 1u].accesses[CANDIDATE] : 0u};
    unsigned under[2] = {inherited[BOUNDARY] | tree[BOUNDARY],
                         inherited[CANDIDATE] | tree[CANDIDATE]};
    if (maelys_contract_permission(under[CANDIDATE] | exact[CANDIDATE]) >
        maelys_contract_permission(under[BOUNDARY] | exact[BOUNDARY])) {
      base = path;
    } else if (maelys_contract_permission(under[CANDIDATE]) >
               maelys_contract_permission(under[BOUNDARY])) {
      base = path;
      below_base = 1;
    }
    stack[depth++] = (tree_state_t){path, {under[BOUNDARY], under[CANDIDATE]}};
  }
  free(order);
  free(stack);

  maelys_mir_result_t result = MAELYS_MIR_OK;
  if (base) {
    char *witness = below_base
                        ? maelys_plan_descendant_witness(merged, total, base)
                        : maelys_strdup(base);
    if (!witness) {
      result = MAELYS_MIR_ERR_MEMORY;
    } else if (exceeds_at(boundary, n, candidate, m, witness)) {
      *out = witness;
    } else {
      /* The pass and the definition disagree, which no input should
       * produce: let the definition decide. */
      free(witness);
      free(merged);
      return maelys_plan_filesystem_excess_reference(boundary, n, candidate, m,
                                                     out);
    }
  }
  free(merged);
  return result;
}

static int network_rank(maelys_mir_network_mode_t mode) {
  return mode == MAELYS_MIR_NETWORK_NONE       ? 0
         : mode == MAELYS_MIR_NETWORK_MEDIATED ? 1
                                               : 2;
}

static void network_excess(const maelys_sandbox_policy_plan_t *boundary,
                           const maelys_sandbox_policy_plan_t *candidate,
                           maelys_sandbox_policy_containment_t *out) {
  out->network = MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_NONE;
  out->candidate_destination = SIZE_MAX;
  if (network_rank(candidate->network) > network_rank(boundary->network)) {
    out->network = MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_MODE;
    return;
  }
  /* A direct boundary allows every destination; a candidate without
   * mediation names none. */
  if (boundary->network != MAELYS_MIR_NETWORK_MEDIATED ||
      candidate->network != MAELYS_MIR_NETWORK_MEDIATED)
    return;
  for (size_t i = 0; i < candidate->network_destination_count; ++i) {
    const maelys_mir_network_destination_t *asked =
        &candidate->network_destinations[i];
    const maelys_mir_network_destination_t *allowed = NULL;
    for (size_t j = 0; j < boundary->network_destination_count && !allowed;
         ++j) {
      const maelys_mir_network_destination_t *d =
          &boundary->network_destinations[j];
      if (d->protocol == asked->protocol && d->port == asked->port &&
          strcmp(d->host, asked->host) == 0)
        allowed = d;
    }
    maelys_sandbox_policy_network_excess_t excess =
        MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_NONE;
    if (!allowed)
      excess = MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_DESTINATION;
    else if ((allowed->flags & MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI) &&
             !(asked->flags & MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI))
      excess = MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_TLS_SNI;
    else if ((asked->flags &
              MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES) &&
             !(allowed->flags &
               MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES))
      excess = MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_PRIVATE_ADDRESSES;
    if (excess) {
      out->network = excess;
      out->candidate_destination = i;
      return;
    }
  }
}

void maelys_sandbox_policy_containment_clear(
    maelys_sandbox_policy_containment_t *containment) {
  if (!containment)
    return;
  free(containment->path);
  memset(containment, 0, sizeof(*containment));
  containment->boundary_rule = containment->candidate_rule = SIZE_MAX;
  containment->candidate_destination = SIZE_MAX;
}

maelys_mir_result_t maelys_sandbox_policy_plan_contains(
    const maelys_sandbox_policy_plan_t *boundary,
    const maelys_sandbox_policy_plan_t *candidate,
    maelys_sandbox_policy_containment_t *out, char **err) {
  if (out) {
    out->path = NULL;
    maelys_sandbox_policy_containment_clear(out);
  }
  if (!boundary || !candidate || !out) {
    maelys_set_error(err, "boundary plan, candidate plan and output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  char *witness = NULL;
  maelys_mir_result_t result = maelys_plan_filesystem_excess(
      boundary->rules, boundary->rule_count, candidate->rules,
      candidate->rule_count, &witness);
  if (result != MAELYS_MIR_OK)
    return result;
  if (witness) {
    maelys_sandbox_policy_evaluation_t allowed, asked;
    maelys_plan_evaluate(boundary->rules, boundary->rule_count, witness,
                         &allowed);
    maelys_plan_evaluate(candidate->rules, candidate->rule_count, witness,
                         &asked);
    out->exceeds |= MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM;
    out->path = witness;
    out->boundary_permission = allowed.permission;
    out->candidate_permission = asked.permission;
    out->boundary_rule = allowed.decisive_rule;
    out->candidate_rule = asked.decisive_rule;
  }
  network_excess(boundary, candidate, out);
  if (out->network)
    out->exceeds |= MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK;
  if (candidate->root_mode == MAELYS_MIR_ROOT_EPHEMERAL_WRITE &&
      boundary->root_mode != MAELYS_MIR_ROOT_EPHEMERAL_WRITE)
    out->exceeds |= MAELYS_SANDBOX_POLICY_DIMENSION_ROOT;
  if (boundary->process_tree_required && !candidate->process_tree_required)
    out->exceeds |= MAELYS_SANDBOX_POLICY_DIMENSION_PROCESS;
  return MAELYS_MIR_OK;
}
