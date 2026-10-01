/*
 * The permission contract of a SandboxPlan, independent of rule order:
 *
 *   any applicable deny            -> no access
 *   no deny, any applicable write  -> read and write
 *   only applicable reads          -> read
 *   no applicable rule             -> no access
 *
 * Scope decides whether a rule applies; the precision of its path never
 * beats a deny nor removes an inherited write. The plan order is a derived
 * encoding of this contract, not its definition.
 */
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int maelys_plan_path_is_canonical(const char *path) {
  if (!path || path[0] != '/')
    return 0;
  if (path[1] == '\0')
    return 1;
  for (const char *segment = path + 1;;) {
    const char *end = strchr(segment, '/');
    size_t length = end ? (size_t)(end - segment) : strlen(segment);
    if (length == 0u || (length == 1u && segment[0] == '.') ||
        (length == 2u && segment[0] == '.' && segment[1] == '.'))
      return 0;
    if (!end)
      return 1;
    segment = end + 1;
  }
}

int maelys_plan_rule_applies(const maelys_sandbox_policy_resolved_rule_t *rule,
                             const char *path) {
  size_t n = strlen(rule->path);
  if (strcmp(rule->path, path) == 0)
    return 1;
  if (rule->scope != MAELYS_MIR_SCOPE_TREE)
    return 0;
  if (n == 1u) /* the tree of "/" holds every absolute path */
    return 1;
  return strncmp(rule->path, path, n) == 0 && path[n] == '/';
}

void maelys_plan_evaluate(const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t count, const char *path,
                          maelys_sandbox_policy_evaluation_t *out) {
  size_t deny = SIZE_MAX, write = SIZE_MAX, read = SIZE_MAX, applicable = 0u;
  for (size_t i = 0; i < count; ++i) {
    if (!maelys_plan_rule_applies(&rules[i], path))
      continue;
    ++applicable;
    if (rules[i].access == MAELYS_MIR_FS_DENY && deny == SIZE_MAX)
      deny = i;
    else if (rules[i].access == MAELYS_MIR_FS_WRITE && write == SIZE_MAX)
      write = i;
    else if (rules[i].access == MAELYS_MIR_FS_READ && read == SIZE_MAX)
      read = i;
  }
  out->applicable_rule_count = applicable;
  if (deny != SIZE_MAX) {
    out->permission = MAELYS_SANDBOX_POLICY_PERMISSION_NONE;
    out->reason = MAELYS_SANDBOX_POLICY_REASON_DENY_RULE;
    out->decisive_rule = deny;
  } else if (write != SIZE_MAX) {
    out->permission = MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE;
    out->reason = MAELYS_SANDBOX_POLICY_REASON_WRITE_RULE;
    out->decisive_rule = write;
  } else if (read != SIZE_MAX) {
    out->permission = MAELYS_SANDBOX_POLICY_PERMISSION_READ;
    out->reason = MAELYS_SANDBOX_POLICY_REASON_READ_RULE;
    out->decisive_rule = read;
  } else {
    out->permission = MAELYS_SANDBOX_POLICY_PERMISSION_NONE;
    out->reason = MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY;
    out->decisive_rule = SIZE_MAX;
  }
}

/*
 * The order plans had through ABI 4, read by last-match backends as "the
 * most specific rule wins": broad to specific, tree before exact, and
 * read < write < deny on one target. It is kept only to find the policies
 * whose permissions the contract above would change.
 */
static int legacy_rule_compare(const maelys_sandbox_policy_resolved_rule_t *a,
                               const maelys_sandbox_policy_resolved_rule_t *b) {
  size_t an = strlen(a->path), bn = strlen(b->path);
  if (an != bn)
    return an < bn ? -1 : 1;
  int path = strcmp(a->path, b->path);
  if (path)
    return path;
  if (a->scope != b->scope)
    return a->scope == MAELYS_MIR_SCOPE_TREE ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  return 0;
}

static maelys_sandbox_policy_permission_t
permission_of(maelys_mir_fs_access_t access) {
  switch (access) {
  case MAELYS_MIR_FS_READ:
    return MAELYS_SANDBOX_POLICY_PERMISSION_READ;
  case MAELYS_MIR_FS_WRITE:
    return MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE;
  case MAELYS_MIR_FS_DENY:
    break;
  }
  return MAELYS_SANDBOX_POLICY_PERMISSION_NONE;
}

static maelys_sandbox_policy_permission_t
legacy_evaluate(const maelys_sandbox_policy_resolved_rule_t *rules,
                size_t count, const char *path, size_t *out_rule) {
  size_t winner = SIZE_MAX;
  for (size_t i = 0; i < count; ++i) {
    if (!maelys_plan_rule_applies(&rules[i], path))
      continue;
    if (winner == SIZE_MAX || legacy_rule_compare(&rules[winner], &rules[i]) < 0)
      winner = i;
  }
  *out_rule = winner;
  return winner == SIZE_MAX ? MAELYS_SANDBOX_POLICY_PERMISSION_NONE
                            : permission_of(rules[winner].access);
}

/* A path strictly inside `base` that no rule names nor lies under, so the
 * rules applying to it are exactly the tree rules at or above `base`. Each
 * rule path can spoil one candidate at most, so count + 1 attempts suffice. */
static char *descendant_witness(
    const maelys_sandbox_policy_resolved_rule_t *rules, size_t count,
    const char *base) {
  size_t base_length = strlen(base);
  size_t size = base_length + 48u;
  char *candidate = malloc(size);
  if (!candidate)
    return NULL;
  for (size_t attempt = 0; attempt <= count; ++attempt) {
    (void)snprintf(candidate, size, "%s/maelys-witness-%zu",
                   base_length == 1u ? "" : base, attempt);
    size_t n = strlen(candidate);
    int taken = 0;
    for (size_t i = 0; i < count && !taken; ++i)
      taken = strncmp(rules[i].path, candidate, n) == 0 &&
              (rules[i].path[n] == '\0' || rules[i].path[n] == '/');
    if (!taken)
      return candidate;
  }
  free(candidate);
  return NULL;
}

static int conflict_at(const maelys_sandbox_policy_resolved_rule_t *rules,
                       size_t count, const char *path,
                       maelys_plan_conflict_t *out) {
  maelys_sandbox_policy_evaluation_t contract;
  size_t legacy_rule = SIZE_MAX;
  maelys_plan_evaluate(rules, count, path, &contract);
  maelys_sandbox_policy_permission_t before =
      legacy_evaluate(rules, count, path, &legacy_rule);
  if (before == contract.permission)
    return 0;
  out->before = before;
  out->after = contract.permission;
  out->legacy_rule = legacy_rule;
  out->contract_rule = contract.decisive_rule;
  return 1;
}

/*
 * Permissions are constant between rule paths: the rules applying to a path
 * are the exact rules naming it and the tree rules at or above it. Checking
 * every rule path and one unnamed descendant of each therefore visits every
 * region, so a difference between the two precedences cannot be missed.
 */
maelys_mir_result_t
maelys_plan_find_conflict(const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t count, maelys_plan_conflict_t *out) {
  memset(out, 0, sizeof(*out));
  for (size_t i = 0; i < count; ++i) {
    if (conflict_at(rules, count, rules[i].path, out)) {
      out->witness = maelys_strdup(rules[i].path);
      return out->witness ? MAELYS_MIR_ERR_CONFLICT : MAELYS_MIR_ERR_MEMORY;
    }
    char *inside = descendant_witness(rules, count, rules[i].path);
    if (!inside)
      return MAELYS_MIR_ERR_MEMORY;
    if (conflict_at(rules, count, inside, out)) {
      out->witness = inside;
      return MAELYS_MIR_ERR_CONFLICT;
    }
    free(inside);
  }
  return MAELYS_MIR_OK;
}

/* Grants first, then every deny: a backend that applies rules in order and
 * lets the last match win reproduces the contract for deny, and additive
 * grants need no order at all. */
static int plan_rule_compare(const void *left, const void *right) {
  const maelys_sandbox_policy_resolved_rule_t *a = left, *b = right;
  int a_deny = a->access == MAELYS_MIR_FS_DENY;
  int b_deny = b->access == MAELYS_MIR_FS_DENY;
  if (a_deny != b_deny)
    return a_deny ? 1 : -1;
  return legacy_rule_compare(a, b);
}

const char *
maelys_sandbox_policy_permission_name(maelys_sandbox_policy_permission_t value) {
  switch (value) {
  case MAELYS_SANDBOX_POLICY_PERMISSION_NONE:
    return "none";
  case MAELYS_SANDBOX_POLICY_PERMISSION_READ:
    return "read";
  case MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE:
    return "read-write";
  }
  return "unknown";
}

const char *
maelys_sandbox_policy_reason_name(maelys_sandbox_policy_reason_t value) {
  switch (value) {
  case MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY:
    return "default-deny";
  case MAELYS_SANDBOX_POLICY_REASON_DENY_RULE:
    return "deny-rule";
  case MAELYS_SANDBOX_POLICY_REASON_WRITE_RULE:
    return "write-rule";
  case MAELYS_SANDBOX_POLICY_REASON_READ_RULE:
    return "read-rule";
  }
  return "unknown";
}

static const char *access_name(maelys_mir_fs_access_t access) {
  return access == MAELYS_MIR_FS_READ    ? "read"
         : access == MAELYS_MIR_FS_WRITE ? "write"
                                         : "deny";
}

static void describe_rule(const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t index, char *out, size_t size) {
  if (index == SIZE_MAX)
    (void)snprintf(out, size, "no rule");
  else
    (void)snprintf(out, size, "%s %s %s", access_name(rules[index].access),
                   rules[index].scope == MAELYS_MIR_SCOPE_TREE ? "tree" : "exact",
                   rules[index].path);
}

maelys_mir_result_t
maelys_sandbox_policy_plan_finalize(maelys_sandbox_policy_plan_t *plan,
                                    char **err) {
  maelys_plan_conflict_t conflict;
  maelys_mir_result_t result =
      maelys_plan_find_conflict(plan->rules, plan->rule_count, &conflict);
  if (result == MAELYS_MIR_ERR_CONFLICT) {
    char legacy[4200], contract[4200];
    describe_rule(plan->rules, conflict.legacy_rule, legacy, sizeof(legacy));
    describe_rule(plan->rules, conflict.contract_rule, contract,
                  sizeof(contract));
    maelys_set_error(
        err,
        "permission precedence conflict at %s: before=%s after=%s; "
        "most-specific-wins decided by [%s], deny-wins and additive grants "
        "by [%s]; rewrite the policy so both agree",
        conflict.witness, maelys_sandbox_policy_permission_name(conflict.before),
        maelys_sandbox_policy_permission_name(conflict.after), legacy, contract);
  }
  free(conflict.witness);
  if (result != MAELYS_MIR_OK)
    return result;
  if (plan->rule_count > 1u)
    qsort(plan->rules, plan->rule_count, sizeof(*plan->rules),
          plan_rule_compare);
  return MAELYS_MIR_OK;
}

maelys_mir_result_t maelys_sandbox_policy_plan_evaluate(
    const maelys_sandbox_policy_plan_t *plan, const char *absolute_path,
    maelys_sandbox_policy_evaluation_t *out, char **err) {
  if (!plan || !out) {
    maelys_set_error(err, "plan and evaluation output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  if (!maelys_plan_path_is_canonical(absolute_path)) {
    maelys_set_error(err, "evaluated path must be absolute, without empty, "
                          "'.' or '..' segments and without a trailing slash");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  maelys_plan_evaluate(plan->rules, plan->rule_count, absolute_path, out);
  return MAELYS_MIR_OK;
}
