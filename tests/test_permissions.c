/*
 * The permission contract against its corpus, and the claim that the
 * conflict search between contract 1 and contract 2 visits every region.
 */
#include "internal.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);             \
      ++failures;                                                              \
    }                                                                          \
  } while (0)
#define FAIL_CASE(...)                                                         \
  do {                                                                         \
    fprintf(stderr, "FAIL %s:%zu: ", file, line_number);                       \
    fprintf(stderr, __VA_ARGS__);                                              \
    fputc('\n', stderr);                                                       \
    ++failures;                                                                \
  } while (0)

#define MAX_RULES 16u
#define MAX_QUERIES 16u
#define MAX_NODES 48u

typedef enum node_type { NODE_FILE = 1, NODE_DIRECTORY, NODE_ABSENT } node_type_t;

typedef struct node {
  char path[256];
  node_type_t type;
} node_t;

static int is_ancestor(const char *ancestor, const char *path) {
  size_t n = strlen(ancestor);
  if (strcmp(ancestor, path) == 0)
    return 0;
  return n == 1u || (strncmp(ancestor, path, n) == 0 && path[n] == '/');
}

static const node_t *find_node(const node_t *nodes, size_t count,
                               const char *path) {
  for (size_t i = 0; i < count; ++i)
    if (strcmp(nodes[i].path, path) == 0)
      return &nodes[i];
  return NULL;
}

typedef struct query {
  char path[256];
  maelys_sandbox_policy_permission_t permission;
  maelys_sandbox_policy_reason_t reason;
} query_t;

static int parse_permission(const char *text,
                            maelys_sandbox_policy_permission_t *out) {
  for (int value = 0; value <= 2; ++value) {
    if (strcmp(text, maelys_sandbox_policy_permission_name(
                         (maelys_sandbox_policy_permission_t)value)) == 0) {
      *out = (maelys_sandbox_policy_permission_t)value;
      return 1;
    }
  }
  return 0;
}

static int parse_reason(const char *text, maelys_sandbox_policy_reason_t *out) {
  for (int value = 1; value <= 4; ++value) {
    if (strcmp(text, maelys_sandbox_policy_reason_name(
                         (maelys_sandbox_policy_reason_t)value)) == 0) {
      *out = (maelys_sandbox_policy_reason_t)value;
      return 1;
    }
  }
  return 0;
}

static void check_queries(const char *file,
                          const maelys_sandbox_policy_resolved_rule_t *rules,
                          size_t rule_count, const query_t *queries,
                          size_t query_count, const char *order) {
  size_t line_number = 0;
  for (size_t i = 0; i < query_count; ++i) {
    maelys_sandbox_policy_evaluation_t got;
    maelys_plan_evaluate(rules, rule_count, queries[i].path, &got);
    if (got.permission != queries[i].permission ||
        got.reason != queries[i].reason)
      FAIL_CASE("%s order: %s gives %s (%s), expected %s (%s)", order,
                queries[i].path,
                maelys_sandbox_policy_permission_name(got.permission),
                maelys_sandbox_policy_reason_name(got.reason),
                maelys_sandbox_policy_permission_name(queries[i].permission),
                maelys_sandbox_policy_reason_name(queries[i].reason));
    if ((got.reason == MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY) !=
        (got.decisive_rule == SIZE_MAX))
      FAIL_CASE("%s order: %s has an inconsistent decisive rule", order,
                queries[i].path);
  }
}

static void run_case(const char *file) {
  FILE *stream = fopen(file, "r");
  size_t line_number = 0;
  if (!stream) {
    FAIL_CASE("cannot open");
    return;
  }
  maelys_sandbox_policy_plan_t *plan = calloc(1, sizeof(*plan));
  plan->rules = calloc(MAX_RULES, sizeof(*plan->rules));
  plan->rule_capacity = MAX_RULES;
  static query_t queries[MAX_QUERIES];
  size_t query_count = 0;
  static node_t nodes[MAX_NODES];
  size_t node_count = 0;
  int compile_seen = 0, refused = 0, requires_protection = 0;
  maelys_sandbox_policy_permission_t before = 0, after = 0;
  char line[512];
  while (fgets(line, sizeof(line), stream)) {
    ++line_number;
    char a[64], b[64], c[256], d[64];
    if (line[0] == '#' || line[0] == '\n')
      continue;
    if (sscanf(line, "rule %63s %63s %255s", a, b, c) == 3) {
      maelys_sandbox_policy_resolved_rule_t rule;
      rule.access = strcmp(a, "read") == 0    ? MAELYS_MIR_FS_READ
                    : strcmp(a, "write") == 0 ? MAELYS_MIR_FS_WRITE
                                              : MAELYS_MIR_FS_DENY;
      rule.scope = strcmp(b, "tree") == 0 ? MAELYS_MIR_SCOPE_TREE
                                          : MAELYS_MIR_SCOPE_EXACT;
      if ((rule.access == MAELYS_MIR_FS_DENY && strcmp(a, "deny") != 0) ||
          (rule.scope == MAELYS_MIR_SCOPE_EXACT && strcmp(b, "exact") != 0) ||
          !maelys_plan_path_is_canonical(c) || plan->rule_count == MAX_RULES) {
        FAIL_CASE("invalid rule");
        continue;
      }
      rule.missing = strstr(line, " protect-create")
                         ? MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE
                         : MAELYS_SANDBOX_POLICY_MISSING_ERROR;
      rule.path = maelys_strdup(c);
      plan->rules[plan->rule_count++] = rule;
    } else if (sscanf(line, "query %255s %63s %63s", c, a, b) == 3) {
      if (query_count == MAX_QUERIES || !maelys_plan_path_is_canonical(c) ||
          !parse_permission(a, &queries[query_count].permission) ||
          !parse_reason(b, &queries[query_count].reason)) {
        FAIL_CASE("invalid query");
        continue;
      }
      (void)snprintf(queries[query_count].path,
                     sizeof(queries[query_count].path), "%s", c);
      ++query_count;
    } else if (sscanf(line, "node %63s %255s", a, c) == 2) {
      node_type_t type = strcmp(a, "file") == 0        ? NODE_FILE
                         : strcmp(a, "directory") == 0 ? NODE_DIRECTORY
                         : strcmp(a, "absent") == 0    ? NODE_ABSENT
                                                       : 0;
      if (!type || node_count == MAX_NODES || !maelys_plan_path_is_canonical(c) ||
          find_node(nodes, node_count, c)) {
        FAIL_CASE("invalid or repeated node");
        continue;
      }
      (void)snprintf(nodes[node_count].path, sizeof(nodes[node_count].path),
                     "%s", c);
      nodes[node_count++].type = type;
    } else if (sscanf(line, "compile refused before=%63s after=%63s", a, d) ==
               2) {
      compile_seen = refused = 1;
      if (!parse_permission(a, &before) || !parse_permission(d, &after))
        FAIL_CASE("invalid compile expectation");
    } else if (sscanf(line, "requires %63s", a) == 1) {
      const char *name = maelys_sandbox_policy_capability_name(
          MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE);
      if (strcmp(a, name) != 0)
        FAIL_CASE("unknown capability %s", a);
      requires_protection = 1;
    } else if (strcmp(line, "compile accepted\n") == 0) {
      compile_seen = 1;
    } else {
      FAIL_CASE("unknown directive");
    }
  }
  fclose(stream);
  line_number = 0;
  if (!compile_seen || query_count == 0)
    FAIL_CASE("a case needs queries and one compile line");

  /* Every path a rule or a query names says what it is on the host, and the
   * declarations describe one possible tree. */
  for (size_t i = 0; i < plan->rule_count; ++i) {
    const node_t *node = find_node(nodes, node_count, plan->rules[i].path);
    int protect = plan->rules[i].missing ==
                  MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE;
    if (!node)
      FAIL_CASE("no node line for the rule path %s", plan->rules[i].path);
    else if (protect != (node->type == NODE_ABSENT))
      FAIL_CASE("%s: a rule target is absent exactly when it is protect-create",
                node->path);
  }
  for (size_t i = 0; i < query_count; ++i)
    if (!find_node(nodes, node_count, queries[i].path))
      FAIL_CASE("no node line for the query path %s", queries[i].path);
  for (size_t i = 0; i < node_count; ++i) {
    for (size_t j = 0; j < node_count; ++j) {
      if (!is_ancestor(nodes[i].path, nodes[j].path))
        continue;
      if (nodes[i].type == NODE_FILE)
        FAIL_CASE("%s lies beneath the file %s", nodes[j].path, nodes[i].path);
      if (nodes[i].type == NODE_ABSENT && nodes[j].type != NODE_ABSENT)
        FAIL_CASE("%s exists beneath the absent %s", nodes[j].path,
                  nodes[i].path);
    }
  }

  /* A plan requires the protection exactly when a rule carries it. */
  int carries_protection = 0;
  for (size_t i = 0; i < plan->rule_count; ++i) {
    if (plan->rules[i].missing == MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE) {
      carries_protection = 1;
      if (plan->rules[i].access != MAELYS_MIR_FS_DENY)
        FAIL_CASE("protect-create on a rule that is not a deny");
    }
  }
  if (carries_protection != requires_protection)
    FAIL_CASE("the requires line and the protect-create rules disagree");

  /* The contract holds for every order of the rules. */
  check_queries(file, plan->rules, plan->rule_count, queries, query_count,
                "written");
  for (size_t i = 0; i < plan->rule_count / 2u; ++i) {
    maelys_sandbox_policy_resolved_rule_t swap = plan->rules[i];
    plan->rules[i] = plan->rules[plan->rule_count - 1u - i];
    plan->rules[plan->rule_count - 1u - i] = swap;
  }
  check_queries(file, plan->rules, plan->rule_count, queries, query_count,
                "reversed");

  maelys_plan_conflict_t conflict;
  maelys_mir_result_t found =
      maelys_plan_find_conflict(plan->rules, plan->rule_count, &conflict);
  char *error = NULL;
  maelys_mir_result_t finalized =
      maelys_sandbox_policy_plan_finalize(plan, &error);
  if (refused) {
    if (found != MAELYS_MIR_ERR_CONFLICT || finalized != MAELYS_MIR_ERR_CONFLICT)
      FAIL_CASE("expected a precedence conflict");
    else if (conflict.before != before || conflict.after != after)
      FAIL_CASE("conflict at %s is before=%s after=%s", conflict.witness,
                maelys_sandbox_policy_permission_name(conflict.before),
                maelys_sandbox_policy_permission_name(conflict.after));
    else if (!error || !strstr(error, "permission precedence conflict at /") ||
             !strstr(error, conflict.witness))
      FAIL_CASE("the diagnostic does not name the witness path");
  } else {
    if (found != MAELYS_MIR_OK || finalized != MAELYS_MIR_OK)
      FAIL_CASE("unexpected refusal: %s", error ? error : "no diagnostic");
    check_queries(file, plan->rules, plan->rule_count, queries, query_count,
                  "plan");
    /* Plan order: every grant, then every deny. */
    int deny_seen = 0;
    for (size_t i = 0; i < plan->rule_count; ++i) {
      if (plan->rules[i].access == MAELYS_MIR_FS_DENY)
        deny_seen = 1;
      else if (deny_seen)
        FAIL_CASE("a grant follows a deny in plan order");
    }
  }
  free(conflict.witness);
  maelys_mir_error_free(error);
  maelys_sandbox_policy_plan_destroy(plan);
}

static int by_name(const void *left, const void *right) {
  return strcmp(*(char *const *)left, *(char *const *)right);
}

static void test_corpus(const char *directory) {
  DIR *handle = opendir(directory);
  CHECK(handle != NULL);
  if (!handle)
    return;
  char *files[128];
  size_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(handle)) && count < 128u) {
    size_t n = strlen(entry->d_name);
    if (n < 6u || strcmp(entry->d_name + n - 5u, ".case") != 0)
      continue;
    size_t size = strlen(directory) + n + 2u;
    files[count] = malloc(size);
    (void)snprintf(files[count], size, "%s/%s", directory, entry->d_name);
    ++count;
  }
  closedir(handle);
  qsort(files, count, sizeof(*files), by_name);
  CHECK(count >= 20u);
  for (size_t i = 0; i < count; ++i) {
    run_case(files[i]);
    free(files[i]);
  }
}

/* ---- exhaustive cross-check of the conflict search ------------------------ */

static uint32_t random_state = 0x9e3779b9u;
static uint32_t next_random(void) {
  random_state ^= random_state << 13;
  random_state ^= random_state >> 17;
  random_state ^= random_state << 5;
  return random_state;
}

/* Most specific wins, written independently of src/permissions.c: longest
 * path, then exact over tree, then deny over write over read. */
static maelys_sandbox_policy_permission_t
most_specific(const maelys_sandbox_policy_resolved_rule_t *rules, size_t count,
              const char *path) {
  int best = -1;
  for (size_t i = 0; i < count; ++i) {
    if (!maelys_plan_rule_applies(&rules[i], path))
      continue;
    if (best < 0) {
      best = (int)i;
      continue;
    }
    const maelys_sandbox_policy_resolved_rule_t *a = &rules[best], *b = &rules[i];
    size_t an = strlen(a->path), bn = strlen(b->path);
    int later = bn != an ? bn > an
                : a->scope != b->scope ? b->scope == MAELYS_MIR_SCOPE_EXACT
                                       : b->access > a->access;
    if (later)
      best = (int)i;
  }
  if (best < 0 || rules[best].access == MAELYS_MIR_FS_DENY)
    return MAELYS_SANDBOX_POLICY_PERMISSION_NONE;
  return rules[best].access == MAELYS_MIR_FS_WRITE
             ? MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE
             : MAELYS_SANDBOX_POLICY_PERMISSION_READ;
}

/* Every path of depth 0..4 over three segment names, as rule paths use two
 * of them and depth 3 at most: each region has a path here. */
static int differs_somewhere(const maelys_sandbox_policy_resolved_rule_t *rules,
                             size_t count) {
  static const char *const names[] = {"a", "b", "c"};
  for (unsigned depth = 0; depth <= 4u; ++depth) {
    unsigned total = 1;
    for (unsigned i = 0; i < depth; ++i)
      total *= 3u;
    for (unsigned index = 0; index < total; ++index) {
      char path[32] = "/";
      size_t used = depth ? 0u : 1u;
      unsigned rest = index;
      for (unsigned i = 0; i < depth; ++i, rest /= 3u)
        used += (size_t)snprintf(path + used, sizeof(path) - used, "/%s",
                                 names[rest % 3u]);
      maelys_sandbox_policy_evaluation_t contract;
      maelys_plan_evaluate(rules, count, path, &contract);
      if (contract.permission != most_specific(rules, count, path))
        return 1;
    }
  }
  return 0;
}

static void test_conflict_search_is_complete(void) {
  static const char *const paths[] = {"/",      "/a",     "/b",     "/a/a",
                                      "/a/b",   "/b/a",   "/a/a/a", "/a/a/b",
                                      "/a/b/a", "/b/a/b"};
  unsigned conflicts = 0, agreements = 0;
  for (unsigned round = 0; round < 20000u; ++round) {
    maelys_sandbox_policy_resolved_rule_t rules[5];
    size_t count = 1u + next_random() % 5u;
    for (size_t i = 0; i < count; ++i) {
      rules[i].access = (maelys_mir_fs_access_t)(1u + next_random() % 3u);
      rules[i].scope = (maelys_mir_path_scope_t)(1u + next_random() % 2u);
      rules[i].path = (char *)paths[next_random() % 10u];
      rules[i].missing = MAELYS_SANDBOX_POLICY_MISSING_ERROR;
    }
    maelys_plan_conflict_t conflict;
    maelys_mir_result_t found = maelys_plan_find_conflict(rules, count, &conflict);
    int expected = differs_somewhere(rules, count);
    CHECK((found == MAELYS_MIR_ERR_CONFLICT) == expected);
    CHECK(found == MAELYS_MIR_OK || found == MAELYS_MIR_ERR_CONFLICT);
    if (found == MAELYS_MIR_ERR_CONFLICT) {
      maelys_sandbox_policy_evaluation_t contract;
      maelys_plan_evaluate(rules, count, conflict.witness, &contract);
      CHECK(contract.permission == conflict.after);
      CHECK(most_specific(rules, count, conflict.witness) == conflict.before);
      CHECK(conflict.before != conflict.after);
      ++conflicts;
    } else {
      ++agreements;
    }
    free(conflict.witness);
    if (failures)
      return;
  }
  CHECK(conflicts > 1000u && agreements > 1000u);
}

/* The sorted search must answer exactly as the definition: same verdict,
 * same witness, same permissions, same deciding rules. The universe mixes
 * the root, names that byte order would misplace ("/a-", "/a.b" against
 * "/a/b"), witness-like names that collide with generated witnesses, and
 * repeated paths. */
static void test_search_matches_reference(void) {
  static const char *const paths[] = {
      "/",       "/a",       "/a-",      "/a.b",   "/a/b",    "/a/b/c",
      "/a/b-",   "/a/-",     "/ab",      "/b",     "/b/a",    "/b/a/a",
      "/a/maelys-witness-0", "/a/maelys-witness-1", "/maelys-witness-0",
      "/a/maelys-witness-0/x", "/a/b/c/d/e", "/b/a/a/a"};
  const size_t path_count = sizeof(paths) / sizeof(paths[0]);
  unsigned conflicts = 0, agreements = 0;
  for (unsigned round = 0; round < 60000u; ++round) {
    maelys_sandbox_policy_resolved_rule_t rules[12];
    size_t count = next_random() % 13u;
    for (size_t i = 0; i < count; ++i) {
      rules[i].access = (maelys_mir_fs_access_t)(1u + next_random() % 3u);
      rules[i].scope = (maelys_mir_path_scope_t)(1u + next_random() % 2u);
      rules[i].path = (char *)paths[next_random() % path_count];
      rules[i].missing = MAELYS_SANDBOX_POLICY_MISSING_ERROR;
    }
    maelys_plan_conflict_t fast, reference;
    maelys_mir_result_t got = maelys_plan_find_conflict(rules, count, &fast);
    maelys_mir_result_t expected =
        maelys_plan_find_conflict_reference(rules, count, &reference);
    int same = got == expected && fast.before == reference.before &&
               fast.after == reference.after &&
               fast.legacy_rule == reference.legacy_rule &&
               fast.contract_rule == reference.contract_rule &&
               (fast.witness == NULL) == (reference.witness == NULL) &&
               (!fast.witness || strcmp(fast.witness, reference.witness) == 0);
    if (!same) {
      fprintf(stderr, "FAIL %s: round %u: sorted search %s at %s, reference %s at %s\n",
              __FILE__, round, maelys_mir_result_name(got),
              fast.witness ? fast.witness : "-",
              maelys_mir_result_name(expected),
              reference.witness ? reference.witness : "-");
      ++failures;
    }
    if (expected == MAELYS_MIR_ERR_CONFLICT)
      ++conflicts;
    else
      ++agreements;
    free(fast.witness);
    free(reference.witness);
    if (failures)
      return;
  }
  CHECK(conflicts > 5000u && agreements > 5000u);
}

/* ---- containment ------------------------------------------------------------ */

/*
 * An evaluator of the contract written for these tests alone. It shares no
 * code with maelys_plan_evaluate() nor maelys_plan_rule_applies(): it cuts
 * paths into components and compares component lists, where the library
 * compares string prefixes. An error common to the library's evaluator and
 * its searches is therefore visible here.
 */
static size_t split_components(const char *path, const char *parts[],
                               size_t lengths[], size_t capacity) {
  size_t count = 0;
  for (const char *cursor = path; *cursor;) {
    while (*cursor == '/')
      ++cursor;
    if (!*cursor)
      break;
    const char *end = cursor;
    while (*end && *end != '/')
      ++end;
    if (count < capacity) {
      parts[count] = cursor;
      lengths[count] = (size_t)(end - cursor);
    }
    ++count;
    cursor = end;
  }
  return count;
}

static int independent_permission(
    const maelys_sandbox_policy_resolved_rule_t *rules, size_t count,
    const char *path) {
  const char *target[64], *named[64];
  size_t target_length[64], named_length[64];
  size_t target_count = split_components(path, target, target_length, 64u);
  int denied = 0, written = 0, read = 0;
  for (size_t i = 0; i < count; ++i) {
    size_t named_count =
        split_components(rules[i].path, named, named_length, 64u);
    if (named_count > target_count)
      continue;
    if (named_count < target_count && rules[i].scope != MAELYS_MIR_SCOPE_TREE)
      continue;
    int prefix = 1;
    for (size_t c = 0; prefix && c < named_count; ++c)
      prefix = named_length[c] == target_length[c] &&
               memcmp(named[c], target[c], named_length[c]) == 0;
    if (!prefix)
      continue;
    if (rules[i].access == MAELYS_MIR_FS_DENY)
      denied = 1;
    else if (rules[i].access == MAELYS_MIR_FS_WRITE)
      written = 1;
    else
      read = 1;
  }
  return denied ? 0 : written ? 2 : read ? 1 : 0;
}

static void random_rules(maelys_sandbox_policy_resolved_rule_t *rules,
                         size_t count, const char *const *paths,
                         size_t path_count) {
  for (size_t i = 0; i < count; ++i) {
    rules[i].access = (maelys_mir_fs_access_t)(1u + next_random() % 3u);
    rules[i].scope = (maelys_mir_path_scope_t)(1u + next_random() % 2u);
    rules[i].path = (char *)paths[next_random() % path_count];
    rules[i].missing = MAELYS_SANDBOX_POLICY_MISSING_ERROR;
  }
}

/* Rule paths use two names and three levels; the universe below holds every
 * path of up to four levels over three names, so each region of each pair of
 * policies has a path in it and the answer can be checked exhaustively. */
static void test_containment_is_exact(void) {
  static const char *const paths[] = {"/",      "/a",     "/b",     "/a/a",
                                      "/a/b",   "/b/a",   "/a/a/a", "/a/a/b",
                                      "/a/b/a", "/b/a/b"};
  static const char *const names[] = {"a", "b", "c"};
  unsigned contained = 0, exceeded = 0;
  for (unsigned round = 0; round < 30000u; ++round) {
    maelys_sandbox_policy_resolved_rule_t boundary[5], candidate[5];
    size_t n = next_random() % 6u, m = next_random() % 6u;
    random_rules(boundary, n, paths, 10u);
    random_rules(candidate, m, paths, 10u);
    int expected = 1;
    for (unsigned depth = 0; expected && depth <= 4u; ++depth) {
      unsigned total = 1;
      for (unsigned i = 0; i < depth; ++i)
        total *= 3u;
      for (unsigned index = 0; expected && index < total; ++index) {
        char path[32] = "/";
        size_t used = depth ? 0u : 1u;
        unsigned rest = index;
        for (unsigned i = 0; i < depth; ++i, rest /= 3u)
          used += (size_t)snprintf(path + used, sizeof(path) - used, "/%s",
                                   names[rest % 3u]);
        expected = independent_permission(candidate, m, path) <=
                   independent_permission(boundary, n, path);
      }
    }
    char *witness = NULL, *reference = NULL;
    CHECK(maelys_plan_filesystem_excess(boundary, n, candidate, m, &witness) ==
          MAELYS_MIR_OK);
    CHECK(maelys_plan_filesystem_excess_reference(boundary, n, candidate, m,
                                                  &reference) == MAELYS_MIR_OK);
    if ((witness == NULL) != expected) {
      fprintf(stderr, "FAIL %s: round %u: containment is %s, the search says %s\n",
              __FILE__, round, expected ? "true" : "false",
              witness ? witness : "contained");
      ++failures;
    }
    /* A witness is a real excess, by the independent evaluator. */
    if (witness)
      CHECK(independent_permission(candidate, m, witness) >
            independent_permission(boundary, n, witness));
    CHECK((witness == NULL) == (reference == NULL));
    if (witness && reference)
      CHECK(strcmp(witness, reference) == 0);
    if (expected)
      ++contained;
    else
      ++exceeded;
    free(witness);
    free(reference);
    if (failures)
      return;
  }
  CHECK(contained > 2000u && exceeded > 2000u);
}

/* The pass and the definition agree on names a byte-order sort misplaces,
 * on witness-like names and on repeated paths, witness included. */
static void test_containment_matches_reference(void) {
  static const char *const paths[] = {
      "/",       "/a",       "/a-",      "/a.b",   "/a/b",    "/a/b/c",
      "/a/b-",   "/a/-",     "/ab",      "/b",     "/b/a",    "/b/a/a",
      "/a/maelys-witness-0", "/a/maelys-witness-1", "/maelys-witness-0",
      "/a/maelys-witness-0/x", "/a/b/c/d/e", "/b/a/a/a"};
  const size_t path_count = sizeof(paths) / sizeof(paths[0]);
  unsigned exceeded = 0;
  for (unsigned round = 0; round < 60000u; ++round) {
    maelys_sandbox_policy_resolved_rule_t boundary[8], candidate[8];
    size_t n = next_random() % 9u, m = next_random() % 9u;
    random_rules(boundary, n, paths, path_count);
    random_rules(candidate, m, paths, path_count);
    char *witness = NULL, *reference = NULL;
    CHECK(maelys_plan_filesystem_excess(boundary, n, candidate, m, &witness) ==
          MAELYS_MIR_OK);
    CHECK(maelys_plan_filesystem_excess_reference(boundary, n, candidate, m,
                                                  &reference) == MAELYS_MIR_OK);
    if ((witness == NULL) != (reference == NULL) ||
        (witness && strcmp(witness, reference) != 0)) {
      fprintf(stderr, "FAIL %s: round %u: pass says %s, definition says %s\n",
              __FILE__, round, witness ? witness : "contained",
              reference ? reference : "contained");
      ++failures;
    }
    if (witness) {
      CHECK(independent_permission(candidate, m, witness) >
            independent_permission(boundary, n, witness));
      ++exceeded;
    }
    free(witness);
    free(reference);
    if (failures)
      return;
  }
  CHECK(exceeded > 5000u);
  /* A plan contains itself, and nothing exceeds an empty candidate. */
  maelys_sandbox_policy_resolved_rule_t rules[6];
  random_rules(rules, 6u, paths, path_count);
  char *witness = NULL;
  CHECK(maelys_plan_filesystem_excess(rules, 6u, rules, 6u, &witness) ==
            MAELYS_MIR_OK &&
        witness == NULL);
  CHECK(maelys_plan_filesystem_excess(rules, 6u, NULL, 0u, &witness) ==
            MAELYS_MIR_OK &&
        witness == NULL);
  CHECK(maelys_plan_filesystem_excess(NULL, 0u, NULL, 0u, &witness) ==
            MAELYS_MIR_OK &&
        witness == NULL);
}

static void test_evaluate_arguments(void) {
  maelys_sandbox_policy_plan_t *plan = calloc(1, sizeof(*plan));
  maelys_sandbox_policy_evaluation_t out;
  static const char *const invalid[] = {"",      "relative", "/a/",  "/a//b",
                                        "/a/./b", "/a/../b",  "/..",  "//"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    char *error = NULL;
    CHECK(maelys_sandbox_policy_plan_evaluate(plan, invalid[i], &out, &error) ==
          MAELYS_MIR_ERR_ARGUMENT);
    CHECK(error != NULL);
    maelys_mir_error_free(error);
  }
  CHECK(maelys_sandbox_policy_plan_evaluate(plan, NULL, &out, NULL) ==
        MAELYS_MIR_ERR_ARGUMENT);
  CHECK(maelys_sandbox_policy_plan_evaluate(NULL, "/", &out, NULL) ==
        MAELYS_MIR_ERR_ARGUMENT);
  CHECK(maelys_sandbox_policy_plan_evaluate(plan, "/", &out, NULL) ==
        MAELYS_MIR_OK);
  CHECK(out.permission == MAELYS_SANDBOX_POLICY_PERMISSION_NONE &&
        out.reason == MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY &&
        out.decisive_rule == SIZE_MAX && out.applicable_rule_count == 0u);
  maelys_sandbox_policy_plan_destroy(plan);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: test_permissions CORPUS_CASES_DIRECTORY\n");
    return 2;
  }
  test_corpus(argv[1]);
  test_conflict_search_is_complete();
  test_search_matches_reference();
  test_containment_is_exact();
  test_containment_matches_reference();
  test_evaluate_arguments();
  if (failures)
    fprintf(stderr, "%d permission test failures\n", failures);
  return failures ? 1 : 0;
}
