/*
 * Measures the precedence-conflict search and a full plan compilation on
 * synthetic policies. Not part of `make check`: run `make bench`.
 * Times are CPU seconds of this process on the machine that runs it.
 */
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef maelys_mir_result_t (*search_t)(
    const maelys_sandbox_policy_resolved_rule_t *, size_t,
    maelys_plan_conflict_t *);

static double seconds(search_t search,
                      const maelys_sandbox_policy_resolved_rule_t *rules,
                      size_t count, maelys_mir_result_t expected) {
  maelys_plan_conflict_t conflict;
  clock_t start = clock();
  maelys_mir_result_t result = search(rules, count, &conflict);
  double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
  free(conflict.witness);
  if (result != expected) {
    fprintf(stderr, "unexpected result %s\n", maelys_mir_result_name(result));
    exit(1);
  }
  return elapsed;
}

static maelys_sandbox_policy_resolved_rule_t rule(maelys_mir_fs_access_t access,
                                                  maelys_mir_path_scope_t scope,
                                                  const char *path) {
  maelys_sandbox_policy_resolved_rule_t r = {
      access, scope, maelys_strdup(path), MAELYS_SANDBOX_POLICY_MISSING_ERROR};
  return r;
}

/* One shape of `count` rules; every shape but `conflict` has none, so the
 * whole policy is visited. */
static maelys_sandbox_policy_resolved_rule_t *shape(const char *name,
                                                    size_t count) {
  maelys_sandbox_policy_resolved_rule_t *rules = calloc(count, sizeof(*rules));
  char path[8192];
  rules[0] = rule(MAELYS_MIR_FS_READ, MAELYS_MIR_SCOPE_TREE, "/w");
  for (size_t i = 1; i < count; ++i) {
    if (strcmp(name, "siblings") == 0 || strcmp(name, "conflict") == 0) {
      (void)snprintf(path, sizeof(path), "/w/d%07zu", i);
      rules[i] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_TREE, path);
    } else if (strcmp(name, "witness-names") == 0) {
      /* every generated witness of /w collides with a rule */
      (void)snprintf(path, sizeof(path), "/w/maelys-witness-%zu", i - 1u);
      rules[i] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_EXACT, path);
    } else if (strcmp(name, "chains") == 0) {
      /* chains 200 deep of witness-like names: each rule spoils a witness
       * of the one above it */
      size_t used = (size_t)snprintf(path, sizeof(path), "/w/c%zu", i / 200u);
      for (size_t level = 0; level < i % 200u; ++level)
        used += (size_t)snprintf(path + used, sizeof(path) - used,
                                 "/maelys-witness-0");
      rules[i] = rule(MAELYS_MIR_FS_READ, MAELYS_MIR_SCOPE_TREE, path);
    } else { /* repeated: 64 rules per path, as overlapping roots give */
      (void)snprintf(path, sizeof(path), "/w/d%07zu", i / 64u);
      rules[i] = rule(MAELYS_MIR_FS_DENY,
                      i % 2u ? MAELYS_MIR_SCOPE_TREE : MAELYS_MIR_SCOPE_EXACT,
                      path);
    }
  }
  if (strcmp(name, "conflict-named") == 0 && count >= 4u) {
    /* A conflict below /w/hub, whose every witness number is a rule: the
     * report needs the first free one among count. */
    for (size_t i = 0; i < count; ++i) {
      free(rules[i].path);
      (void)snprintf(path, sizeof(path), "/w/hub/maelys-witness-%zu", i);
      rules[i] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_EXACT, path);
    }
    free(rules[0].path);
    free(rules[1].path);
    free(rules[2].path);
    rules[0] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_TREE, "/w");
    rules[1] = rule(MAELYS_MIR_FS_READ, MAELYS_MIR_SCOPE_TREE, "/w/hub");
    rules[2] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_EXACT, "/w/hub");
  }
  if (strcmp(name, "conflict") == 0) { /* found last, reported once */
    free(rules[count - 1u].path);
    (void)snprintf(path, sizeof(path), "/w/d%07zu/reopened", count - 2u);
    rules[count - 1u] = rule(MAELYS_MIR_FS_READ, MAELYS_MIR_SCOPE_TREE, path);
  }
  return rules;
}

static void bench_search(void) {
  static const char *const shapes[] = {"siblings",       "witness-names",
                                       "chains",         "repeated",
                                       "conflict",       "conflict-named"};
  static const size_t sizes[] = {4096u, 16384u, 65536u, 262144u};
  printf("%-14s %8s %12s %12s\n", "shape", "rules", "sorted (s)",
         "reference (s)");
  for (size_t s = 0; s < sizeof(shapes) / sizeof(shapes[0]); ++s) {
    for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); ++n) {
      size_t count = sizes[n];
      maelys_sandbox_policy_resolved_rule_t *rules = shape(shapes[s], count);
      maelys_mir_result_t expected = strncmp(shapes[s], "conflict", 8u) == 0
                                         ? MAELYS_MIR_ERR_CONFLICT
                                         : MAELYS_MIR_OK;
      double sorted = seconds(maelys_plan_find_conflict, rules, count, expected);
      printf("%-14s %8zu %12.3f", shapes[s], count, sorted);
      if (count <= 16384u)
        printf(" %12.3f\n",
               seconds(maelys_plan_find_conflict_reference, rules, count,
                       expected));
      else
        printf(" %12s\n", "not run");
      fflush(stdout);
      for (size_t i = 0; i < count; ++i)
        free(rules[i].path);
      free(rules);
    }
  }
}

/* Containment of two plans of `count` rules each: the candidate repeats the
 * boundary, so nothing exceeds and every region is visited. */
static void bench_containment(void) {
  static const char *const shapes[] = {"siblings", "chains"};
  static const size_t sizes[] = {4096u, 16384u, 262144u};
  printf("\n%-14s %8s %12s %12s\n", "containment", "rules", "pass (s)",
         "reference (s)");
  /* A candidate that exceeds below /w, where the boundary names every
   * witness number: the verdict needs the first free one among count. */
  for (size_t n = 0; n < 3u; ++n) {
    size_t count = sizes[n];
    maelys_sandbox_policy_resolved_rule_t *boundary =
        shape("witness-names", count);
    free(boundary[0].path);
    boundary[0] = rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_EXACT, "/w");
    maelys_sandbox_policy_resolved_rule_t candidate[] = {
        {MAELYS_MIR_FS_READ, MAELYS_MIR_SCOPE_TREE, (char *)"/w",
         MAELYS_SANDBOX_POLICY_MISSING_ERROR},
        {MAELYS_MIR_FS_DENY, MAELYS_MIR_SCOPE_EXACT, (char *)"/w",
         MAELYS_SANDBOX_POLICY_MISSING_ERROR}};
    char *witness = NULL;
    clock_t start = clock();
    maelys_mir_result_t result =
        maelys_plan_filesystem_excess(boundary, count, candidate, 2u, &witness);
    double pass = (double)(clock() - start) / CLOCKS_PER_SEC;
    if (result != MAELYS_MIR_OK || !witness)
      exit(1);
    printf("%-14s %8zu %12.3f %12s\n", "exceeds-named", count, pass, "not run");
    fflush(stdout);
    free(witness);
    for (size_t i = 0; i < count; ++i)
      free(boundary[i].path);
    free(boundary);
  }
  for (size_t s = 0; s < 2u; ++s) {
    for (size_t n = 0; n < 3u; ++n) {
      size_t count = sizes[n];
      maelys_sandbox_policy_resolved_rule_t *rules = shape(shapes[s], count);
      char *witness = NULL;
      clock_t start = clock();
      maelys_mir_result_t result =
          maelys_plan_filesystem_excess(rules, count, rules, count, &witness);
      double pass = (double)(clock() - start) / CLOCKS_PER_SEC;
      if (result != MAELYS_MIR_OK || witness)
        exit(1);
      printf("%-14s %8zu %12.3f", shapes[s], count, pass);
      if (count <= 4096u) {
        start = clock();
        result = maelys_plan_filesystem_excess_reference(rules, count, rules,
                                                         count, &witness);
        if (result != MAELYS_MIR_OK || witness)
          exit(1);
        printf(" %12.3f\n", (double)(clock() - start) / CLOCKS_PER_SEC);
      } else {
        printf(" %12s\n", "not run");
      }
      fflush(stdout);
      for (size_t i = 0; i < count; ++i)
        free(rules[i].path);
      free(rules);
    }
  }
}

/* The largest plan a MIR can resolve to: 4096 rules on minimal-runtime,
 * each kept under 64 host roots. */
static void bench_compile(void) {
  char base[64];
  (void)snprintf(base, sizeof(base), "/tmp/maelys-policy-bench-%ld",
                 (long)getpid());
  if (mkdir(base, 0700) != 0)
    exit(1);
  maelys_sandbox_policy_host_t *host = NULL;
  maelys_mir_builder_t *builder = NULL;
  maelys_mir_t *mir = NULL;
  maelys_sandbox_policy_plan_t *plan = NULL;
  char *error = NULL, path[256];
  int failed = maelys_sandbox_policy_host_create(&host, &error) != MAELYS_MIR_OK ||
               maelys_mir_builder_create(&builder, &error) != MAELYS_MIR_OK;
  for (unsigned i = 0; !failed && i < 64u; ++i) {
    (void)snprintf(path, sizeof(path), "%s/root%02u", base, i);
    failed = mkdir(path, 0700) != 0 ||
             maelys_sandbox_policy_host_add_minimal_runtime_root(
                 host, path, &error) != MAELYS_MIR_OK;
  }
  for (unsigned i = 0; !failed && i < MAELYS_MIR_MAX_RULES; ++i) {
    (void)snprintf(path, sizeof(path), "absent%04u", i);
    failed = maelys_mir_builder_add_fs_rule(
                 builder, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_MINIMAL_RUNTIME,
                 path, MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP,
                 &error) != MAELYS_MIR_OK;
  }
  failed = failed ||
           maelys_mir_builder_build(builder, &mir, &error) != MAELYS_MIR_OK;
  clock_t start = clock();
  failed = failed || maelys_sandbox_policy_compile(mir, host, UINT64_MAX, &plan,
                                                   &error) != MAELYS_MIR_OK;
  double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
  if (failed) {
    fprintf(stderr, "compile bench failed: %s\n", error ? error : "-");
    exit(1);
  }
  size_t bytes = 0;
  for (size_t i = 0; i < plan->rule_count; ++i)
    bytes += strlen(plan->rules[i].path) + 1u;
  printf("\ncompile: %u MIR rules x 64 minimal roots -> %zu plan rules in "
         "%.3f s; %zu path bytes, %zu rule bytes\n",
         MAELYS_MIR_MAX_RULES, plan->rule_count, elapsed, bytes,
         plan->rule_capacity * sizeof(*plan->rules));
  maelys_sandbox_policy_plan_destroy(plan);
  maelys_mir_destroy(mir);
  maelys_mir_builder_destroy(builder);
  maelys_sandbox_policy_host_destroy(host);
  for (unsigned i = 0; i < 64u; ++i) {
    (void)snprintf(path, sizeof(path), "%s/root%02u", base, i);
    (void)rmdir(path);
  }
  (void)rmdir(base);
}

int main(void) {
  bench_search();
  bench_containment();
  bench_compile();
  return 0;
}
