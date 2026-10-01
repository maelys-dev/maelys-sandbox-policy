#include <maelys/sandbox_policy.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);             \
      ++failures;                                                              \
    }                                                                          \
  } while (0)
#define CHECK_OK(x)                                                            \
  do {                                                                         \
    maelys_mir_result_t check_result = (x);                                    \
    if (check_result != MAELYS_MIR_OK) {                                       \
      fprintf(stderr, "FAIL %s:%d: %s => %s\n", __FILE__, __LINE__, #x,        \
              maelys_mir_result_name(check_result));                           \
      ++failures;                                                              \
    }                                                                          \
  } while (0)
static const maelys_sandbox_policy_capabilities_t all_caps =
    MAELYS_SANDBOX_POLICY_CAP_FS_READ | MAELYS_SANDBOX_POLICY_CAP_FS_WRITE |
    MAELYS_SANDBOX_POLICY_CAP_FS_DENY | MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE |
    MAELYS_SANDBOX_POLICY_CAP_NETWORK_DIRECT | MAELYS_SANDBOX_POLICY_CAP_NETWORK_MEDIATED |
    MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE |
    MAELYS_SANDBOX_POLICY_CAP_ROOT_EPHEMERAL_WRITE;

static int make_temp_dir(char *path) {
  int fd = mkstemp(path);
  if (fd < 0)
    return 0;
  if (close(fd) != 0 || unlink(path) != 0)
    return 0;
  return mkdir(path, 0700) == 0;
}

static maelys_mir_t *policy(void) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_set_root_mode(
      b, MAELYS_MIR_ROOT_EPHEMERAL_WRITE, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "build",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, "build/secret",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_MINIMAL_RUNTIME, "",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return m;
}

static void test_compile(void) {
  char root[] = "/tmp/maelys-sandbox-policy-test-XXXXXX";
  CHECK(make_temp_dir(root));
  char build[512], secret[512];
  CHECK(snprintf(build, sizeof(build), "%s/build", root) > 0);
  CHECK(snprintf(secret, sizeof(secret), "%s/secret", build) > 0);
  CHECK(mkdir(build, 0700) == 0);
  CHECK(mkdir(secret, 0700) == 0);
  maelys_sandbox_policy_host_t *h = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_temp(h, "/tmp", &e));
  CHECK_OK(maelys_sandbox_policy_host_add_minimal_runtime_root(h, "/usr", &e));
  maelys_mir_t *m = policy();
  CHECK(maelys_sandbox_policy_check_support(m, MAELYS_SANDBOX_POLICY_CAP_FS_READ, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_error_free(e);
  e = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_root_mode(p) ==
        MAELYS_MIR_ROOT_EPHEMERAL_WRITE);
  CHECK(maelys_sandbox_policy_plan_rule_count(p) == 4);
  CHECK(strlen(maelys_sandbox_policy_plan_mir_digest(p)) == 64);
  maelys_sandbox_policy_resolved_rule_view_t last;
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, maelys_sandbox_policy_plan_rule_count(p) - 1,
                                       &last));
  CHECK(last.access == MAELYS_MIR_FS_DENY);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  maelys_sandbox_policy_host_destroy(h);
  CHECK(rmdir(secret) == 0);
  CHECK(rmdir(build) == 0);
  CHECK(rmdir(root) == 0);
  maelys_mir_error_free(e);
}

static void test_symlink_escape(void) {
  char root[] = "/tmp/maelys-sandbox-policy-link-XXXXXX";
  CHECK(make_temp_dir(root));
  char linkpath[512];
  CHECK(snprintf(linkpath, sizeof(linkpath), "%s/out", root) > 0);
  CHECK(symlink("/usr", linkpath) == 0);
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  maelys_sandbox_policy_host_t *h = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "out",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  maelys_sandbox_policy_host_destroy(h);
  maelys_mir_destroy(m);
  maelys_mir_builder_destroy(b);
  CHECK(unlink(linkpath) == 0);
  CHECK(rmdir(root) == 0);
}

static void test_mediated_network(void) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  maelys_sandbox_policy_host_t *h = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_set_network(b, MAELYS_MIR_NETWORK_MEDIATED, &e));
  CHECK_OK(maelys_mir_builder_add_network_destination(
      b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "github.com", 443u, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK(maelys_sandbox_policy_host_set_network_mediator(h, "bad mediator", &e) ==
        MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_set_network_mediator(h, "local-proxy", &e));
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_network(p) == MAELYS_MIR_NETWORK_MEDIATED);
  CHECK(strcmp(maelys_sandbox_policy_plan_network_mediator(p), "local-proxy") == 0);
  CHECK(maelys_sandbox_policy_plan_network_destination_count(p) == 1u);
  maelys_mir_network_destination_view_t destination;
  CHECK_OK(maelys_sandbox_policy_plan_network_destination_at(p, 0, &destination));
  CHECK(strcmp(destination.host, "github.com") == 0);
  CHECK(destination.port == 443u);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_sandbox_policy_host_destroy(h);
  maelys_mir_destroy(m);
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
}

static void test_destination_flags_require_capabilities(void) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  maelys_sandbox_policy_host_t *h = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  const maelys_sandbox_policy_capabilities_t flag_caps =
      MAELYS_SANDBOX_POLICY_CAP_NETWORK_REQUIRE_TLS_SNI |
      MAELYS_SANDBOX_POLICY_CAP_NETWORK_PRIVATE_ADDRESSES;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_set_network(b, MAELYS_MIR_NETWORK_MEDIATED, &e));
  CHECK_OK(maelys_mir_builder_add_network_destination_ex(
      b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "github.com", 443u,
      MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI, &e));
  CHECK_OK(maelys_mir_builder_add_network_destination_ex(
      b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "registry.internal", 5000u,
      MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  CHECK((maelys_sandbox_policy_required_capabilities(m) & flag_caps) ==
        flag_caps);
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_network_mediator(h, "egress", &e));
  CHECK(maelys_sandbox_policy_compile(
            m, h, all_caps | MAELYS_SANDBOX_POLICY_CAP_NETWORK_PRIVATE_ADDRESSES,
            &p, &e) == MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(e && strstr(e, "network-require-tls-sni") != NULL);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK(maelys_sandbox_policy_compile(
            m, h, all_caps | MAELYS_SANDBOX_POLICY_CAP_NETWORK_REQUIRE_TLS_SNI,
            &p, &e) == MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps | flag_caps, &p, &e));
  maelys_mir_network_destination_view_t legacy;
  CHECK(maelys_sandbox_policy_plan_network_destination_at(p, 0, &legacy) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_network_destination_ex_view_t d;
  CHECK_OK(maelys_sandbox_policy_plan_network_destination_at_ex(p, 0, &d));
  CHECK(strcmp(d.host, "github.com") == 0 &&
        d.flags == MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI);
  CHECK_OK(maelys_sandbox_policy_plan_network_destination_at_ex(p, 1, &d));
  CHECK(strcmp(d.host, "registry.internal") == 0 && d.port == 5000u &&
        d.flags == MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_sandbox_policy_host_destroy(h);
  maelys_mir_destroy(m);
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
}

static maelys_mir_t *two_rules(maelys_mir_fs_access_t first_access,
                               maelys_mir_path_root_t first_root,
                               const char *first,
                               maelys_mir_fs_access_t second_access,
                               maelys_mir_path_root_t second_root,
                               const char *second) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(b, first_access, first_root, first,
                                          MAELYS_MIR_SCOPE_TREE,
                                          MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(b, second_access, second_root, second,
                                          MAELYS_MIR_SCOPE_TREE,
                                          MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_set_root_mode(b, MAELYS_MIR_ROOT_EPHEMERAL_WRITE,
                                            &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return m;
}

static void expect_conflict(maelys_mir_t *m,
                            const maelys_sandbox_policy_host_t *h,
                            const char *before_after) {
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_CONFLICT);
  CHECK(p == NULL);
  CHECK(e && strstr(e, "permission precedence conflict at /") != NULL);
  CHECK(e && strstr(e, before_after) != NULL);
  maelys_mir_error_free(e);
  maelys_mir_destroy(m);
}

static void test_permission_contract(void) {
  char root[] = "/tmp/maelys-sandbox-policy-contract-XXXXXX";
  CHECK(make_temp_dir(root));
  char private_dir[512], public_dir[512], temp_dir[512], link[512], src[512];
  CHECK(snprintf(private_dir, sizeof(private_dir), "%s/private", root) > 0);
  CHECK(snprintf(public_dir, sizeof(public_dir), "%s/public", private_dir) > 0);
  CHECK(snprintf(temp_dir, sizeof(temp_dir), "%s/tmp", private_dir) > 0);
  CHECK(snprintf(src, sizeof(src), "%s/src", root) > 0);
  CHECK(snprintf(link, sizeof(link), "%s/alias", src) > 0);
  CHECK(mkdir(private_dir, 0700) == 0 && mkdir(public_dir, 0700) == 0 &&
        mkdir(temp_dir, 0700) == 0 && mkdir(src, 0700) == 0);
  maelys_sandbox_policy_host_t *h = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_temp(h, temp_dir, &e));

  /* A grant under a denied tree, and a read under a written tree, meant
   * something else before: both are refused, and no plan is returned. */
  expect_conflict(two_rules(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                            "private", MAELYS_MIR_FS_READ,
                            MAELYS_MIR_ROOT_WORKSPACE, "private/public"),
                  h, "before=read after=none");
  expect_conflict(two_rules(MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "",
                            MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE,
                            "src"),
                  h, "before=read after=read-write");
  /* The overlap may only show once roots are resolved: the temp root lies
   * inside the denied tree of the workspace. */
  expect_conflict(two_rules(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                            "private", MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_TEMP,
                            ""),
                  h, "before=read-write after=none");
  /* ...or once a link is resolved: the host rule names an alias of it. */
  CHECK(symlink(public_dir, link) == 0);
  expect_conflict(two_rules(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                            "private", MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_HOST,
                            link),
                  h, "before=read after=none");

  /* An accepted plan: grants first, denies last, evaluated by the contract.
   * The ephemeral-write root grants nothing by itself. */
  maelys_mir_t *m = two_rules(MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "",
                              MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                              "private");
  maelys_sandbox_policy_plan_t *p = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_root_mode(p) ==
        MAELYS_MIR_ROOT_EPHEMERAL_WRITE);
  maelys_sandbox_policy_resolved_rule_view_t rule;
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 0, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_WRITE);
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 1, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_DENY);
  char *resolved_root = realpath(root, NULL);
  char path[600];
  maelys_sandbox_policy_evaluation_t evaluation;
  CHECK(snprintf(path, sizeof(path), "%s/src/main.c", resolved_root) > 0);
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, path, &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE &&
        evaluation.reason == MAELYS_SANDBOX_POLICY_REASON_WRITE_RULE &&
        evaluation.decisive_rule == 0u);
  CHECK(snprintf(path, sizeof(path), "%s/private/public/a", resolved_root) > 0);
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, path, &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_NONE &&
        evaluation.reason == MAELYS_SANDBOX_POLICY_REASON_DENY_RULE &&
        evaluation.decisive_rule == 1u && evaluation.applicable_rule_count == 2u);
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, "/etc/hosts", &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_NONE &&
        evaluation.reason == MAELYS_SANDBOX_POLICY_REASON_DEFAULT_DENY);
  free(resolved_root);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  maelys_sandbox_policy_host_destroy(h);
  maelys_mir_error_free(e);
  CHECK(unlink(link) == 0);
  CHECK(rmdir(src) == 0 && rmdir(temp_dir) == 0 && rmdir(public_dir) == 0 &&
        rmdir(private_dir) == 0 && rmdir(root) == 0);
}

static maelys_mir_t *missing_policy(const char *relative) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, relative,
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return m;
}

static void test_missing_is_not_io_failure(void) {
  char root[] = "/tmp/maelys-sandbox-policy-missing-XXXXXX";
  CHECK(make_temp_dir(root));
  maelys_sandbox_policy_host_t *h = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));

  /* An absent deny used to vanish from the plan. It is kept, and a backend
   * that cannot protect its creation gets no plan at all. */
  maelys_mir_t *m = missing_policy("absent");
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(p == NULL);
  CHECK(e && strstr(e, "fs-protect-create") != NULL);
  maelys_mir_error_free(e);
  e = NULL;
  maelys_mir_destroy(m);

  char loop[512];
  CHECK(snprintf(loop, sizeof(loop), "%s/loop", root) > 0);
  CHECK(symlink("loop", loop) == 0);
  m = missing_policy("loop");
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) == MAELYS_MIR_ERR_IO);
  CHECK(p == NULL);
  CHECK(e != NULL);
  maelys_mir_error_free(e);
  maelys_mir_destroy(m);
  maelys_sandbox_policy_host_destroy(h);
  CHECK(unlink(loop) == 0);
  CHECK(rmdir(root) == 0);
}

static maelys_mir_t *one_rule(maelys_mir_fs_access_t access,
                              maelys_mir_path_root_t root, const char *relative,
                              maelys_mir_missing_path_t missing) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(b, access, root, relative,
                                          MAELYS_MIR_SCOPE_TREE, missing, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return m;
}

static const maelys_sandbox_policy_capabilities_t protect_caps =
    MAELYS_SANDBOX_POLICY_CAP_FS_READ | MAELYS_SANDBOX_POLICY_CAP_FS_WRITE |
    MAELYS_SANDBOX_POLICY_CAP_FS_DENY | MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE |
    MAELYS_SANDBOX_POLICY_CAP_PROCESS_TREE |
    MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE;

/* Compiles a deny with missing:skip on `relative` and checks the single
 * protect-create rule it must leave, at `expected` under the resolved root. */
static void expect_protected(const maelys_sandbox_policy_host_t *h,
                             const char *resolved_root, const char *relative,
                             const char *expected) {
  maelys_mir_t *m = one_rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                             relative, MAELYS_MIR_MISSING_SKIP);
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  char path[700];
  CHECK(snprintf(path, sizeof(path), "%s/%s", resolved_root, expected) > 0);
  CHECK_OK(maelys_sandbox_policy_compile(m, h, protect_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_rule_count(p) == 1u);
  maelys_sandbox_policy_resolved_rule_view_t rule;
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 0, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_DENY &&
        rule.missing == MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE);
  if (strcmp(rule.path, path) != 0) {
    fprintf(stderr, "FAIL %s: deny on %s resolved to %s, expected %s\n",
            __FILE__, relative, rule.path, path);
    ++failures;
  }
  CHECK(maelys_sandbox_policy_plan_required_capabilities(p) &
        MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE);
  maelys_sandbox_policy_evaluation_t evaluation;
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, path, &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_NONE &&
        evaluation.reason == MAELYS_SANDBOX_POLICY_REASON_DENY_RULE);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  maelys_mir_error_free(e);
}

static void expect_absent_deny_error(const maelys_sandbox_policy_host_t *h,
                                     const char *relative,
                                     maelys_mir_missing_path_t missing,
                                     maelys_mir_result_t expected,
                                     const char *fragment) {
  maelys_mir_t *m = one_rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE,
                             relative, missing);
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  maelys_mir_result_t got =
      maelys_sandbox_policy_compile(m, h, protect_caps, &p, &e);
  if (got != expected || p != NULL || !e || !strstr(e, fragment)) {
    fprintf(stderr, "FAIL %s: deny on %s gave %s (%s), expected %s with '%s'\n",
            __FILE__, relative, maelys_mir_result_name(got), e ? e : "-",
            maelys_mir_result_name(expected), fragment);
    ++failures;
  }
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  maelys_mir_error_free(e);
}

static void test_absent_deny(void) {
  char root[] = "/tmp/maelys-sandbox-policy-absent-XXXXXX";
  char outside[] = "/tmp/maelys-sandbox-policy-outside-XXXXXX";
  CHECK(make_temp_dir(root) && make_temp_dir(outside));
  char *resolved_root = realpath(root, NULL);
  char real_dir[512], inner[512], dangling[512], escape[512], file[512];
  CHECK(snprintf(real_dir, sizeof(real_dir), "%s/real", root) > 0);
  CHECK(snprintf(inner, sizeof(inner), "%s/inner", root) > 0);
  CHECK(snprintf(dangling, sizeof(dangling), "%s/dangling", root) > 0);
  CHECK(snprintf(escape, sizeof(escape), "%s/escape", root) > 0);
  CHECK(snprintf(file, sizeof(file), "%s/file", root) > 0);
  CHECK(mkdir(real_dir, 0700) == 0);
  CHECK(symlink("real", inner) == 0);
  CHECK(symlink("nowhere", dangling) == 0);
  CHECK(symlink(outside, escape) == 0);
  FILE *stream = fopen(file, "w");
  CHECK(stream != NULL && fclose(stream) == 0);
  maelys_sandbox_policy_host_t *h = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));

  /* The canonical existing prefix, then the literal remaining components. */
  expect_protected(h, resolved_root, ".git", ".git");
  expect_protected(h, resolved_root, "a/b/c", "a/b/c");
  expect_protected(h, resolved_root, "real/later", "real/later");
  expect_protected(h, resolved_root, "inner/later/deep", "real/later/deep");

  /* Nothing ambiguous is named. */
  expect_absent_deny_error(h, "dangling", MAELYS_MIR_MISSING_SKIP,
                           MAELYS_MIR_ERR_IO, "dangling symbolic link");
  expect_absent_deny_error(h, "dangling/child", MAELYS_MIR_MISSING_SKIP,
                           MAELYS_MIR_ERR_IO, "dangling symbolic link");
  expect_absent_deny_error(h, "file/child", MAELYS_MIR_MISSING_SKIP,
                           MAELYS_MIR_ERR_IO, "non-directory");
  expect_absent_deny_error(h, "escape/child", MAELYS_MIR_MISSING_SKIP,
                           MAELYS_MIR_ERR_FORMAT, "leaves its symbolic root");
  /* missing:error stays an error, whatever the backend offers. */
  expect_absent_deny_error(h, ".git", MAELYS_MIR_MISSING_ERROR,
                           MAELYS_MIR_ERR_MISSING, "does not exist");

  /* An absent grant is still omitted, and asks nothing of the backend. */
  maelys_mir_t *m = one_rule(MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE,
                             "build", MAELYS_MIR_MISSING_SKIP);
  maelys_sandbox_policy_plan_t *p = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_rule_count(p) == 0u);
  CHECK(!(maelys_sandbox_policy_plan_required_capabilities(p) &
          MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE));
  CHECK(maelys_sandbox_policy_plan_omitted_rule_count(p) == 1u);
  maelys_sandbox_policy_omitted_rule_view_t omitted;
  CHECK_OK(maelys_sandbox_policy_plan_omitted_rule_at(p, 0, &omitted));
  CHECK(omitted.access == MAELYS_MIR_FS_WRITE &&
        omitted.root == MAELYS_MIR_ROOT_WORKSPACE &&
        strcmp(omitted.relative, "build") == 0 &&
        strcmp(omitted.host_root, resolved_root) == 0);
  CHECK(maelys_sandbox_policy_plan_omitted_rule_at(p, 1, &omitted) ==
        MAELYS_MIR_ERR_ARGUMENT);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);

  /* A deny that exists is an ordinary rule. */
  m = one_rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, "real",
               MAELYS_MIR_MISSING_SKIP);
  p = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  maelys_sandbox_policy_resolved_rule_view_t rule;
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 0, &rule));
  CHECK(rule.missing == MAELYS_SANDBOX_POLICY_MISSING_ERROR);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);

  /* Every missing capability is named at once, the discovered one too. */
  m = one_rule(MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, ".git",
               MAELYS_MIR_MISSING_SKIP);
  maelys_sandbox_policy_capabilities_t required = 0;
  CHECK_OK(maelys_sandbox_policy_resolved_capabilities(m, h, &required, &e));
  CHECK(required == (maelys_sandbox_policy_required_capabilities(m) |
                     MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE));
  p = NULL;
  CHECK(maelys_sandbox_policy_compile(m, h, MAELYS_SANDBOX_POLICY_CAP_NETWORK_NONE,
                                      &p, &e) == MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(p == NULL);
  CHECK(e && strstr(e, "fs-deny") && strstr(e, "fs-protect-create"));
  maelys_mir_error_free(e);
  e = NULL;
  maelys_mir_destroy(m);
  CHECK(strcmp(maelys_sandbox_policy_capability_name(
                   MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE),
               "fs-protect-create") == 0);
  CHECK(maelys_sandbox_policy_capability_name(0) == NULL);
  CHECK(maelys_sandbox_policy_capability_name(3) == NULL);

  maelys_sandbox_policy_host_destroy(h);
  free(resolved_root);
  CHECK(unlink(file) == 0 && unlink(escape) == 0 && unlink(dangling) == 0 &&
        unlink(inner) == 0 && rmdir(real_dir) == 0 && rmdir(root) == 0 &&
        rmdir(outside) == 0);
}

/* examples/workspace.json reads the workspace and denies .git with
 * missing:skip. In a workspace that has no .git, a backend that cannot
 * protect its creation must get no plan: the example is not edited to hide
 * that loss of availability. */
static void test_example_without_git(void) {
  char root[] = "/tmp/maelys-sandbox-policy-example-XXXXXX";
  CHECK(make_temp_dir(root));
  FILE *stream = fopen("examples/workspace.json", "rb");
  CHECK(stream != NULL);
  if (!stream)
    return;
  static uint8_t json[8192];
  size_t size = fread(json, 1u, sizeof(json), stream);
  CHECK(fclose(stream) == 0 && size > 0u && size < sizeof(json));
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_compile_json(json, size, &m, &e));
  maelys_sandbox_policy_host_t *h = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  CHECK_OK(maelys_sandbox_policy_host_add_minimal_runtime_root(h, "/usr", &e));
  maelys_sandbox_policy_plan_t *p = NULL;
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(p == NULL);
  CHECK(e && strstr(e, "fs-protect-create") != NULL);
  maelys_mir_error_free(e);
  e = NULL;

  /* With .git present, the same policy and backend are accepted. */
  char git[512];
  CHECK(snprintf(git, sizeof(git), "%s/.git", root) > 0);
  CHECK(mkdir(git, 0700) == 0);
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_rule_count(p) == 3u);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_sandbox_policy_host_destroy(h);
  maelys_mir_destroy(m);
  maelys_mir_error_free(e);
  CHECK(rmdir(git) == 0 && rmdir(root) == 0);
}

/* A plan with the given filesystem rule and other dimensions. */
static maelys_sandbox_policy_plan_t *
dimension_plan(const maelys_sandbox_policy_host_t *h,
               maelys_mir_fs_access_t access, const char *relative,
               maelys_mir_network_mode_t network, const char *host,
               maelys_mir_network_destination_flags_t flags,
               maelys_mir_root_mode_t root, int process_tree) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  maelys_sandbox_policy_plan_t *p = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, access, MAELYS_MIR_ROOT_WORKSPACE, relative, MAELYS_MIR_SCOPE_TREE,
      MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_set_network(b, network, &e));
  if (host)
    CHECK_OK(maelys_mir_builder_add_network_destination_ex(
        b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, host, 443u, flags, &e));
  CHECK_OK(maelys_mir_builder_set_root_mode(b, root, &e));
  CHECK_OK(maelys_mir_builder_set_process_tree_required(b, process_tree, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  CHECK_OK(maelys_sandbox_policy_compile(m, h, UINT64_MAX, &p, &e));
  maelys_mir_destroy(m);
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return p;
}

static unsigned exceeds(const maelys_sandbox_policy_plan_t *boundary,
                        const maelys_sandbox_policy_plan_t *candidate,
                        maelys_sandbox_policy_containment_t *out) {
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_plan_contains(boundary, candidate, out, &e));
  maelys_mir_error_free(e);
  return out->exceeds;
}

static void test_containment(void) {
  char root[] = "/tmp/maelys-sandbox-policy-contain-XXXXXX";
  CHECK(make_temp_dir(root));
  char src[512];
  CHECK(snprintf(src, sizeof(src), "%s/src", root) > 0);
  CHECK(mkdir(src, 0700) == 0);
  char *resolved_src = realpath(src, NULL);
  maelys_sandbox_policy_host_t *h = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_network_mediator(h, "egress", &e));
  const maelys_mir_network_destination_flags_t sni =
      MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI;
  const maelys_mir_network_destination_flags_t priv =
      MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES;
#define PLAN(access, relative, network, host, flags, rootmode, tree)           \
  dimension_plan(h, access, relative, network, host, flags, rootmode, tree)
  maelys_sandbox_policy_plan_t *boundary =
      PLAN(MAELYS_MIR_FS_READ, "", MAELYS_MIR_NETWORK_MEDIATED, "github.com",
           sni, MAELYS_MIR_ROOT_READ_ONLY, 1);
  maelys_sandbox_policy_containment_t c;

  /* A sub-agent asking a subtree of what its parent holds is contained. */
  maelys_sandbox_policy_plan_t *narrower =
      PLAN(MAELYS_MIR_FS_READ, "src", MAELYS_MIR_NETWORK_NONE, NULL, 0u,
           MAELYS_MIR_ROOT_READ_ONLY, 1);
  CHECK(exceeds(boundary, narrower, &c) == 0u);
  CHECK(c.path == NULL && c.boundary_rule == SIZE_MAX &&
        c.candidate_destination == SIZE_MAX);
  maelys_sandbox_policy_containment_clear(&c);
  /* ...and the converse is not: the parent reads more than the subtree. */
  CHECK(exceeds(narrower, boundary, &c) ==
        (MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM |
         MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK));
  CHECK(c.network == MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_MODE);
  CHECK(c.candidate_permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ &&
        c.boundary_permission == MAELYS_SANDBOX_POLICY_PERMISSION_NONE &&
        c.boundary_rule == SIZE_MAX && c.candidate_rule == 0u);
  maelys_sandbox_policy_containment_clear(&c);
  CHECK(exceeds(boundary, boundary, &c) == 0u);
  maelys_sandbox_policy_containment_clear(&c);

  /* Filesystem: writing where the boundary only reads, with the witness. */
  maelys_sandbox_policy_plan_t *writer =
      PLAN(MAELYS_MIR_FS_WRITE, "src", MAELYS_MIR_NETWORK_NONE, NULL, 0u,
           MAELYS_MIR_ROOT_READ_ONLY, 1);
  CHECK(exceeds(boundary, writer, &c) ==
        MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM);
  CHECK(c.path && strcmp(c.path, resolved_src) == 0);
  CHECK(c.boundary_permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ &&
        c.candidate_permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE &&
        c.boundary_rule == 0u && c.candidate_rule == 0u);
  maelys_sandbox_policy_containment_clear(&c);
  CHECK(c.path == NULL && c.exceeds == 0u);

  /* Network: mode, destination, then each flag. */
  static const struct {
    maelys_mir_network_mode_t mode;
    const char *host;
    maelys_mir_network_destination_flags_t flags;
    maelys_sandbox_policy_network_excess_t expected;
  } network_cases[] = {
      {MAELYS_MIR_NETWORK_NONE, NULL, 0u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_NONE},
      {MAELYS_MIR_NETWORK_MEDIATED, "github.com", 0x1u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_NONE},
      {MAELYS_MIR_NETWORK_DIRECT, NULL, 0u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_MODE},
      {MAELYS_MIR_NETWORK_MEDIATED, "example.org", 0x1u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_DESTINATION},
      {MAELYS_MIR_NETWORK_MEDIATED, "github.com", 0u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_TLS_SNI},
      {MAELYS_MIR_NETWORK_MEDIATED, "github.com", 0x3u,
       MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_PRIVATE_ADDRESSES},
  };
  for (size_t i = 0; i < sizeof(network_cases) / sizeof(network_cases[0]); ++i) {
    maelys_sandbox_policy_plan_t *candidate =
        PLAN(MAELYS_MIR_FS_READ, "src", network_cases[i].mode,
             network_cases[i].host, network_cases[i].flags,
             MAELYS_MIR_ROOT_READ_ONLY, 1);
    unsigned got = exceeds(boundary, candidate, &c);
    CHECK(c.network == network_cases[i].expected);
    CHECK(got == (network_cases[i].expected
                      ? MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK
                      : 0u));
    CHECK((c.candidate_destination == 0u) ==
          (network_cases[i].expected >
           MAELYS_SANDBOX_POLICY_NETWORK_EXCESS_MODE));
    maelys_sandbox_policy_containment_clear(&c);
    maelys_sandbox_policy_plan_destroy(candidate);
  }
  /* A direct boundary allows every destination and every flag. */
  maelys_sandbox_policy_plan_t *direct =
      PLAN(MAELYS_MIR_FS_READ, "", MAELYS_MIR_NETWORK_DIRECT, NULL, 0u,
           MAELYS_MIR_ROOT_EPHEMERAL_WRITE, 0);
  maelys_sandbox_policy_plan_t *private_peer =
      PLAN(MAELYS_MIR_FS_READ, "src", MAELYS_MIR_NETWORK_MEDIATED,
           "registry.internal", priv, MAELYS_MIR_ROOT_EPHEMERAL_WRITE, 0);
  CHECK(exceeds(direct, private_peer, &c) == 0u);
  maelys_sandbox_policy_containment_clear(&c);

  /* Root and process: the looser mode exceeds the stricter boundary. */
  CHECK(exceeds(boundary, private_peer, &c) ==
        (MAELYS_SANDBOX_POLICY_DIMENSION_NETWORK |
         MAELYS_SANDBOX_POLICY_DIMENSION_ROOT |
         MAELYS_SANDBOX_POLICY_DIMENSION_PROCESS));
  maelys_sandbox_policy_containment_clear(&c);
  CHECK(exceeds(direct, boundary, &c) == 0u);
  maelys_sandbox_policy_containment_clear(&c);

  CHECK(maelys_sandbox_policy_plan_contains(NULL, boundary, &c, &e) ==
        MAELYS_MIR_ERR_ARGUMENT);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK(maelys_sandbox_policy_plan_contains(boundary, boundary, NULL, NULL) ==
        MAELYS_MIR_ERR_ARGUMENT);
#undef PLAN
  maelys_sandbox_policy_plan_destroy(private_peer);
  maelys_sandbox_policy_plan_destroy(direct);
  maelys_sandbox_policy_plan_destroy(writer);
  maelys_sandbox_policy_plan_destroy(narrower);
  maelys_sandbox_policy_plan_destroy(boundary);
  maelys_sandbox_policy_host_destroy(h);
  free(resolved_src);
  maelys_mir_error_free(e);
  CHECK(rmdir(src) == 0 && rmdir(root) == 0);
}

static void test_deny_write(void) {
  char root[] = "/tmp/maelys-sandbox-policy-denywrite-XXXXXX";
  CHECK(make_temp_dir(root));
  char git[512];
  CHECK(snprintf(git, sizeof(git), "%s/.git", root) > 0);
  CHECK(mkdir(git, 0700) == 0);
  char *resolved_root = realpath(root, NULL);
  maelys_sandbox_policy_host_t *h = NULL;
  char *e = NULL;
  CHECK_OK(maelys_sandbox_policy_host_create(&h, &e));
  CHECK_OK(maelys_sandbox_policy_host_set_workspace(h, root, &e));
  const maelys_sandbox_policy_capabilities_t deny_write =
      MAELYS_SANDBOX_POLICY_CAP_FS_DENY_WRITE;

  /* write the workspace, keep .git read-only */
  maelys_mir_t *m = two_rules(MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "",
                              MAELYS_MIR_FS_DENY_WRITE,
                              MAELYS_MIR_ROOT_WORKSPACE, ".git");
  CHECK(maelys_sandbox_policy_required_capabilities(m) & deny_write);
  maelys_sandbox_policy_plan_t *p = NULL;
  /* A backend that does not announce the capability gets no plan. */
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(p == NULL && e && strstr(e, "fs-deny-write") != NULL);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps | deny_write, &p, &e));
  /* plan order: the grant, then the deny-write */
  maelys_sandbox_policy_resolved_rule_view_t rule;
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 0, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_WRITE);
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 1, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_DENY_WRITE &&
        rule.missing == MAELYS_SANDBOX_POLICY_MISSING_ERROR);
  char path[600];
  maelys_sandbox_policy_evaluation_t evaluation;
  CHECK(snprintf(path, sizeof(path), "%s/.git/config", resolved_root) > 0);
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, path, &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ &&
        evaluation.reason == MAELYS_SANDBOX_POLICY_REASON_DENY_WRITE_RULE &&
        evaluation.decisive_rule == 1u);
  CHECK(snprintf(path, sizeof(path), "%s/src/main.c", resolved_root) > 0);
  CHECK_OK(maelys_sandbox_policy_plan_evaluate(p, path, &evaluation, &e));
  CHECK(evaluation.permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE);

  /* It is contained in the plan that writes everything, not the converse. */
  maelys_mir_t *wide = one_rule(MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE,
                                "", MAELYS_MIR_MISSING_ERROR);
  maelys_sandbox_policy_plan_t *wide_plan = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(wide, h, all_caps, &wide_plan, &e));
  maelys_sandbox_policy_containment_t c;
  const unsigned filesystem = MAELYS_SANDBOX_POLICY_DIMENSION_FILESYSTEM;
  CHECK((exceeds(wide_plan, p, &c) & filesystem) == 0u);
  maelys_sandbox_policy_containment_clear(&c);
  CHECK(exceeds(p, wide_plan, &c) & filesystem);
  CHECK(c.boundary_permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ &&
        c.candidate_permission == MAELYS_SANDBOX_POLICY_PERMISSION_READ_WRITE);
  maelys_sandbox_policy_containment_clear(&c);
  maelys_sandbox_policy_plan_destroy(wide_plan);
  maelys_mir_destroy(wide);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);

  /* A read under a write stays ambiguous beside a deny-write: refused. */
  maelys_mir_builder_t *b = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, ".git",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_DENY_WRITE, MAELYS_MIR_ROOT_WORKSPACE, ".git",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  p = NULL;
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps | deny_write, &p, &e) ==
        MAELYS_MIR_ERR_CONFLICT);
  CHECK(p == NULL);
  maelys_mir_error_free(e);
  e = NULL;
  maelys_mir_destroy(m);
  maelys_mir_builder_destroy(b);

  /* An absent target is kept and needs the protection of its creation. */
  m = one_rule(MAELYS_MIR_FS_DENY_WRITE, MAELYS_MIR_ROOT_WORKSPACE, ".env",
               MAELYS_MIR_MISSING_SKIP);
  p = NULL;
  CHECK(maelys_sandbox_policy_compile(m, h, all_caps | deny_write, &p, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  CHECK(p == NULL && e && strstr(e, "fs-protect-create") != NULL);
  maelys_mir_error_free(e);
  e = NULL;
  CHECK_OK(maelys_sandbox_policy_compile(
      m, h, all_caps | deny_write | MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE,
      &p, &e));
  CHECK_OK(maelys_sandbox_policy_plan_rule_at(p, 0, &rule));
  CHECK(rule.access == MAELYS_MIR_FS_DENY_WRITE &&
        rule.missing == MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  CHECK(strcmp(maelys_sandbox_policy_capability_name(deny_write),
               "fs-deny-write") == 0);

  maelys_sandbox_policy_host_destroy(h);
  free(resolved_root);
  maelys_mir_error_free(e);
  CHECK(rmdir(git) == 0 && rmdir(root) == 0);
}

int main(void) {
  test_compile();
  test_symlink_escape();
  test_mediated_network();
  test_permission_contract();
  test_destination_flags_require_capabilities();
  test_missing_is_not_io_failure();
  test_absent_deny();
  test_example_without_git();
  test_containment();
  test_deny_write();
  if (failures)
    fprintf(stderr, "%d sandbox test failures\n", failures);
  return failures ? 1 : 0;
}
