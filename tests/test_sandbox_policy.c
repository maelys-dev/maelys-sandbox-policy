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

  maelys_mir_t *m = missing_policy("absent");
  CHECK_OK(maelys_sandbox_policy_compile(m, h, all_caps, &p, &e));
  CHECK(maelys_sandbox_policy_plan_rule_count(p) == 0);
  maelys_sandbox_policy_plan_destroy(p);
  maelys_mir_destroy(m);
  p = NULL;

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

int main(void) {
  test_compile();
  test_symlink_escape();
  test_mediated_network();
  test_missing_is_not_io_failure();
  if (failures)
    fprintf(stderr, "%d sandbox test failures\n", failures);
  return failures ? 1 : 0;
}
