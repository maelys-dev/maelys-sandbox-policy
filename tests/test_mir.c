#include <maelys/mir.h>

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
#define CHECK_OK(x)                                                            \
  do {                                                                         \
    maelys_mir_result_t check_result = (x);                                    \
    if (check_result != MAELYS_MIR_OK) {                                       \
      fprintf(stderr, "FAIL %s:%d: %s => %s\n", __FILE__, __LINE__, #x,        \
              maelys_mir_result_name(check_result));                           \
      ++failures;                                                              \
    }                                                                          \
  } while (0)

static maelys_mir_t *build_order(int reverse) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *mir = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  if (reverse) {
    CHECK_OK(maelys_mir_builder_add_fs_rule(
        b, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, ".git/",
        MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP, &e));
    CHECK_OK(maelys_mir_builder_add_fs_rule(
        b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "./src",
        MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  } else {
    CHECK_OK(maelys_mir_builder_add_fs_rule(
        b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "src",
        MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
    CHECK_OK(maelys_mir_builder_add_fs_rule(
        b, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, ".git",
        MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP, &e));
  }
  CHECK_OK(maelys_mir_builder_build(b, &mir, &e));
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  return mir;
}

static void test_determinism(void) {
  maelys_mir_t *a = build_order(0), *b = build_order(1);
  uint8_t *ab = NULL, *bb = NULL;
  size_t an = 0, bn = 0;
  char *e = NULL;
  CHECK_OK(maelys_mir_encode(a, &ab, &an, &e));
  CHECK_OK(maelys_mir_encode(b, &bb, &bn, &e));
  CHECK(an == bn);
  CHECK(memcmp(ab, bb, an) == 0);
  char ah[65], bh[65];
  CHECK_OK(maelys_mir_digest_hex(a, ah, &e));
  CHECK_OK(maelys_mir_digest_hex(b, bh, &e));
  CHECK(strcmp(ah, bh) == 0);
  maelys_mir_t *decoded = NULL;
  CHECK_OK(maelys_mir_decode(ab, an, &decoded, &e));
  CHECK(maelys_mir_fs_rule_count(decoded) == 2);
  maelys_mir_bytes_free(ab);
  maelys_mir_bytes_free(bb);
  maelys_mir_destroy(decoded);
  maelys_mir_destroy(a);
  maelys_mir_destroy(b);
  maelys_mir_error_free(e);
}

static void test_precedence(void) {
  maelys_mir_builder_t *b = NULL;
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "secret",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, "secret",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_build(b, &m, &e));
  CHECK(maelys_mir_fs_rule_count(m) == 1);
  maelys_mir_fs_rule_view_t v;
  CHECK_OK(maelys_mir_fs_rule_at(m, 0, &v));
  CHECK(v.access == MAELYS_MIR_FS_DENY);
  maelys_mir_builder_destroy(b);
  maelys_mir_destroy(m);
  maelys_mir_error_free(e);
}

static void test_ephemeral_root_identity(void) {
  maelys_mir_builder_t *readonly_builder = NULL, *writable_builder = NULL;
  maelys_mir_t *readonly = NULL, *writable = NULL;
  char *error = NULL;
  CHECK_OK(maelys_mir_builder_create(&readonly_builder, &error));
  CHECK_OK(maelys_mir_builder_create(&writable_builder, &error));
  CHECK_OK(maelys_mir_builder_set_root_mode(
      writable_builder, MAELYS_MIR_ROOT_EPHEMERAL_WRITE, &error));
  CHECK_OK(maelys_mir_builder_build(readonly_builder, &readonly, &error));
  CHECK_OK(maelys_mir_builder_build(writable_builder, &writable, &error));
  CHECK(maelys_mir_root_mode(readonly) == MAELYS_MIR_ROOT_READ_ONLY);
  CHECK(maelys_mir_root_mode(writable) == MAELYS_MIR_ROOT_EPHEMERAL_WRITE);
  char readonly_digest[65], writable_digest[65];
  CHECK_OK(maelys_mir_digest_hex(readonly, readonly_digest, &error));
  CHECK_OK(maelys_mir_digest_hex(writable, writable_digest, &error));
  CHECK(strcmp(readonly_digest, writable_digest) != 0);
  maelys_mir_destroy(readonly);
  maelys_mir_destroy(writable);
  maelys_mir_builder_destroy(readonly_builder);
  maelys_mir_builder_destroy(writable_builder);
  maelys_mir_error_free(error);
}

static const char valid_json[] =
    "{\"$schema\":\"https://schemas.maelys.dev/mir-source/v3/"
    "schema.json\",\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\","
    "\"rules\":[{\"access\":\"read\",\"path\":{\"special\":\"minimal-runtime\"}"
    "},{\"access\":\"write\",\"path\":{\"root\":\"workspace\",\"relative\":"
    "\"build//./"
    "obj\"},\"missing\":\"skip\"}]},\"network\":{\"mode\":\"none\"},"
    "\"root\":{\"mode\":\"read-only\"},\"process\":{\"treeConfinement\":\"required\"}}";
static void test_json(void) {
  maelys_mir_t *m = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_compile_json((const uint8_t *)valid_json,
                                   strlen(valid_json), &m, &e));
  CHECK(maelys_mir_fs_rule_count(m) == 2);
  maelys_mir_fs_rule_view_t v;
  CHECK_OK(maelys_mir_fs_rule_at(m, 1, &v));
  CHECK(strcmp(v.relative, "build/obj") == 0);
  uint8_t *inspection = NULL;
  size_t inspection_size = 0;
  CHECK_OK(maelys_mir_inspect_json(m, &inspection, &inspection_size, &e));
  CHECK(inspection_size > 0u);
  CHECK(strstr((const char *)inspection, "\"inspectionVersion\": 1") !=
        NULL);
  CHECK(strstr((const char *)inspection,
               "\"basis\": \"canonical-mir-v3-bytes\"") != NULL);
  CHECK(strstr((const char *)inspection, "\"path\": \"build/obj\"") !=
        NULL);
  maelys_mir_bytes_free(inspection);
  maelys_mir_destroy(m);
  const char *bad = "{\"formatVersion\":3,\"formatVersion\":3}";
  CHECK(maelys_mir_compile_json((const uint8_t *)bad, strlen(bad), &m, &e) ==
        MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  const char *escape =
      "{\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\",\"rules\":[{"
      "\"access\":\"read\",\"path\":{\"root\":\"workspace\",\"relative\":\"../"
      "escape\"}}]},\"network\":{\"mode\":\"none\"},\"root\":{\"mode\":\"read-only\"},\"process\":{"
      "\"treeConfinement\":\"required\"}}";
  CHECK(maelys_mir_compile_json((const uint8_t *)escape, strlen(escape), &m,
                                &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  const char *bad_surrogate =
      "{\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\",\"rules\":[{"
      "\"access\":\"read\",\"path\":{\"root\":\"workspace\",\"relative\":"
      "\"\\uD800\\uXXXX\"}}]},\"network\":{\"mode\":\"none\"},\"root\":{\"mode\":\"read-only\"},\"process\":{"
      "\"treeConfinement\":\"required\"}}";
  CHECK(maelys_mir_compile_json((const uint8_t *)bad_surrogate,
                                strlen(bad_surrogate), &m,
                                &e) == MAELYS_MIR_ERR_FORMAT);
  CHECK(e != NULL && strstr(e, "invalid Unicode escape") != NULL);
  maelys_mir_error_free(e);
  e = NULL;
  const char *missing_separator = "{\"\"  \r";
  CHECK(maelys_mir_compile_json((const uint8_t *)missing_separator,
                                strlen(missing_separator), &m,
                                &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  const char *legacy =
      "{\"formatVersion\":1,\"filesystem\":{\"default\":\"deny\","
      "\"rules\":[]},\"network\":{\"mode\":\"none\"},\"root\":{\"mode\":\"read-only\"},\"process\":{"
      "\"treeConfinement\":\"required\"}}";
  CHECK(maelys_mir_compile_json((const uint8_t *)legacy, strlen(legacy),
                                &m, &e) == MAELYS_MIR_ERR_FORMAT);
  CHECK(m == NULL);
  maelys_mir_error_free(e);
}

static void test_artifact_digest(void) {
  static const uint8_t abc[] = {'a', 'b', 'c'};
  char digest[MAELYS_MIR_DIGEST_HEX_SIZE];
  char *error = NULL;
  CHECK_OK(maelys_mir_artifact_digest_hex(abc, sizeof(abc), digest, &error));
  CHECK(strcmp(digest,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ==
        0);
  CHECK_OK(maelys_mir_artifact_digest_hex(NULL, 0u, digest, &error));
  CHECK(strcmp(digest,
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") ==
        0);
  maelys_mir_error_free(error);
}

static void test_network_allowlist(void) {
  static const char json[] =
      "{\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\",\"rules\":[]},"
      "\"network\":{\"mode\":\"mediated\",\"allow\":["
      "{\"protocol\":\"tcp\",\"host\":\"GitHub.COM\",\"port\":443},"
      "{\"protocol\":\"tcp\",\"host\":\"github.com\",\"port\":443},"
      "{\"protocol\":\"tcp\",\"host\":\"api.github.com\",\"port\":443}]},"
      "\"root\":{\"mode\":\"read-only\"},\"process\":{\"treeConfinement\":\"required\"}}";
  maelys_mir_t *mir = NULL, *decoded = NULL;
  char *error = NULL;
  CHECK_OK(maelys_mir_compile_json((const uint8_t *)json, strlen(json),
                                   &mir, &error));
  CHECK(maelys_mir_network(mir) == MAELYS_MIR_NETWORK_MEDIATED);
  CHECK(maelys_mir_network_destination_count(mir) == 2u);
  maelys_mir_network_destination_view_t destination;
  CHECK_OK(maelys_mir_network_destination_at(mir, 1, &destination));
  CHECK(strcmp(destination.host, "github.com") == 0);
  CHECK(destination.port == 443u);
  uint8_t *bytes = NULL;
  size_t size = 0;
  CHECK_OK(maelys_mir_encode(mir, &bytes, &size, &error));
  CHECK_OK(maelys_mir_decode(bytes, size, &decoded, &error));
  CHECK(maelys_mir_network_destination_count(decoded) == 2u);
  char before[65], after[65];
  CHECK_OK(maelys_mir_digest_hex(mir, before, &error));
  CHECK_OK(maelys_mir_digest_hex(decoded, after, &error));
  CHECK(strcmp(before, after) == 0);
  maelys_mir_bytes_free(bytes);
  maelys_mir_destroy(decoded);
  maelys_mir_destroy(mir);
  maelys_mir_error_free(error);
}

static void test_noncanonical(void) {
  maelys_mir_t *m = build_order(0);
  uint8_t *bytes = NULL;
  size_t n = 0;
  char *e = NULL;
  CHECK_OK(maelys_mir_encode(m, &bytes, &n, &e));
  uint8_t *extra = malloc(n + 1);
  memcpy(extra, bytes, n);
  extra[n] = 0;
  CHECK(maelys_mir_check_canonical(extra, n + 1, &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  free(extra);
  maelys_mir_bytes_free(bytes);
  maelys_mir_destroy(m);
}

static void test_restrictive_overlay(void) {
  maelys_mir_builder_t *b = NULL, *r = NULL;
  maelys_mir_t *base = NULL, *restriction = NULL, *effective = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      b, MAELYS_MIR_FS_WRITE, MAELYS_MIR_ROOT_WORKSPACE, "",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_ERROR, &e));
  CHECK_OK(maelys_mir_builder_set_network(b, MAELYS_MIR_NETWORK_DIRECT, &e));
  CHECK_OK(maelys_mir_builder_build(b, &base, &e));
  CHECK_OK(maelys_mir_builder_create(&r, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      r, MAELYS_MIR_FS_DENY, MAELYS_MIR_ROOT_WORKSPACE, ".git",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP, &e));
  CHECK_OK(maelys_mir_builder_set_network(r, MAELYS_MIR_NETWORK_NONE, &e));
  CHECK_OK(maelys_mir_builder_build(r, &restriction, &e));
  CHECK_OK(maelys_mir_restrict(base, restriction, &effective, &e));
  CHECK(maelys_mir_network(effective) == MAELYS_MIR_NETWORK_NONE);
  CHECK(maelys_mir_fs_rule_count(effective) == 2);
  maelys_mir_destroy(effective);
  maelys_mir_destroy(restriction);
  maelys_mir_builder_destroy(r);
  CHECK_OK(maelys_mir_builder_create(&r, &e));
  CHECK_OK(maelys_mir_builder_add_fs_rule(
      r, MAELYS_MIR_FS_READ, MAELYS_MIR_ROOT_WORKSPACE, "secrets",
      MAELYS_MIR_SCOPE_TREE, MAELYS_MIR_MISSING_SKIP, &e));
  CHECK_OK(maelys_mir_builder_build(r, &restriction, &e));
  CHECK(maelys_mir_restrict(base, restriction, &effective, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_error_free(e);
  maelys_mir_destroy(restriction);
  maelys_mir_builder_destroy(r);
  maelys_mir_destroy(base);
  maelys_mir_builder_destroy(b);
}

int main(void) {
  test_determinism();
  test_precedence();
  test_ephemeral_root_identity();
  test_json();
  test_network_allowlist();
  test_artifact_digest();
  test_noncanonical();
  test_restrictive_overlay();
  if (failures)
    fprintf(stderr, "%d MIR test failures\n", failures);
  return failures ? 1 : 0;
}
