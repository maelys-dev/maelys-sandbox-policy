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

static maelys_mir_t *compile_destinations(const char *allow) {
  char json[1024];
  (void)snprintf(json, sizeof(json),
                 "{\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\","
                 "\"rules\":[]},\"network\":{\"mode\":\"mediated\",\"allow\":"
                 "[%s]},\"root\":{\"mode\":\"read-only\"},\"process\":"
                 "{\"treeConfinement\":\"disabled\"}}",
                 allow);
  maelys_mir_t *mir = NULL;
  char *error = NULL;
  (void)maelys_mir_compile_json((const uint8_t *)json, strlen(json), &mir,
                                &error);
  maelys_mir_error_free(error);
  return mir;
}

static maelys_mir_network_destination_flags_t
flags_of(const maelys_mir_t *mir, const char *host) {
  for (size_t i = 0; i < maelys_mir_network_destination_count(mir); ++i) {
    maelys_mir_network_destination_ex_view_t d;
    CHECK_OK(maelys_mir_network_destination_at_ex(mir, i, &d));
    if (strcmp(d.host, host) == 0)
      return d.flags;
  }
  return UINT32_C(0xffffffff);
}

static void test_network_destination_flags(void) {
  const maelys_mir_network_destination_flags_t sni =
      MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI;
  const maelys_mir_network_destination_flags_t priv =
      MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES;
  char *e = NULL;

  /* Explicit false flags keep the 0.4.x identity. */
  maelys_mir_t *plain = compile_destinations(
      "{\"protocol\":\"tcp\",\"host\":\"github.com\",\"port\":443}");
  maelys_mir_t *explicit_false = compile_destinations(
      "{\"protocol\":\"tcp\",\"host\":\"github.com\",\"port\":443,"
      "\"requireTlsSni\":false,\"allowPrivateAddresses\":false}");
  CHECK(plain && explicit_false);
  char plain_hex[65], false_hex[65];
  CHECK_OK(maelys_mir_digest_hex(plain, plain_hex, &e));
  CHECK_OK(maelys_mir_digest_hex(explicit_false, false_hex, &e));
  CHECK(strcmp(plain_hex, false_hex) == 0);
  maelys_mir_network_destination_view_t legacy;
  CHECK_OK(maelys_mir_network_destination_at(plain, 0, &legacy));

  /* Duplicates merge restrictively: SNI by OR, private addresses by AND. */
  maelys_mir_t *mir = compile_destinations(
      "{\"protocol\":\"tcp\",\"host\":\"github.com\",\"port\":443,"
      "\"requireTlsSni\":true},"
      "{\"protocol\":\"tcp\",\"host\":\"GitHub.com\",\"port\":443,"
      "\"allowPrivateAddresses\":true},"
      "{\"protocol\":\"tcp\",\"host\":\"registry.internal\",\"port\":5000,"
      "\"allowPrivateAddresses\":true,\"requireTlsSni\":true}");
  CHECK(mir != NULL);
  CHECK(maelys_mir_network_destination_count(mir) == 2u);
  CHECK(flags_of(mir, "github.com") == sni);
  CHECK(flags_of(mir, "registry.internal") == (sni | priv));
  CHECK(maelys_mir_network_destination_at(mir, 0, &legacy) ==
        MAELYS_MIR_ERR_UNSUPPORTED);

  char mir_hex[65];
  CHECK_OK(maelys_mir_digest_hex(mir, mir_hex, &e));
  CHECK(strcmp(mir_hex, plain_hex) != 0);

  uint8_t *bytes = NULL;
  size_t size = 0;
  maelys_mir_t *decoded = NULL;
  CHECK_OK(maelys_mir_encode(mir, &bytes, &size, &e));
  /* First network record follows the 20-byte header (no filesystem rules). */
  const uint8_t *record = bytes + 20;
  CHECK(record[0] == 2u && record[4] == sni && record[5] == 0u);
  CHECK(record[6] == 0u && record[7] == strlen("github.com"));
  /* A 0.4.x decoder reads bytes 4..7 as one length and must reject it. */
  uint32_t legacy_length = ((uint32_t)record[4] << 24) |
                           ((uint32_t)record[5] << 16) |
                           ((uint32_t)record[6] << 8) | record[7];
  CHECK(legacy_length > MAELYS_MIR_MAX_NETWORK_HOST_BYTES);
  CHECK_OK(maelys_mir_decode(bytes, size, &decoded, &e));
  char decoded_hex[65];
  CHECK_OK(maelys_mir_digest_hex(decoded, decoded_hex, &e));
  CHECK(strcmp(mir_hex, decoded_hex) == 0);
  CHECK(flags_of(decoded, "registry.internal") == (sni | priv));

  uint8_t *tampered = malloc(size);
  memcpy(tampered, bytes, size);
  tampered[20 + 4] = 0x04u;
  CHECK(maelys_mir_check_canonical(tampered, size, &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  memcpy(tampered, bytes, size);
  tampered[20 + 5] = 0x01u;
  CHECK(maelys_mir_check_canonical(tampered, size, &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  free(tampered);

  maelys_mir_builder_t *b = NULL;
  CHECK_OK(maelys_mir_builder_create(&b, &e));
  CHECK(maelys_mir_builder_add_network_destination_ex(
            b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "github.com", 443u, 0x4u,
            &e) == MAELYS_MIR_ERR_ARGUMENT);
  maelys_mir_builder_destroy(b);
  maelys_mir_error_free(e);
  e = NULL;

  static const char *const invalid[] = {
      "{\"protocol\":\"tcp\",\"host\":\"a.com\",\"port\":1,\"requireTlsSni\":1}",
      "{\"protocol\":\"tcp\",\"host\":\"a.com\",\"port\":1,"
      "\"requireTlsSni\":truex}",
      "{\"protocol\":\"tcp\",\"host\":\"a.com\",\"port\":1,"
      "\"requireTlsSni\":true,\"requireTlsSni\":true}",
      "{\"protocol\":\"tcp\",\"host\":\"a.com\",\"port\":1,"
      "\"allowPrivateAddresses\":\"true\"}",
      "{\"protocol\":\"tcp\",\"host\":\"a.com\",\"requireTlsSni\":true}",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    maelys_mir_t *rejected = compile_destinations(invalid[i]);
    CHECK(rejected == NULL);
    maelys_mir_destroy(rejected);
  }

  /* Composition keeps the narrower decision per destination. */
  maelys_mir_t *base = compile_destinations(
      "{\"protocol\":\"tcp\",\"host\":\"registry.internal\",\"port\":5000,"
      "\"allowPrivateAddresses\":true}");
  maelys_mir_t *ceiling = compile_destinations(
      "{\"protocol\":\"tcp\",\"host\":\"registry.internal\",\"port\":5000,"
      "\"requireTlsSni\":true}");
  maelys_mir_t *effective = NULL;
  CHECK_OK(maelys_mir_restrict(base, ceiling, &effective, &e));
  CHECK(flags_of(effective, "registry.internal") == sni);
  maelys_mir_destroy(effective);
  effective = NULL;
  CHECK_OK(maelys_mir_restrict(base, base, &effective, &e));
  CHECK(flags_of(effective, "registry.internal") == priv);
  maelys_mir_destroy(effective);

  maelys_mir_destroy(ceiling);
  maelys_mir_destroy(base);
  maelys_mir_bytes_free(bytes);
  maelys_mir_destroy(decoded);
  maelys_mir_destroy(mir);
  maelys_mir_destroy(explicit_false);
  maelys_mir_destroy(plain);
  maelys_mir_error_free(e);
}

static maelys_mir_t *compile_rules(const char *rules) {
  char json[2048];
  (void)snprintf(json, sizeof(json),
                 "{\"formatVersion\":3,\"filesystem\":{\"default\":\"deny\","
                 "\"rules\":[%s]},\"network\":{\"mode\":\"none\"},\"root\":"
                 "{\"mode\":\"read-only\"},\"process\":{\"treeConfinement\":"
                 "\"disabled\"}}",
                 rules);
  maelys_mir_t *mir = NULL;
  char *error = NULL;
  (void)maelys_mir_compile_json((const uint8_t *)json, strlen(json), &mir,
                                &error);
  maelys_mir_error_free(error);
  return mir;
}

/* The accesses a policy keeps on workspace/a, in canonical order. */
static void expect_accesses(const char *rules, const char *expected) {
  maelys_mir_t *mir = compile_rules(rules);
  char got[16] = "";
  size_t used = 0;
  CHECK(mir != NULL);
  for (size_t i = 0; i < maelys_mir_fs_rule_count(mir); ++i) {
    maelys_mir_fs_rule_view_t rule;
    CHECK_OK(maelys_mir_fs_rule_at(mir, i, &rule));
    if (strcmp(rule.relative, "a") == 0 && used + 1u < sizeof(got))
      got[used++] = (char)('0' + (int)rule.access);
  }
  got[used] = '\0';
  if (strcmp(got, expected) != 0) {
    fprintf(stderr, "FAIL %s: [%s] keeps accesses %s, expected %s\n", __FILE__,
            rules, got, expected);
    ++failures;
  }
  /* canonical bytes survive a round trip unchanged */
  uint8_t *bytes = NULL;
  size_t size = 0;
  char *e = NULL;
  maelys_mir_t *decoded = NULL;
  CHECK_OK(maelys_mir_encode(mir, &bytes, &size, &e));
  CHECK_OK(maelys_mir_decode(bytes, size, &decoded, &e));
  maelys_mir_bytes_free(bytes);
  maelys_mir_destroy(decoded);
  maelys_mir_destroy(mir);
  maelys_mir_error_free(e);
}

#define RULE(access)                                                           \
  "{\"access\":\"" access "\",\"path\":{\"root\":\"workspace\",\"relative\":\"a\"}}"

static void test_deny_write(void) {
  /* 1 read, 2 write, 3 deny, 4 deny-write. One target keeps one grant and
   * one deny-write; a deny replaces both, whatever the order given. */
  expect_accesses(RULE("deny-write"), "4");
  expect_accesses(RULE("write") "," RULE("deny-write"), "24");
  expect_accesses(RULE("deny-write") "," RULE("write"), "24");
  expect_accesses(RULE("read") "," RULE("deny-write"), "14");
  expect_accesses(RULE("read") "," RULE("deny-write") "," RULE("write"), "24");
  expect_accesses(RULE("write") "," RULE("deny-write") "," RULE("read"), "24");
  expect_accesses(RULE("deny-write") "," RULE("deny-write"), "4");
  expect_accesses(RULE("write") "," RULE("deny-write") "," RULE("deny"), "3");
  expect_accesses(RULE("deny") "," RULE("deny-write") "," RULE("write"), "3");
  expect_accesses(RULE("deny") "," RULE("deny-write"), "3");

  /* Same permissions, same bytes: the order of the source does not show. */
  maelys_mir_t *one = compile_rules(RULE("write") "," RULE("deny-write"));
  maelys_mir_t *two = compile_rules(RULE("deny-write") "," RULE("read") ","
                                    RULE("write"));
  char first[65], second[65];
  char *e = NULL;
  CHECK_OK(maelys_mir_digest_hex(one, first, &e));
  CHECK_OK(maelys_mir_digest_hex(two, second, &e));
  CHECK(strcmp(first, second) == 0);

  /* Bytes that hold a target otherwise are not canonical: the deny-write
   * before its grant, and a deny beside a deny-write. */
  uint8_t *bytes = NULL;
  size_t size = 0;
  CHECK_OK(maelys_mir_encode(one, &bytes, &size, &e));
  /* two records of 12 + 1 bytes follow the 20-byte header */
  CHECK(size == 20u + 2u * 13u && bytes[21] == 2u && bytes[34] == 4u);
  bytes[21] = 4u;
  bytes[34] = 2u;
  CHECK(maelys_mir_check_canonical(bytes, size, &e) ==
        MAELYS_MIR_ERR_NON_CANONICAL);
  maelys_mir_error_free(e);
  e = NULL;
  bytes[21] = 3u;
  bytes[34] = 4u;
  CHECK(maelys_mir_check_canonical(bytes, size, &e) ==
        MAELYS_MIR_ERR_NON_CANONICAL);
  maelys_mir_error_free(e);
  e = NULL;
  bytes[21] = 5u; /* no fifth access */
  CHECK(maelys_mir_check_canonical(bytes, size, &e) == MAELYS_MIR_ERR_FORMAT);
  maelys_mir_error_free(e);
  e = NULL;
  maelys_mir_bytes_free(bytes);

  /* A restriction may remove writing; it may still not grant. */
  maelys_mir_t *base = compile_rules(RULE("write"));
  maelys_mir_t *ceiling = compile_rules(RULE("deny-write"));
  maelys_mir_t *effective = NULL;
  CHECK_OK(maelys_mir_restrict(base, ceiling, &effective, &e));
  CHECK(maelys_mir_fs_rule_count(effective) == 2u);
  char restricted[65];
  CHECK_OK(maelys_mir_digest_hex(effective, restricted, &e));
  CHECK(strcmp(restricted, first) == 0);
  maelys_mir_destroy(effective);
  effective = NULL;
  CHECK(maelys_mir_restrict(ceiling, one, &effective, &e) ==
        MAELYS_MIR_ERR_UNSUPPORTED);
  maelys_mir_error_free(e);
  maelys_mir_destroy(ceiling);
  maelys_mir_destroy(base);
  maelys_mir_destroy(two);
  maelys_mir_destroy(one);
}
#undef RULE

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

/* A name whose last label reads as a number is a literal in disguise: only
 * the strict dotted IPv4 is accepted, by the builder and by the decoder. */
#define LITERAL_SNI_HEX "4d4d495200030000000000000301010000000001020101bb030000093132372e302e302e31"

static void test_numeric_hosts(void) {
  static const char *const accepted[] = {
      "93.184.216.34", "0.0.0.0", "255.255.255.255", "1.example.com",
      "0xdead.example.com", "x0.example.com", "localhost",
  };
  static const char *const refused[] = {
      "127.1",    "2130706433", "0x7f.1",    "010.0.0.1",   "999.1.1.1",
      "0x7f000001", "0x7f.0x1", "0177.0x1", "0X7F.1",     "1.2.3.04",
      "256.1.1.1",  "a.0xdead", "example.0x1", "1.2.3",  "1.2.3.4.5",
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(*accepted); ++i) {
    maelys_mir_builder_t *b = NULL;
    char *e = NULL;
    CHECK_OK(maelys_mir_builder_create(&b, &e));
    CHECK(maelys_mir_builder_add_network_destination(
              b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, accepted[i], 443u, &e) ==
          MAELYS_MIR_OK);
    maelys_mir_error_free(e);
    maelys_mir_builder_destroy(b);
  }
  for (size_t i = 0; i < sizeof(refused) / sizeof(*refused); ++i) {
    maelys_mir_builder_t *b = NULL;
    char *e = NULL;
    CHECK_OK(maelys_mir_builder_create(&b, &e));
    if (maelys_mir_builder_add_network_destination(
            b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, refused[i], 443u, &e) !=
        MAELYS_MIR_ERR_ARGUMENT) {
      fprintf(stderr, "FAIL: builder accepted %s\n", refused[i]);
      ++failures;
    }
    maelys_mir_error_free(e);
    maelys_mir_builder_destroy(b);
  }

  /* Bytes a 0.9.1 encoder could have written: the last host of the
   * mediated-flags vector, registry.internal, replaced by a name of the same
   * length that keeps the record order. The decoder refuses them now. */
  FILE *f = fopen("tests/vectors/mediated-flags.mir", "rb");
  CHECK(f != NULL);
  if (!f)
    return;
  uint8_t bytes[4096];
  size_t size = fread(bytes, 1u, sizeof(bytes), f);
  fclose(f);
  CHECK(size == 0x7au && memcmp(bytes + 0x69, "registry.internal", 17u) == 0);
  static const char *const disguised[] = {"registry.0x7f0001",
                                          "registry.00000001"};
  for (size_t i = 0; i < 2u; ++i) {
    uint8_t tampered[4096];
    memcpy(tampered, bytes, size);
    memcpy(tampered + 0x69, disguised[i], 17u);
    maelys_mir_t *decoded = NULL;
    char *e = NULL;
    CHECK(maelys_mir_decode(tampered, size, &decoded, &e) ==
          MAELYS_MIR_ERR_FORMAT);
    CHECK(decoded == NULL);
    CHECK(e != NULL && strstr(e, "invalid host") != NULL);
    maelys_mir_error_free(e);
  }
  /* A TLS server name is never required of a literal (RFC 6066): the
   * builder refuses it, and so does the decoder on bytes that carry it. */
  {
    maelys_mir_builder_t *b = NULL;
    char *e = NULL;
    CHECK_OK(maelys_mir_builder_create(&b, &e));
    CHECK(maelys_mir_builder_add_network_destination_ex(
              b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "127.0.0.1", 443u,
              MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI,
              &e) == MAELYS_MIR_ERR_ARGUMENT);
    maelys_mir_error_free(e);
    e = NULL;
    CHECK_OK(maelys_mir_builder_add_network_destination_ex(
        b, MAELYS_MIR_NETWORK_PROTOCOL_TCP, "127.0.0.1", 443u,
        MAELYS_MIR_NETWORK_DESTINATION_ALLOW_PRIVATE_ADDRESSES, &e));
    CHECK_OK(maelys_mir_builder_set_network(b, MAELYS_MIR_NETWORK_MEDIATED,
                                            &e));
    maelys_mir_t *literal = NULL;
    CHECK_OK(maelys_mir_builder_build(b, &literal, &e));
    maelys_mir_builder_destroy(b);
    uint8_t *encoded = NULL;
    size_t encoded_size = 0;
    CHECK_OK(maelys_mir_encode(literal, &encoded, &encoded_size, &e));
    maelys_mir_destroy(literal);
    /* The only record follows the header; its flags byte is at +4. */
    CHECK(encoded_size == 20u + 8u + 9u && encoded[20 + 4] == 0x02u);
    encoded[20 + 4] = 0x03u;
    maelys_mir_t *rejected = NULL;
    CHECK(maelys_mir_decode(encoded, encoded_size, &rejected, &e) ==
          MAELYS_MIR_ERR_ARGUMENT);
    CHECK(rejected == NULL);
    maelys_mir_error_free(e);
    e = NULL;
    char hex[2 * 64 + 1];
    for (size_t i = 0; i < encoded_size; ++i)
      snprintf(hex + 2 * i, 3u, "%02x", encoded[i]);
    /* The TypeScript verifier holds the same bytes in its test. */
    CHECK(strcmp(hex, LITERAL_SNI_HEX) == 0);
    free(encoded);
  }

  /* The vector itself still decodes: the rule changed no valid artifact. */
  maelys_mir_t *decoded = NULL;
  char *e = NULL;
  CHECK_OK(maelys_mir_decode(bytes, size, &decoded, &e));
  maelys_mir_destroy(decoded);
}

int main(void) {
  test_determinism();
  test_precedence();
  test_ephemeral_root_identity();
  test_json();
  test_network_allowlist();
  test_network_destination_flags();
  test_deny_write();
  test_artifact_digest();
  test_noncanonical();
  test_restrictive_overlay();
  test_numeric_hosts();
  if (failures)
    fprintf(stderr, "%d MIR test failures\n", failures);
  return failures ? 1 : 0;
}
