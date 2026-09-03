#ifndef MAELYS_MIR_H
#define MAELYS_MIR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAELYS_MIR_FORMAT_VERSION 3u
#define MAELYS_MIR_ABI_VERSION 3u
#define MAELYS_MIR_DIGEST_HEX_SIZE 65u
#define MAELYS_MIR_INSPECTION_FORMAT_VERSION 1u
#define MAELYS_MIR_MAX_BYTES (1024u * 1024u)
#define MAELYS_MIR_MAX_RULES 4096u
#define MAELYS_MIR_MAX_STRING_BYTES 4096u
#define MAELYS_MIR_MAX_NETWORK_DESTINATIONS 1024u
#define MAELYS_MIR_MAX_NETWORK_HOST_BYTES 253u

typedef struct maelys_mir maelys_mir_t;
typedef struct maelys_mir_builder maelys_mir_builder_t;

typedef enum maelys_mir_result {
  MAELYS_MIR_OK = 0,
  MAELYS_MIR_ERR_ARGUMENT = 1,
  MAELYS_MIR_ERR_MEMORY = 2,
  MAELYS_MIR_ERR_FORMAT = 3,
  MAELYS_MIR_ERR_LIMIT = 4,
  MAELYS_MIR_ERR_NON_CANONICAL = 5,
  MAELYS_MIR_ERR_IO = 6,
  MAELYS_MIR_ERR_UNSUPPORTED = 7,
  MAELYS_MIR_ERR_MISSING = 8
} maelys_mir_result_t;

typedef enum maelys_mir_fs_access {
  MAELYS_MIR_FS_READ = 1,
  MAELYS_MIR_FS_WRITE = 2,
  MAELYS_MIR_FS_DENY = 3
} maelys_mir_fs_access_t;

typedef enum maelys_mir_path_root {
  MAELYS_MIR_ROOT_MINIMAL_RUNTIME = 1,
  MAELYS_MIR_ROOT_WORKSPACE = 2,
  MAELYS_MIR_ROOT_TEMP = 3,
  MAELYS_MIR_ROOT_HOST = 4
} maelys_mir_path_root_t;

typedef enum maelys_mir_path_scope {
  MAELYS_MIR_SCOPE_EXACT = 1,
  MAELYS_MIR_SCOPE_TREE = 2
} maelys_mir_path_scope_t;

typedef enum maelys_mir_missing_path {
  MAELYS_MIR_MISSING_ERROR = 1,
  MAELYS_MIR_MISSING_SKIP = 2
} maelys_mir_missing_path_t;

typedef enum maelys_mir_network_mode {
  MAELYS_MIR_NETWORK_NONE = 1,
  MAELYS_MIR_NETWORK_DIRECT = 2,
  MAELYS_MIR_NETWORK_MEDIATED = 3
} maelys_mir_network_mode_t;

typedef enum maelys_mir_network_protocol {
  MAELYS_MIR_NETWORK_PROTOCOL_TCP = 1
} maelys_mir_network_protocol_t;

typedef enum maelys_mir_root_mode {
  MAELYS_MIR_ROOT_READ_ONLY = 1,
  MAELYS_MIR_ROOT_EPHEMERAL_WRITE = 2
} maelys_mir_root_mode_t;

typedef struct maelys_mir_network_destination_view {
  maelys_mir_network_protocol_t protocol;
  const char *host;
  uint16_t port;
} maelys_mir_network_destination_view_t;

typedef struct maelys_mir_fs_rule_view {
  maelys_mir_fs_access_t access;
  maelys_mir_path_root_t root;
  maelys_mir_path_scope_t scope;
  maelys_mir_missing_path_t missing;
  const char *relative;
} maelys_mir_fs_rule_view_t;

void maelys_mir_error_free(char *error);
void maelys_mir_bytes_free(uint8_t *bytes);
const char *maelys_mir_result_name(maelys_mir_result_t result);

maelys_mir_result_t
maelys_mir_builder_create(maelys_mir_builder_t **out_builder, char **out_error);
void maelys_mir_builder_destroy(maelys_mir_builder_t *builder);
maelys_mir_result_t maelys_mir_builder_add_fs_rule(
    maelys_mir_builder_t *builder, maelys_mir_fs_access_t access,
    maelys_mir_path_root_t root, const char *relative,
    maelys_mir_path_scope_t scope, maelys_mir_missing_path_t missing,
    char **out_error);
maelys_mir_result_t
maelys_mir_builder_set_network(maelys_mir_builder_t *builder,
                               maelys_mir_network_mode_t mode,
                               char **out_error);
maelys_mir_result_t
maelys_mir_builder_set_root_mode(maelys_mir_builder_t *builder,
                                 maelys_mir_root_mode_t mode,
                                 char **out_error);
maelys_mir_result_t maelys_mir_builder_add_network_destination(
    maelys_mir_builder_t *builder,
    maelys_mir_network_protocol_t protocol,
    const char *host,
    uint16_t port,
    char **out_error);
maelys_mir_result_t
maelys_mir_builder_set_process_tree_required(maelys_mir_builder_t *builder,
                                             int required, char **out_error);
maelys_mir_result_t maelys_mir_builder_build(maelys_mir_builder_t *builder,
                                             maelys_mir_t **out_mir,
                                             char **out_error);

void maelys_mir_destroy(maelys_mir_t *mir);
size_t maelys_mir_fs_rule_count(const maelys_mir_t *mir);
maelys_mir_result_t maelys_mir_fs_rule_at(const maelys_mir_t *mir, size_t index,
                                          maelys_mir_fs_rule_view_t *out_rule);
maelys_mir_network_mode_t maelys_mir_network(const maelys_mir_t *mir);
maelys_mir_root_mode_t maelys_mir_root_mode(const maelys_mir_t *mir);
size_t maelys_mir_network_destination_count(const maelys_mir_t *mir);
maelys_mir_result_t maelys_mir_network_destination_at(
    const maelys_mir_t *mir,
    size_t index,
    maelys_mir_network_destination_view_t *out_destination);
int maelys_mir_process_tree_required(const maelys_mir_t *mir);

maelys_mir_result_t maelys_mir_encode(const maelys_mir_t *mir,
                                      uint8_t **out_bytes, size_t *out_size,
                                      char **out_error);
maelys_mir_result_t maelys_mir_decode(const uint8_t *bytes, size_t size,
                                      maelys_mir_t **out_mir, char **out_error);
maelys_mir_result_t maelys_mir_check_canonical(const uint8_t *bytes,
                                               size_t size, char **out_error);
maelys_mir_result_t
maelys_mir_digest_hex(const maelys_mir_t *mir,
                      char out_hex[MAELYS_MIR_DIGEST_HEX_SIZE],
                      char **out_error);

/* Hash arbitrary artifact bytes. This is intentionally separate from
 * maelys_mir_digest_hex(): only canonical MIR bytes carry decision identity. */
maelys_mir_result_t maelys_mir_artifact_digest_hex(
    const uint8_t *bytes, size_t size,
    char out_hex[MAELYS_MIR_DIGEST_HEX_SIZE], char **out_error);

/* Produce a stable, human-readable JSON projection of a resolved MIR. The
 * projection is non-normative: policy identity remains SHA-256 over canonical
 * MIR v3 bytes, never over this JSON. Free the result with
 * maelys_mir_bytes_free(). */
maelys_mir_result_t maelys_mir_inspect_json(const maelys_mir_t *mir,
                                            uint8_t **out_json,
                                            size_t *out_size,
                                            char **out_error);

/*
 * Compose an untrusted/project restriction over a trusted base policy.
 * The restriction may add deny rules, narrow network access, or require
 * process-tree confinement. Any filesystem grant is rejected.
 */
maelys_mir_result_t maelys_mir_restrict(const maelys_mir_t *base,
                                        const maelys_mir_t *restriction,
                                        maelys_mir_t **out_effective,
                                        char **out_error);

/* Strict human-source compiler. JSON is input only; MIR remains canonical
 * binary. */
maelys_mir_result_t maelys_mir_compile_json(const uint8_t *json, size_t size,
                                            maelys_mir_t **out_mir,
                                            char **out_error);

#ifdef __cplusplus
}
#endif

#endif
