CC ?= cc
AR ?= ar
EMCC ?= emcc
CFLAGS ?= -std=c11 -O2 -g
CPPFLAGS ?=
FEATURE_DEFS := -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
WARNINGS := -Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wstrict-prototypes
INCLUDES := -Iinclude -Isrc
BUILD := build
PREFIX ?= /usr/local
DESTDIR ?=
VERSION := $(shell sed -n '1p' VERSION)

# The command line is built on maelys-cli and speaks agent-cli/v2, whose
# conformance kit comes from agent-cli-spec. Both are pinned under
# dependencies/ and read under MAELYS_DEPENDENCIES_DIR, never from a sibling
# working copy: run 'sh scripts/checkout-dependencies.sh DIR' and export the
# lines it prints. maelys-release.conf declares `[dependencies] apart`, so the
# socle sets the variable in CI and in the release. The libraries and the WASM
# build need neither.
MAELYS_CLI_DIR ?= $(MAELYS_DEPENDENCIES_DIR)/maelys-cli
MAELYS_CLI_TAG := $(word 1,$(shell cat dependencies/maelys-cli.pin))
MAELYS_CLI_PIN := $(word 2,$(shell cat dependencies/maelys-cli.pin))
MAELYS_CLI_BUILD := $(abspath $(BUILD)/deps/maelys-cli)
MAELYS_CLI_LIB := $(MAELYS_CLI_BUILD)/lib/libmaelys_cli.a
MAELYS_CLI_EMBED := $(MAELYS_CLI_DIR)/tools/maelys-cli-embed
MAELYS_SPEC_DIR ?= $(MAELYS_DEPENDENCIES_DIR)/agent-cli-spec
MAELYS_SPEC_TAG := $(word 1,$(shell cat dependencies/agent-cli-spec.pin))
MAELYS_SPEC_PIN := $(word 2,$(shell cat dependencies/agent-cli-spec.pin))
GENERATED := $(BUILD)/generated
CLI_SCHEMAS := $(wildcard cli/schemas/*.json)
CLI_SCHEMA_SYMBOLS := $(foreach schema,$(CLI_SCHEMAS),\
	policy_$(subst -,_,$(basename $(notdir $(schema))))_schema=$(schema))

MIR_SRC := src/common.c src/sha256.c src/mir.c src/source_json.c src/inspect_json.c
POLICY_SRC := src/sandbox_policy.c src/permissions.c
MIR_OBJ := $(MIR_SRC:%.c=$(BUILD)/%.o)
POLICY_OBJ := $(POLICY_SRC:%.c=$(BUILD)/%.o)

.PHONY: all check clean asan ubsan tsan fuzz fuzz-build install wasm wasm-check reference-check conformance-check playground-dist \
	check-dependencies check-cli-contract check-spec-contract agent-cli-check
all: $(BUILD)/lib/libmaelys-mir.a $(BUILD)/lib/libmaelys-sandbox-policy.a $(BUILD)/bin/maelys-policy

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(FEATURE_DEFS) $(CFLAGS) $(WARNINGS) $(INCLUDES) -MMD -MP -c $< -o $@

$(BUILD)/lib/libmaelys-mir.a: $(MIR_OBJ)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(BUILD)/lib/libmaelys-sandbox-policy.a: $(POLICY_OBJ)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

check-dependencies:
	@test -n "$(MAELYS_DEPENDENCIES_DIR)$(MAELYS_CLI_DIR)" -a -f "$(MAELYS_CLI_DIR)/include/maelys/cli.h" || \
		{ echo "MAELYS_DEPENDENCIES_DIR is unset or holds no maelys-cli: run 'sh scripts/checkout-dependencies.sh DIR' and export the lines it prints" >&2; exit 1; }

check-cli-contract: check-dependencies
	@test "$$(git -C "$(MAELYS_CLI_DIR)" rev-parse HEAD)" = "$(MAELYS_CLI_PIN)" || \
		{ echo "maelys-cli must be pinned to $(MAELYS_CLI_TAG) ($(MAELYS_CLI_PIN))" >&2; exit 1; }
	@git -C "$(MAELYS_CLI_DIR)" diff --quiet "$(MAELYS_CLI_PIN)" -- || \
		{ echo "pinned maelys-cli checkout is modified" >&2; exit 1; }

check-spec-contract: check-dependencies
	@test -f "$(MAELYS_SPEC_DIR)/conformance/run.py" || \
		{ echo "MAELYS_SPEC_DIR must name agent-cli-spec" >&2; exit 1; }
	@test "$$(git -C "$(MAELYS_SPEC_DIR)" rev-parse HEAD)" = "$(MAELYS_SPEC_PIN)" || \
		{ echo "agent-cli-spec must be pinned to $(MAELYS_SPEC_TAG) ($(MAELYS_SPEC_PIN))" >&2; exit 1; }
	@test "$$(sed -n 1p "$(MAELYS_CLI_DIR)/dependencies/agent-cli-spec.pin")" = "$(MAELYS_SPEC_TAG)" || \
		{ echo "agent-cli-spec $(MAELYS_SPEC_TAG) is not the version maelys-cli $(MAELYS_CLI_TAG) targets" >&2; exit 1; }

# Only the command line links libmaelys_cli; the two libraries never do.
$(MAELYS_CLI_LIB): check-cli-contract
	$(MAKE) -C $(MAELYS_CLI_DIR) BUILD=$(MAELYS_CLI_BUILD) CC=$(CC) CPPFLAGS= \
		CFLAGS='$(CFLAGS)' $(MAELYS_CLI_LIB)

$(GENERATED)/policy_schemas.h: $(CLI_SCHEMAS) | check-dependencies
	@mkdir -p $(@D)
	sh $(MAELYS_CLI_EMBED) --header $(CLI_SCHEMA_SYMBOLS) >$@

$(GENERATED)/policy_schemas.c: $(CLI_SCHEMAS) | check-dependencies
	@mkdir -p $(@D)
	sh $(MAELYS_CLI_EMBED) $(CLI_SCHEMA_SYMBOLS) >$@

$(BUILD)/generated/policy_schemas.o: $(GENERATED)/policy_schemas.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/cli/maelys-policy.o: CPPFLAGS += -isystem $(MAELYS_CLI_DIR)/include -I$(GENERATED)
$(BUILD)/cli/maelys-policy.o: $(GENERATED)/policy_schemas.h | check-dependencies

$(BUILD)/bin/maelys-policy: $(BUILD)/cli/maelys-policy.o $(BUILD)/generated/policy_schemas.o \
		$(BUILD)/lib/libmaelys-sandbox-policy.a $(BUILD)/lib/libmaelys-mir.a $(MAELYS_CLI_LIB)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

# The contract's own kit drives the built binary from the outside: describe,
# every envelope and each command's declared output schema. It only reads.
agent-cli-check: $(BUILD)/bin/maelys-policy check-spec-contract
	python3 $(MAELYS_SPEC_DIR)/conformance/run.py $(abspath $(BUILD)/bin/maelys-policy)

$(BUILD)/tests/test_mir: $(BUILD)/tests/test_mir.o $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_sandbox_policy: $(BUILD)/tests/test_sandbox_policy.o $(BUILD)/lib/libmaelys-sandbox-policy.a $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_permissions: $(BUILD)/tests/test_permissions.o $(BUILD)/lib/libmaelys-sandbox-policy.a $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_sha256: $(BUILD)/tests/test_sha256.o $(BUILD)/src/sha256.o $(BUILD)/src/common.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

check: all $(BUILD)/tests/test_mir $(BUILD)/tests/test_sandbox_policy $(BUILD)/tests/test_permissions $(BUILD)/tests/test_sha256
	$(BUILD)/tests/test_mir
	$(BUILD)/tests/test_sandbox_policy
	$(BUILD)/tests/test_permissions corpus/permissions/cases
	$(BUILD)/tests/test_sha256
	sh tests/test_cli.sh $(BUILD)/bin/maelys-policy
	sh tests/test_vectors.sh $(BUILD)/bin/maelys-policy
	sh scripts/audit-boundaries.sh
	$(MAKE) agent-cli-check

wasm:
	@mkdir -p $(BUILD)/wasm
	$(EMCC) $(FEATURE_DEFS) -std=c11 -O3 $(WARNINGS) $(INCLUDES) \
		wasm/maelys_policy_wasm.c $(MIR_SRC) \
		-sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createMaelysPolicy \
		-sENVIRONMENT=web,node -sFILESYSTEM=0 -sALLOW_MEMORY_GROWTH=1 \
		-sMALLOC=emmalloc -sNO_EXIT_RUNTIME=1 --no-entry \
		-sEXPORTED_FUNCTIONS='["_maelys_wasm_compile_text","_maelys_wasm_reset","_maelys_wasm_mir_hex","_maelys_wasm_mir_size","_maelys_wasm_digest","_maelys_wasm_inspection","_maelys_wasm_error"]' \
		-sEXPORTED_RUNTIME_METHODS='["ccall","UTF8ToString"]' \
		-o $(BUILD)/wasm/maelys-policy.mjs
	cp wasm/browser-api.mjs $(BUILD)/wasm/index.mjs
	cp wasm/playground-runtime.mjs $(BUILD)/wasm/playground-runtime.mjs

wasm-check: all wasm
	node wasm/test-wasm.mjs

reference-check:
	npm --prefix reference/typescript ci --ignore-scripts
	npm --prefix reference/typescript run check

conformance-check: check wasm-check reference-check

playground-dist: conformance-check
	node scripts/build-playground-dist.mjs

asan:
	$(MAKE) clean
	$(MAKE) check CFLAGS='-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address'

ubsan:
	$(MAKE) clean
	$(MAKE) check CFLAGS='-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=undefined'

tsan:
	$(MAKE) clean
	$(MAKE) check CFLAGS='-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=thread'

FUZZ_SECONDS ?= 10

fuzz-build: $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(BUILD)/fuzz
	$(CC) $(FEATURE_DEFS) -std=c11 -O1 -g -fsanitize=fuzzer,address $(INCLUDES) fuzz/fuzz_decode.c $(MIR_SRC) -o $(BUILD)/fuzz/fuzz_decode
	$(CC) $(FEATURE_DEFS) -std=c11 -O1 -g -fsanitize=fuzzer,address $(INCLUDES) fuzz/fuzz_json.c $(MIR_SRC) -o $(BUILD)/fuzz/fuzz_json

# A bounded run, as the fleet's `make fuzz` is: it belongs in CI.
fuzz: fuzz-build
	$(BUILD)/fuzz/fuzz_decode -max_total_time=$(FUZZ_SECONDS)
	$(BUILD)/fuzz/fuzz_json -max_total_time=$(FUZZ_SECONDS)

$(BUILD)/pkgconfig/%.pc: pkgconfig/%.pc.in VERSION
	@mkdir -p $(@D)
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(VERSION)|g' $< > $@

install: all $(BUILD)/pkgconfig/maelys-mir.pc $(BUILD)/pkgconfig/maelys-sandbox-policy.pc
	install -d $(DESTDIR)$(PREFIX)/include/maelys $(DESTDIR)$(PREFIX)/lib/pkgconfig $(DESTDIR)$(PREFIX)/bin \
		$(DESTDIR)$(PREFIX)/share/doc/maelys-sandbox-policy \
		$(DESTDIR)$(PREFIX)/share/maelys-sandbox-policy/schemas
	install -m 0644 include/maelys/mir.h include/maelys/sandbox_policy.h $(DESTDIR)$(PREFIX)/include/maelys/
	install -m 0644 $(BUILD)/lib/libmaelys-mir.a $(BUILD)/lib/libmaelys-sandbox-policy.a $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 $(BUILD)/pkgconfig/maelys-mir.pc $(BUILD)/pkgconfig/maelys-sandbox-policy.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	install -m 0755 $(BUILD)/bin/maelys-policy $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 LICENSE README.md SECURITY.md docs/*.md \
		$(DESTDIR)$(PREFIX)/share/doc/maelys-sandbox-policy/
	install -m 0644 schemas/mir-source-v3.schema.json \
		$(DESTDIR)$(PREFIX)/share/maelys-sandbox-policy/schemas/
	install -d $(DESTDIR)$(PREFIX)/share/maelys-sandbox-policy/corpus/permissions/cases
	install -m 0644 corpus/permissions/README.md corpus/permissions/VERSION \
		$(DESTDIR)$(PREFIX)/share/maelys-sandbox-policy/corpus/permissions/
	install -m 0644 corpus/permissions/cases/*.case \
		$(DESTDIR)$(PREFIX)/share/maelys-sandbox-policy/corpus/permissions/cases/

clean:
	rm -rf $(BUILD)

-include $(MIR_OBJ:.o=.d) $(POLICY_OBJ:.o=.d) $(BUILD)/cli/maelys-policy.d $(wildcard $(BUILD)/tests/*.d)
