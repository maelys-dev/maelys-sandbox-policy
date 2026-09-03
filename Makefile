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

MIR_SRC := src/common.c src/sha256.c src/mir.c src/source_json.c src/inspect_json.c
POLICY_SRC := src/sandbox_policy.c
MIR_OBJ := $(MIR_SRC:%.c=$(BUILD)/%.o)
POLICY_OBJ := $(POLICY_SRC:%.c=$(BUILD)/%.o)

.PHONY: all check clean asan ubsan tsan fuzz install wasm wasm-check reference-check conformance-check playground-dist
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

$(BUILD)/bin/maelys-policy: $(BUILD)/cli/maelys-policy.o $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_mir: $(BUILD)/tests/test_mir.o $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_sandbox_policy: $(BUILD)/tests/test_sandbox_policy.o $(BUILD)/lib/libmaelys-sandbox-policy.a $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/tests/test_sha256: $(BUILD)/tests/test_sha256.o $(BUILD)/src/sha256.o $(BUILD)/src/common.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

check: all $(BUILD)/tests/test_mir $(BUILD)/tests/test_sandbox_policy $(BUILD)/tests/test_sha256
	$(BUILD)/tests/test_mir
	$(BUILD)/tests/test_sandbox_policy
	$(BUILD)/tests/test_sha256
	sh tests/test_cli.sh $(BUILD)/bin/maelys-policy
	sh tests/test_vectors.sh $(BUILD)/bin/maelys-policy
	sh scripts/audit-boundaries.sh

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

fuzz: $(BUILD)/lib/libmaelys-mir.a
	@mkdir -p $(BUILD)/fuzz
	$(CC) $(FEATURE_DEFS) -std=c11 -O1 -g -fsanitize=fuzzer,address $(INCLUDES) fuzz/fuzz_decode.c $(MIR_SRC) -o $(BUILD)/fuzz/fuzz_decode
	$(CC) $(FEATURE_DEFS) -std=c11 -O1 -g -fsanitize=fuzzer,address $(INCLUDES) fuzz/fuzz_json.c $(MIR_SRC) -o $(BUILD)/fuzz/fuzz_json

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

clean:
	rm -rf $(BUILD)

-include $(MIR_OBJ:.o=.d) $(POLICY_OBJ:.o=.d)
