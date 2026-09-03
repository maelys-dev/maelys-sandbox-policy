# Portable tooling over MIR v3

The v2.5 milestone is a tooling release, not a wire-format release. Canonical
MIR v3 bytes remain the sole decision identity.

```text
strict JSON source
       │
       ▼
same pure C compiler ─────── native CLI / C library
       │
       └──────────────────── WebAssembly browser module
       │
       ▼
canonical MIR v3 bytes ── SHA-256 ── decision digest
       │
       ├── deterministic JSON inspection (non-normative)
       └── independent TypeScript structural verification
```

## Build and verify

```sh
make check             # native compiler, CLI and frozen vectors
make wasm-check        # compile C with Emscripten and compare every byte
make reference-check   # build and run the TypeScript verifier
make conformance-check # all three gates
make playground-dist   # verify everything and emit a self-describing site bundle
```

`build/wasm/` contains:

- `maelys-policy.wasm`: the C compiler and canonical codec;
- `maelys-policy.mjs`: the generated Emscripten module;
- `index.mjs`: a small browser/Node wrapper returning MIR bytes, digest and
  inspection JSON;
- `playground-runtime.mjs`: compiler plus independent verifier integration.

`make playground-dist` produces `dist/playground/`. Its `assets.json` records
the exact byte size, SHA-256 and destination of every browser asset. The
directory is autonomous: Hermes can validate and synchronize it into a Yavena
site without executing this repository's build system.

```sh
hermes asset bundle-sync dist/playground/assets.json --repo ../maelys-sandbox-policy-site
hermes asset bundle-sync dist/playground/assets.json --repo ../maelys-sandbox-policy-site --apply
```

The first command is a plan. The second verifies the complete bundle before
the first write, updates the site atomically, and generates
`public/wasm/assets.lock.json` with the source version and verified digests.

## Conformance vectors

Each case in `tests/vectors/` freezes four artifacts:

- `NAME.source.json`: strict human source;
- `NAME.mir`: expected canonical bytes;
- `NAME.sha256`: expected decision digest;
- `NAME.inspect.json`: expected non-normative inspection.

Native C, WebAssembly and the TypeScript verifier consume the same files. A
change to canonical bytes therefore fails before it can become an accidental
format migration.

## TypeScript verifier boundary

`reference/typescript` parses and validates canonical MIR v3 and computes its
SHA-256 digest through Web Crypto. It does not compile JSON and is deliberately
not a second policy implementation. The playground uses it after the WASM
compiler so that the producer and verifier fail independently.
