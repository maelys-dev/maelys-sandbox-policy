# Maelys Sandbox Policy

Portable policy IR and sandbox-plan compiler in pure C11.

```text
JSON source ─► libmaelys-mir ─► canonical MIR ─► libmaelys-sandbox-policy
                                                        │
                                                        ▼
                                                   SandboxPlan
                                                        │
                                                        ▼
                                                Maelys Warden backends
```

The repository converges three useful ideas without copying their product
formats: Codex's typed permission entries and special roots, Anthropic SRT's
strict validation and fail-closed posture, and scode's restrictive composition,
inspectability, and final-deny ordering. Provenance is deliberately kept out of
the canonical policy identity; it can later travel as a non-authoritative
sidecar.

MIR is a resolved decision, not a policy language. JSON is accepted only by the
offline/source compiler. Runtime consumers accept canonical MIR bytes and never
silently normalize them.

Sandbox Policy compiles decisions; it does not enforce an operating-system
sandbox. Maelys Warden consumes the resulting immutable plan and owns process
lifecycle, Seatbelt, Bubblewrap and execution receipts.

## Build and test

```sh
make check
make asan
make ubsan
make tsan
```

## CLI

```sh
build/bin/maelys-policy compile examples/workspace.json -o policy.mir
build/bin/maelys-policy validate policy.mir
build/bin/maelys-policy hash policy.mir
build/bin/maelys-policy inspect policy.mir
build/bin/maelys-policy artifact-hash examples/workspace.json
```

## Portable tooling (the v2.5 milestone)

MIR format v3 remains the normative identity format. The portable-tooling
milestone adds a WebAssembly build of the same C compiler, frozen native/WASM
conformance vectors, a dependency-free TypeScript verifier, and a deterministic
JSON inspection projection. The tooling was migrated with the normative v3
producer and does not introduce a second canonical identity.

```sh
make conformance-check
make playground-dist
```

See [portable tooling](docs/portable-tooling.md) and the
[identity decision record](docs/adr-0001-mir-v3-identity.md).

See the [architecture](docs/architecture.md),
[C API contract](docs/api-contract.md), [milestones](docs/milestones.md), the
normative [MIR v3 format](docs/mir-format-v3.md), and the published
[source schema](schemas/mir-source-v3.schema.json). The external architectural
influences are recorded in [design references](docs/references.md).

## License

Mozilla Public License 2.0 ([LICENSE](LICENSE)), like every Maelys repository.
