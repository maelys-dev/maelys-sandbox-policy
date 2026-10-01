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

The libraries have no dependency. The `maelys-policy` command is built on
[maelys-cli](https://github.com/maelys-dev/maelys-cli), pinned with the
[agent-cli-spec](https://github.com/maelys-dev/agent-cli-spec) conformance kit
under `dependencies/`. Fetch both into a directory outside the repository and
name it in `MAELYS_DEPENDENCIES_DIR` (`maelys-release dependencies DIR --apply`
also refreshes an existing one):

```sh
export MAELYS_DEPENDENCIES_DIR="$HOME/.cache/maelys-sandbox-policy/dependencies"
sh scripts/checkout-dependencies.sh "$MAELYS_DEPENDENCIES_DIR"
make check
make asan
make ubsan
make tsan
```

## CLI

`maelys-policy` speaks `agent-cli/v2`: `describe --format json` returns its
catalog, every command answers with a JSON envelope under `--format json`, and
`compile` plans until it is given `--apply`. The generated reference is
[docs/cli.md](docs/cli.md).

```sh
build/bin/maelys-policy compile examples/workspace.json --output policy.mir --apply
build/bin/maelys-policy validate policy.mir        # exit 2 when not canonical MIR
build/bin/maelys-policy hash policy.mir
build/bin/maelys-policy inspect policy.mir
build/bin/maelys-policy artifact-hash examples/workspace.json
build/bin/maelys-policy restrict policy.mir ceiling.mir --output effective.mir --apply
build/bin/maelys-policy capabilities policy.mir    # what a backend must offer
build/bin/maelys-policy capabilities policy.mir --check --available fs-read   # exit 2 if some are missing
build/bin/maelys-policy resolve policy.mir --workspace "$PWD" --minimal-root /usr   # rules on this host
build/bin/maelys-policy evaluate policy.mir --workspace "$PWD" --minimal-root /usr --path "$PWD/src/main.c"
build/bin/maelys-policy contains parent.mir child.mir --workspace "$PWD" --minimal-root /usr   # exit 2 with a witness
build/bin/maelys-policy diff before.mir after.mir --workspace "$PWD" --minimal-root /usr --check   # exit 2 unless equivalent
build/bin/maelys-policy overlaps first.mir second.mir --workspace "$PWD" --minimal-root /usr
build/bin/maelys-policy describe --summary --format json --compact
```

`resolve`, `evaluate`, `contains`, `diff` and `overlaps` answer for one host: the directories given for the
symbolic roots, as they are when the command runs. Their output is a
diagnostic of that resolution, never a policy identity, and it proves
nothing about what a backend installed. `evaluate` takes `--path` as written,
as a resolved path: it follows no link.

`examples/workspace.json` denies `.git` with `missing: skip`. Where the
workspace has no `.git`, the resolved plan requires the backend capability
`fs-protect-create`; a backend that does not announce it refuses the launch
rather than run with the deny removed. See the
[permission contract](docs/permission-contract.md).

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
[C API contract](docs/api-contract.md), the normative
[permission contract](docs/permission-contract.md) and its
[corpus](corpus/permissions/README.md), [milestones](docs/milestones.md), the
normative [MIR v3 format](docs/mir-format-v3.md), and the published
[source schema](schemas/mir-source-v3.schema.json). The external architectural
influences are recorded in [design references](docs/references.md).

## License

Mozilla Public License 2.0 ([LICENSE](LICENSE)), like every Maelys repository.
