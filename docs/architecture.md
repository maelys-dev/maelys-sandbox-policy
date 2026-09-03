# Architecture

```text
policy decision side                         trusted enforcement side

Maelys Datalog ─┐
JSON compiler ──┼─► canonical MIR bytes ─► decode/canonicality check
C/Rust builder ─┘                                  │
                                                   ▼
                                      MIR + trusted HostContext
                                                   │
                                      capability/support check
                                                   │
                                                   ▼
                                             SandboxPlan
                                                   │
                                      executor adapter/backends
```

`libmaelys-mir` owns decisions already made: typed filesystem rules, network
mode, process-tree confinement, canonical encoding, and identity. It contains
no Datalog evaluator and no host configuration.

`libmaelys-sandbox-policy` is a portable compiler, not an enforcer. It combines an
immutable MIR with a trusted host context, resolves symbolic paths, verifies
that a prospective backend can enforce every requested primitive, and emits an
immutable absolute SandboxPlan. For mediated networking, the MIR carries the
resolved TCP hostname/port allowlist while the trusted host selects the
mediator implementation. The adapter preserves that allowlist into Executor;
it is part of both the MIR and Executor plan digests.

The executor owns process lifecycle, race-resistant handoff of the plan,
backend selection, and enforcement. Keeping launch primitives and OS backend
vocabulary outside this repository makes the boundary mechanically auditable
and allows Seatbelt, Bubblewrap, OCI, or future backends to consume the same
plan without changing MIR identity.

The final backend boundary is:

```text
ExecutionRequest ─┐
SandboxPlan ──────┼─► backend compiler ─► enforced OS plan ─► spawn
BackendContext ───┘
```

The executable and argv are therefore not MIR permissions. They are trusted
execution inputs. A Seatbelt or other default-deny backend derives the narrowly
required execution primitive at this boundary; it must never synthesize a
generic permission to execute arbitrary programs.

## Source format choice

Version 2 accepts JSON only. JSON provides one strict, duplicate-key-rejecting
source surface and a published schema. YAML can later be an external frontend
that emits the same canonical MIR; it is intentionally not another parser in
the runtime trust boundary.

## Provenance

Canonical MIR hashes enforcement decisions only. Human provenance may be
carried in a separately signed or hashed sidecar, but cannot alter enforcement
and is not accepted as canonical MIR input in version 2.
