# C API contract

## Ownership

- `*_create`, `*_build`, `*_decode`, `*_compile_json`, `*_restrict`, and
  `maelys_sandbox_policy_compile` return newly owned opaque objects on success.
- Destroy objects with their matching `*_destroy` function exactly once.
- `maelys_mir_encode` returns owned bytes that must be released with
  `maelys_mir_bytes_free`, never directly with the caller's allocator.
- Diagnostics returned through `char **out_error` are optional and must be
  released with `maelys_mir_error_free`. When supplied, the pointed-to value
  must be `NULL` on entry; callers must release an earlier diagnostic before
  reusing the same variable. A call preserves its first diagnostic.
- Strings in `*_view` structures and the plan digest are borrowed. They remain
  valid only until the owning MIR or plan is destroyed.
- Builders copy string input. A built MIR does not retain its builder.

All output pointers are cleared before work begins. On failure, no object or
byte buffer is returned.

## Mutability and threads

Builders and host contexts are mutable and must not be accessed concurrently.
MIR and SandboxPlan objects are immutable after construction; independent
read-only calls are safe from multiple threads. Destroying an object while any
thread is reading it is invalid.

## Trust boundaries

`maelys_mir_compile_json` is a source-side convenience and is not required in
the runtime TCB. A runtime should accept binary MIR through `maelys_mir_decode`,
which rejects any structurally valid but non-canonical representation.

The host context is trusted deployment configuration. MIR symbolic roots never
select the workspace, temp directory, or minimal runtime paths themselves.
Likewise, MIR may request mediated networking and name canonical TCP
hostname/port destinations, but cannot select or configure the mediator. The
trusted host supplies a bounded mediator identifier; compilation fails closed
when mediated networking is requested without one.

`maelys_mir_restrict` accepts a complete restrictive ceiling, not a partial
configuration object. Its filesystem rules must all be `deny`. Network modes
are ordered from narrowest to broadest as `none < mediated < direct`; the
effective mode is the narrower of base and restriction. When both inputs are
mediated, the destination allowlists are intersected; an empty intersection
becomes `none`. For a destination kept by the intersection, `REQUIRE_TLS_SNI`
is combined with logical OR and `ALLOW_PRIVATE_ADDRESSES` with logical AND.
Process-tree confinement is combined with logical OR.

Destination flags are read through `maelys_mir_network_destination_at_ex()`
and `maelys_sandbox_policy_plan_network_destination_at_ex()`. The original
accessors have no field for them and return `MAELYS_MIR_ERR_UNSUPPORTED` for a
destination carrying any flag, so a consumer written before 0.5.0 cannot drop
one silently. A backend advertises `CAP_NETWORK_REQUIRE_TLS_SNI` and
`CAP_NETWORK_PRIVATE_ADDRESSES` only if its mediator enforces them; a plan
using either flag fails closed without the matching capability.

The permissions of a plan are defined by the
[permission contract](permission-contract.md), not by the order of its rules.
`maelys_sandbox_policy_plan_evaluate()` returns what the plan grants on one
resolved absolute path, with the reason and one deciding rule; it reads the
rules only. `maelys_sandbox_policy_compile` fails with
`MAELYS_MIR_ERR_CONFLICT`, and returns no plan, when the resolved rules would
grant different permissions under the earlier most-specific-wins order.

`maelys_sandbox_policy_compile` verifies declared capabilities and resolves current
paths, but it does not enforce them. Executor must consume the plan without
weakening it and account for filesystem changes between compilation and spawn.
The plan's mediator identifier is an opaque backend selection/configuration key,
not a command line and not a network endpoint controlled by the MIR producer.

`missing: skip` applies only when canonicalization reports `ENOENT` or
`ENOTDIR`, represented as `MAELYS_MIR_ERR_MISSING`. Permission errors, symlink
loops, and every other canonicalization failure remain hard errors. This is
required even for optional deny rules, whose silent removal could widen access.

Executable identity and arguments belong to the Executor's trusted
`ExecutionRequest`, not to MIR. A backend compiler combines that request with
the immutable SandboxPlan and backend context immediately before enforcement;
it must grant only the process-execution primitives necessary for that request.
## Inspection and artifact hashing

`maelys_mir_inspect_json()` produces a deterministic JSON view of the resolved
model. It is designed for diagnostics, playgrounds and human review. It is not
an input to policy identity and must never be signed or compared as a substitute
for the canonical MIR bytes.

`maelys_mir_digest_hex()` hashes the canonical encoding of a resolved MIR and
therefore returns the decision identity. `maelys_mir_artifact_digest_hex()`
hashes arbitrary bytes and is intended for source files, packages and
provenance records. The two functions are separate so an artifact hash cannot
silently acquire policy semantics.
