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

A resolved rule carries `missing`: `ERROR` for a path that existed at
resolution, `PROTECT_CREATE` for a deny whose target did not. The latter
makes the plan require `CAP_FS_PROTECT_CREATE`; see the
[permission contract](permission-contract.md). An absent deny is never
dropped.

`missing: skip` applies only when canonicalization reports `ENOENT` or
`ENOTDIR`, represented as `MAELYS_MIR_ERR_MISSING`. Permission errors, symlink
loops, and every other canonicalization failure remain hard errors. This is
required even for optional deny rules, whose silent removal could widen access.

Executable identity and arguments belong to the Executor's trusted
`ExecutionRequest`, not to MIR. A backend compiler combines that request with
the immutable SandboxPlan and backend context immediately before enforcement;
it must grant only the process-execution primitives necessary for that request.
## Resource bounds

The inputs are bounded, and so is the work done on them. Nothing here
introduces a limit: these are the limits that already exist and what they
cost.

| Bound | Value | Where |
|---|---|---|
| MIR document | 1 MiB | `MAELYS_MIR_MAX_BYTES` |
| filesystem rules of a MIR | 4 096 | `MAELYS_MIR_MAX_RULES` |
| network destinations of a MIR | 1 024 | `MAELYS_MIR_MAX_NETWORK_DESTINATIONS` |
| minimal-runtime roots of a host | 64 | `maelys_sandbox_policy_host_add_minimal_runtime_root` |
| resolved rules of a plan | 262 144 | 4 096 rules, each kept under 64 roots |

A rule on `minimal-runtime` resolves once per host root, so a plan may hold
64 times the rules of its MIR. That maximum is reachable from binary MIR and
from the C builder; the JSON source names the minimal runtime only as a
whole.

`maelys_sandbox_policy_compile` resolves each rule, searches the plan for a
precedence conflict and sorts it. With N resolved rules, the search and the
sort take a number of path comparisons proportional to N log N, each bounded
by the length of a path, and the search holds about 41 bytes per rule while
it runs. A reported conflict costs one further pass over the rules.

Measured with `make bench` on an Apple M2 Max, CPU seconds, for policies
without a conflict:

| Resolved rules | Conflict search | Through 0.6.0 (quadratic) |
|---|---|---|
| 4 096 | under 0.02 | 0.4 to 3.6 |
| 16 384 | under 0.07 | 6 to 61 |
| 262 144 | under 1.0 | not run; over 30 minutes by extrapolation |

The spread is the shape of the paths: siblings are cheapest, chains two
hundred components deep the most expensive. The largest plan, 262 144 rules
on absent targets, compiles in 3.7 s and holds 15 MB of paths and 6 MB of
rules. These are measurements of one machine, not guarantees, and they bound
no wall-clock time.

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
