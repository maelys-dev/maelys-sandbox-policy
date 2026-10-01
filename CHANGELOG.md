# Changelog

## Unreleased

- fix the cost of the precedence-conflict search of
  `maelys_sandbox_policy_compile`, which grew with the square of the resolved
  rule count: 0.4 to 3.6 s at 4 096 rules and, by extrapolation, more than
  half an hour for the 262 144 rules a MIR can resolve to under 64
  minimal-runtime roots. It now sorts paths by component and keeps the stack
  of the paths above, in N log N comparisons: under a second at that maximum.
  Accepted and refused policies, witnesses and diagnostics are unchanged; the
  earlier search is kept as the definition the new one is tested against;
- document the resource bounds of compilation in `docs/api-contract.md` and
  add `make bench`, which measures them. No limit is added or lowered.

## 0.6.0 — 2026-10-01

This release fixes what the filesystem rules of a policy grant. MIR bytes
and digests are unchanged, so nothing is silently reinterpreted: a policy the
earlier rule order read differently is refused. Read the breaking entries
before upgrading a consumer: ambiguous policies no longer compile to a plan,
a deny on an absent path now requires a backend capability, and the
SandboxPlan ABI is 5.

- **breaking (SandboxPlan, ABI 5):** the filesystem permissions of a plan are
  now a normative [contract](docs/permission-contract.md) independent of rule
  order: a deny is absolute, grants are additive, access is denied by default
  and the root mode grants nothing. Plans list grants, then denies;
- refuse instead of reinterpret: `maelys_sandbox_policy_compile` returns the
  new `MAELYS_MIR_ERR_CONFLICT` when the resolved rules would grant different
  permissions under the earlier most-specific-wins order (a grant under a
  denied tree, a `read` under a written tree, `exact` against `tree`), naming
  a witness path and the permission before and after. MIR bytes and digests
  are unchanged and no rule is dropped. A read-only subtree of a writable
  tree is no longer expressible;
- add the reference evaluator `maelys_sandbox_policy_plan_evaluate()` and the
  versioned corpus `corpus/permissions`, installed under
  `share/maelys-sandbox-policy/corpus`, for consumers to prove conformance;
- corpus version 3: every path a rule or a query names declares what it is
  on the host (`node file|directory|absent`), so that consumers build one
  tree and guess nothing; `exact` is shown on a directory (cases 04, 06, 22)
  and on a file (new cases 26, 27);
- **breaking:** a `deny` with `missing: skip` on an absent path is no longer
  dropped from the plan. It is kept with `missing = protect-create` on the
  resolved rule, named by its canonical existing prefix and literal remaining
  components, and the plan requires the new capability `fs-protect-create`.
  Without it compilation fails and no plan is returned.
  `examples/workspace.json` is therefore refused in a workspace without
  `.git` until a backend announces that capability; it used to compile and
  protect nothing. `missing: error` still fails, and an absent grant is still
  omitted;
- add `maelys-policy restrict BASE RESTRICTION --output FILE`, a plan/apply
  transaction over `maelys_mir_restrict`, and `maelys-policy capabilities
  POLICY [--check [--available CAPABILITY...]]`, which lists what a policy
  requires and what resolution may add, or checks a declared set and exits 2
  naming every missing capability. A declared set is a declaration, not a
  detection of the backend;
- add `maelys-policy resolve POLICY`, a report of the policy on one host: the
  resolved rules in plan order with their `missing` requirement, the grants
  omitted because absent, the capabilities the plan requires and, with
  `--check`, those a declared backend lacks. Whatever prevents the execution
  is listed as a blocker and exits 2; no rule is dropped to pass. The host
  context is given by typed options (`--workspace`, `--temp`, repeatable
  `--minimal-root`, `--mediator`), not a file;
- add `maelys-policy evaluate POLICY --path PATH`, the reference evaluator on
  the plan resolved for that context: the permission, its reason and the
  deciding rule. A policy that does not resolve gets no answer;
- add `maelys_sandbox_policy_plan_omitted_rule_count()` and `_at()`: the
  absent grants resolution left out of a plan;
- report every missing capability at once, by stable identifier
  (`maelys_sandbox_policy_capability_name()`), including those only resolution
  discovers (`maelys_sandbox_policy_resolved_capabilities()`);
- adopt maelys-release v0.62.2.

## 0.5.1 — 2026-09-27

- fix the Homebrew formula template, whose rendering `brew style` refused
  for its missing `typed` and `frozen_string_literal` headers: v0.5.0 was
  released on GitHub but its formula never reached the tap.

## 0.5.0 — 2026-09-27

- release through the shared maelys-release socle (v0.61.0): the generated
  `release.yml` and Homebrew tap workflow replace the hand-written release
  workflow, `scripts/cut-release.sh` and `scripts/update-tap-formula.sh`;
  `ci.yml` calls the socle's `check-product.yml`;
- `maelys-release.conf` declares `scripts/sync-version.sh`, which copies
  `VERSION` into `sandbox_policy.h` during a cut, and `make check` refuses a
  header that disagrees with `VERSION`;
- fix the Homebrew formula test, which still wrote a format v2 policy;
- **breaking (CLI):** `maelys-policy` is rebuilt on maelys-cli 0.5.30 and
  follows `agent-cli/v2`: `describe`, JSON envelopes, stable error codes,
  exit 2 for a completed validation with violations, shell completion and a
  generated reference in `docs/cli.md`. `compile` is a plan/apply transaction:
  `compile SOURCE --output FILE --apply` replaces `compile SOURCE -o FILE`,
  and an existing output is replaced only with `--replace`. `validate` exits 2
  on non-canonical MIR, which it used to report as 1. `--version` prints
  `maelys-policy X.Y.Z`; `version --field version` prints the bare version.
  The libraries, MIR and SandboxPlan are unchanged;
- pin maelys-cli and agent-cli-spec under `dependencies/`, read under
  `$MAELYS_DEPENDENCIES_DIR`; `make check` runs the agent-cli conformance kit
  against `maelys-policy`, and the Homebrew formula builds the pinned
  framework;
- add two per-destination mediation flags to the MIR v3 source and binary
  formats: `requireTlsSni` (the tunnelled ClientHello SNI must match the allowed
  host) and `allowPrivateAddresses` (a private resolution is permitted). Both
  default to `false`;
- keep every existing policy byte-identical: the flags occupy offset 4 of the
  network record, and the hostname length moves to a 16-bit field at offset
  6. Unflagged digests, inspection output and conformance vectors are unchanged;
  0.4.x decoders reject flagged policies;
- add `maelys_mir_builder_add_network_destination_ex()`,
  `maelys_mir_network_destination_at_ex()` and
  `maelys_sandbox_policy_plan_network_destination_at_ex()`. The original
  accessors return `MAELYS_MIR_ERR_UNSUPPORTED` for a flagged destination
  instead of dropping its flags;
- add capabilities `CAP_NETWORK_REQUIRE_TLS_SNI` and
  `CAP_NETWORK_PRIVATE_ADDRESSES`; a plan fails closed without them;
- compose restrictively: duplicates and `maelys_mir_restrict` combine SNI
  enforcement by OR and private-address permission by AND;
- add the `mediated-flags` native/WASM/TypeScript conformance vector;
- declare `python3` in `dependencies/packages`: `make check`, which the
  release packaging runs, drives the agent-cli conformance kit.

The change is additive, so MIR ABI 3 and Sandbox Policy ABI 4 are unchanged;
`MAELYS_MIR_NETWORK_DESTINATION_REQUIRE_TLS_SNI` serves as a feature test.

## 0.4.1 — 2026-09-03

- relicense from MIT to the Mozilla Public License 2.0, the license of every
  Maelys repository; no code change.

## 0.4.0 — 2026-08-29

- replace MIR/source format v2 with v3 and make the root mode a canonical,
  digest-covered decision: `read-only` or `ephemeral-write`;
- add opaque builder, inspection, SandboxPlan and capability-negotiation
  surfaces for `ROOT_EPHEMERAL_WRITE`;
- keep policy composition restrictive: an effective root is writable only
  when both the trusted base and the restriction allow ephemeral writes;
- bump MIR ABI to 3 and Sandbox Policy ABI to 4. No compatibility reader is
  retained because no external MIR v2 consumer exists.
- retain canonical MIR v3 bytes as the only decision identity;
- add deterministic non-normative JSON inspection and separate artifact hashing;
- add frozen native/WASM conformance vectors and an Emscripten build;
- add a dependency-free TypeScript MIR v3 verifier for browsers and Node.js;
- add a reproducible playground distribution with a checksummed Hermes bundle
  manifest;
- record why RFC 8785/JCS identity is deferred until independent producers need it.

## 0.3.0 — 2026-08-25

- rename the product and repository to Maelys Sandbox Policy;
- replace the `maelys-mir` user command with `maelys-policy`;
- replace `libmaelys-sandbox`, `<maelys/sandbox.h>` and the
  `maelys_sandbox_*` surface with `libmaelys-sandbox-policy`,
  `<maelys/sandbox_policy.h>` and `maelys_sandbox_policy_*`;
- bump the host-plan compiler ABI to 3 without changing MIR ABI 2, MIR format
  v2, source schema v2, canonical bytes or policy digests;
- document the product boundary with Maelys Datalog, Warden, Netd and System.

No compatibility alias is provided because no external consumer exists.

## 0.2.0 — 2026-08-23

- Replace source and binary format v1 with v2; no compatibility reader is kept.
- Add canonical mediated TCP destination allowlists to MIR and SandboxPlan.
- Include the allowlist in canonical MIR encoding, overlays, and SHA-256 identity.

## 0.1.1 — 2026-08-22

- distinguish an absent path from all other canonicalization failures, so
  `missing: skip` cannot suppress `EACCES`, `ELOOP`, or other I/O errors;
- verify the internal SHA-256 implementation with the NIST empty-string and
  `abc` vectors;
- retain the first JSON parser diagnostic instead of replacing and leaking it;
- release a parsed object key when its required `:` separator is absent;
- avoid passing a null base to `qsort` for an empty SandboxPlan;
- specify error-output initialization and the final
  `ExecutionRequest + SandboxPlan` backend compilation boundary.

## 0.1.0 — 2026-08-22

First contract release implementing MIR milestones M0–M4 and sandbox compiler
milestones S1–S3:

- opaque C11 APIs for canonical MIR and SandboxPlan objects;
- strict JSON source compiler and versioned JSON Schema;
- deterministic binary codec and SHA-256 policy identity;
- restrictive-only policy composition;
- trusted symbolic-root and mediated-network resolution;
- fail-closed capability negotiation and SandboxPlan production;
- CLI, unit/integration tests, fuzz targets, sanitizers, Docker/GCC coverage,
  package metadata, and architecture-boundary auditing.

No OS sandbox backend and no process launcher are included in this release.
