# Changelog

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
