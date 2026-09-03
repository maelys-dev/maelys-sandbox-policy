# Milestones implemented through 0.4.0

## MIR track

- **M0 — Contract:** opaque C ABI, bounded input, deny-default source schema,
  decision/enforcement separation.
- **M1 — Model and builder:** typed filesystem, network and process decisions;
  lexical path normalization; exact-target precedence `deny > write > read`;
  restrictive-only overlay composition for untrusted project policy.
- **M2 — Strict codec:** endian-defined binary v3, explicit lengths, strict UTF-8,
  no trailing bytes, bounded records and strings.
- **M3 — Canonical identity:** normative record order, semantic de-duplication,
  decode rejects non-canonical bytes, SHA-256 over the exact MIR bytes.
- **M4 — Source toolchain:** strict JSON compiler, published Draft 2020-12 schema,
  `compile`, `validate`, `hash`, and `dump` CLI operations.
- **M5 — Mediated destinations:** canonical TCP hostname/port allowlists in the
  JSON source, binary MIR, digest, SandboxPlan, and Executor adapter.
- **M6 — Root disposition:** MIR v3 makes `read-only` versus
  `ephemeral-write` a canonical, digest-covered decision. Scratch sizing and
  overlay implementation remain execution concerns and do not enter policy.

## Sandbox Policy track

- **S1 — Host context:** trusted workspace/temp/minimal-runtime roots are
  canonicalized separately from the MIR. Symlink escapes are rejected.
- **S2 — Capability support:** every requested primitive is mapped to an
  explicit backend capability and unsupported plans fail closed.
- **S3 — SandboxPlan:** symbolic MIR paths become absolute rules. The stable
  plan order is broad-to-specific, with exact rules after tree rules and
  `deny` after grants at equal specificity, so last-match backends can retain
  the normative precedence. The source MIR digest is carried into the plan.

Backends and process launch do not belong to this repository. Maelys Warden
consumes `SandboxPlan` through an adapter and owns Seatbelt/Bubblewrap
enforcement.
