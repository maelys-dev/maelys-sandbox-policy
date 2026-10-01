# Milestones implemented through 0.7.0

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
- **M7 — Destination flags:** each mediated destination carries canonical
  `requireTlsSni` and `allowPrivateAddresses` decisions, both off by default.
  They reuse zero bytes of the MIR v3 record, so unflagged policies keep their
  digests and 0.4.x decoders reject flagged ones.

## Sandbox Policy track

- **S1 — Host context:** trusted workspace/temp/minimal-runtime roots are
  canonicalized separately from the MIR. Symlink escapes are rejected.
- **S2 — Capability support:** every requested primitive is mapped to an
  explicit backend capability and unsupported plans fail closed.
- **S3 — SandboxPlan:** symbolic MIR paths become absolute rules, in a stable
  order. The source MIR digest is carried into the plan.
- **S4 — Permission contract:** a deny is absolute and grants are additive,
  whatever the rule order; plans list grants, then denies. A reference
  evaluator and a shared corpus make the contract testable by consumers. A
  policy that the earlier most-specific-wins order read differently is
  refused instead of reinterpreted.
- **S5 — Containment:** whether one resolved plan grants nothing another
  does not, exactly for the two plans and with a witness per dimension;
  conflict search and containment in N log N over the resolved rules, with
  measured resource bounds.

Backends and process launch do not belong to this repository. Maelys Warden
consumes `SandboxPlan` through an adapter and owns Seatbelt/Bubblewrap
enforcement.
