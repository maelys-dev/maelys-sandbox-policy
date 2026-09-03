# ADR 0001: retain binary MIR v3 as decision identity

Status: accepted

## Decision

Policy identity remains lowercase SHA-256 over the complete canonical MIR v3
byte sequence. A deterministic JSON projection may be emitted for inspection,
but it is explicitly non-normative. RFC 8785/JCS is not introduced as a second
canonical representation.

## Rationale

An independent producer must reproduce policy normalization, ordering,
deduplication, precedence and defaults before serialization. Replacing the last
binary encoding step with JCS does not remove that semantic work. It would add
a second canonical form and a permanent binary/JSON equivalence invariant while
providing little benefit to current consumers.

DSSE and in-toto can attest arbitrary bytes and digests, so they can reference
canonical MIR v3 directly. Human readability is provided by `inspect`; browser
portability is provided by the WebAssembly build; independent verification is
provided by the TypeScript reference verifier.

## Reopening criterion

Reconsider a new identity format only when multiple independent ecosystems must
produce canonical policies and their decision digests without using the C
library or its WebAssembly build. Verification alone is not sufficient reason.
