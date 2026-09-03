# Security policy

## Supported versions

Security fixes are provided for the latest published minor release. Maelys
Sandbox Policy is pre-1.0. MIR format compatibility is specified separately
from the C ABI: release 0.3.0 uses compiler ABI 3 and keeps MIR ABI 2 and MIR
format v3.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting under **Security → Advisories → Report a
vulnerability**.

Include the affected version, input policy or MIR bytes, operating system, a
minimal reproducer and the expected impact when available. Reports are
acknowledged within seven days. Confirmed issues are fixed privately, exercised
against the parser, canonicality, sanitizer and fuzzing gates, then disclosed
with the corresponding release. No bounty program is currently offered.

## Security boundary

Sandbox Policy validates and compiles a resolved decision. It does not launch a
process and is not an operating-system sandbox. Host roots, available backend
capabilities and mediator identity are trusted configuration. Untrusted policy
input cannot choose those values.

MIR decoding rejects non-canonical encodings. A valid release signature or
provenance attestation proves origin, not absence of vulnerabilities or correct
enforcement by a downstream backend.
