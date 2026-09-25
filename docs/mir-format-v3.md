# Maelys MIR binary format v3

All integers are unsigned and big-endian. The maximum accepted document size
is 1 MiB. Strings are shortest-form UTF-8 without NUL and are not terminated on
the wire. Version 3 replaces version 2; the decoder accepts only version 3.

## Header (20 bytes)

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII magic `MMIR` |
| 4 | 2 | format version, exactly `3` |
| 6 | 2 | flags, exactly zero |
| 8 | 4 | filesystem record count |
| 12 | 1 | network: `1 none`, `2 direct`, `3 mediated` |
| 13 | 1 | process-tree confinement: `0 disabled`, `1 required` |
| 14 | 1 | root mode: `1 read-only`, `2 ephemeral-write` |
| 15 | 1 | reserved, exactly zero |
| 16 | 4 | network destination record count |

## Filesystem record

Each record has a 12-byte prefix followed by `path_length` path bytes.

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 1 | record kind, exactly `1` |
| 1 | 1 | access: `1 read`, `2 write`, `3 deny` |
| 2 | 1 | root: `1 minimal-runtime`, `2 workspace`, `3 temp`, `4 host` |
| 3 | 1 | scope: `1 exact`, `2 tree` |
| 4 | 1 | missing: `1 error`, `2 skip` |
| 5 | 3 | reserved, exactly zero |
| 8 | 4 | path length |
| 12 | N | normalized path bytes |

Filesystem records are sorted by `(root, path, scope, missing, access)`. For an
identical target, `deny > write > read`. Filesystem access is deny-default and
write implies read.

## Network destination record

Every network record has an 8-byte prefix followed by `host_length` ASCII bytes.

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 1 | record kind, exactly `2` |
| 1 | 1 | protocol, exactly `1` (TCP) |
| 2 | 2 | destination port, `1..65535` |
| 4 | 1 | destination flags, see below; unknown bits are rejected |
| 5 | 1 | reserved, exactly zero |
| 6 | 2 | hostname length, `1..253` |
| 8 | N | canonical lowercase DNS hostname |

Destination flags:

| Bit | Source key | Meaning when set |
|---:|---|---|
| `0x01` | `requireTlsSni` | the mediator must check that the TLS ClientHello SNI inside the tunnel matches the allowed host |
| `0x02` | `allowPrivateAddresses` | the host may resolve to a private address; otherwise such resolutions are refused |

Both flags default to clear. Network records exist exactly when the mode is
`mediated`, and that mode requires at least one record. They are sorted by
`(host, protocol, port)` and duplicates are eliminated. A duplicate destination
with different flags is merged restrictively: `requireTlsSni` is kept if
either entry sets it, `allowPrivateAddresses` only if both do. `none` and
`direct` forbid destination records.

### Compatibility of destination flags (0.5.0)

Up to 0.4.x, offsets 4..7 held a 32-bit hostname length. Because hostnames
never exceed 253 bytes, offsets 4..6 were always zero, so a record without
flags is byte-identical under both layouts and every existing policy keeps its
digest. A record with any flag reads, under the 0.4.x layout, as a hostname
longer than 253 bytes, so a 0.4.x decoder rejects it: an older consumer fails
closed instead of silently dropping a mediation constraint.

## Canonicality and identity

There are no trailing bytes, unknown flags, unknown records, or alternative
integer encodings. A decoder reconstructs the model, re-encodes it, and accepts
the input only if the bytes are identical. Policy identity is lowercase SHA-256
over the complete canonical byte sequence, including every network destination.
The root mode is part of those bytes: changing the writable-root decision
always changes the policy digest.

`missing: skip` applies only to `ENOENT` and `ENOTDIR`; permission failures,
symlink loops, and other canonicalization errors remain hard failures.
