# Network destination contract

This document is normative. It says what a mediated policy allows a
process to connect to, for one request, whoever applies it. The policy and
the mediator must agree on every request of `corpus/destinations`; that is
what the corpus is for. This is destination contract 1.

The contract is written for two forms of destination: the **exact** name
that MIR v3 carries today, and the **wildcard** `*.suffix` that it does not
carry yet. The wildcard is defined here first, so that the format encodes a
meaning that already has cases and a mediator ready to prove it. Until the
format carries it, a policy with a wildcard cannot be compiled; the corpus
says so with `requires`.

## Names

A **canonical name** is 1 to 253 bytes of ASCII letters, digits and
hyphens, in labels of 1 to 63 bytes separated by single dots, no label
starting or ending with a hyphen, letters in lower case, no trailing dot.
It is what a MIR destination carries, and what every comparison of this
contract is made on.

- An IPv4 literal, `93.184.216.34`, has the form of a canonical name, and
  an exact destination may name one: the builder accepts it, and so does a
  mediator. The contract compares it as the string it is and does not
  define what a valid address is; connecting to it is connecting to that
  address, and the private-address rule applies to it like to any name. An
  IPv6 literal has no canonical form. No wildcard covers a literal: the
  last label of a suffix contains a letter.
- Internationalized names are compared as the ASCII they are written in:
  an `xn--` label is a label like any other, neither decoded nor validated.
- A request whose name has no canonical form is refused; whether a mediator
  lowers the case of what it received first is a matter of its protocol,
  outside this contract. The corpus names every request in canonical form.

A **wildcard destination** is written `*.suffix`, where `suffix` is a
canonical name of **at least two labels** whose **last label contains a
letter**, as every top-level domain does. Only that form exists: no `*`
alone, no `*` inside a label, no `*` elsewhere than as the whole first
label. A wildcard whose suffix breaks either rule is refused at the
source, as is a wildcard carrying `allowPrivateAddresses` (see
"Resolution"). The whole pattern, `*.` included, counts toward the 253
bytes.

## Requests

A request is a protocol, a canonical name, a port, and what the client
presented as TLS server name: one DNS name, or nothing. Whether the name
resolves to a **private address** is a property of the request at the time
it is answered: private means not globally routable (loopback, link-local,
RFC 1918, CGNAT, multicast, documentation ranges, IPv6 outside `2000::/3`,
an IPv4-mapped or NAT64 address judged by its IPv4).

## Matching

A destination **matches** a request when the protocols are equal, the ports
are equal, and:

- an exact destination: the names are equal;
- a wildcard `*.suffix`: the request name ends with `.suffix` and is
  strictly longer than that. It covers every depth under the suffix
  (`b.a.com` and `c.b.a.com` for `*.a.com`), never the suffix itself
  (`a.com`), and never a longer last label (`xa.com`).

A matching destination **admits** the request when both hold:

- if it carries `requireTlsSni`, the client presented exactly one TLS
  server name, of DNS type, equal to the request name — not to the pattern;
- if the request name resolves to a private address, the destination carries
  `allowPrivateAddresses`.

## Verdict

| Mode | Verdict |
|---|---|
| `none` | every request is refused |
| `direct` | every request is allowed, well formed or not: no mediator judges it |
| `mediated` | allowed when **at least one** matching destination admits it; refused otherwise |

Grants are additive, as for filesystem permissions: adding a destination
never removes an access, and the order of destinations never matters. When
several destinations match, each is judged under its own flags; it is
enough that one admits. Hence a wildcard without `requireTlsSni` beside an
exact name under it with the flag leaves that exact entry without effect: it
admits nothing the wildcard does not. Such an entry is not an error; it is
what `diff` will show as unchanged once destinations compare by coverage.

A policy names each (protocol, name or pattern, port) at most once. The
builder merges a repeated exact target into one destination, restrictively:
that is a property of building a policy, not of judging a request.

Refusals carry a reason, with stable identifiers. The first two judge the
request itself; the others are judged destination by destination:

| Reason | When |
|---|---|
| `network-none` | the mode is `none` |
| `malformed-name` | the request name has no canonical form, in `mediated` mode |
| `no-destination` | no destination matches |
| `sni-absent` | a matching destination requires a server name and none was presented |
| `sni-mismatch` | a matching destination requires a server name and the one presented differs from the request name |
| `private-address` | the name resolves to a private address and a matching destination does not allow it |

Each matching destination that does not admit the request has one reason,
the first of `sni-absent`, `sni-mismatch` and `private-address` that holds
for it. The reason reported is the first in the table among those of the
matching destinations. The verdict never depends on the reason, and a
mediator that reports a more specific one still conforms.

## Resolution

For an **exact** destination, a mediator may resolve the name once, when it
seals the policy, pin the addresses for the life of that policy, and refuse
the whole policy if one of them is private without `allowPrivateAddresses`.
That is a refusal before launch, conformant and reported as such; a request
that would be refused for `private-address` is then never made.

For a **wildcard**, the names are not known when the policy is sealed, so
resolution happens at the request, and three guarantees of the exact form do
not hold as they stand: no address is pinned for the life of the policy, the
policy digest covers no address, and a private address is refused per
request rather than at sealing. A mediator that applies wildcards proves, on
the corpus and in an execution:

| Obligation | What the mediator proves |
|---|---|
| `resolve-at-request` | the request name, and no other, is resolved when the request is made, and the connection goes to an address that resolution returned |
| `private-per-request` | every address of that resolution is checked; one private address refuses the request |
| `receipt-address` | the receipt of the connection carries the address actually contacted, since the policy digest no longer does |

Whoever controls the DNS of a name under the suffix chooses the address
contacted. `private-per-request` bounds that choice to global addresses;
nothing would bound it with `allowPrivateAddresses`, which is why a wildcard
never carries that flag. A mediator that cannot hold the three obligations
does not announce the wildcard capability and refuses such a policy before
launch.

## Restriction and comparison

Under `maelys_mir_restrict` and `plan_contains`, a destination of the
candidate is **covered** by a destination of the boundary when every
request the former matches, the latter matches: an exact name is covered by
an equal name or by a wildcard whose suffix it lies under; a wildcard is
covered by an equal wildcard or by one whose suffix lies above its own. A
finite set of exact names never covers a wildcard. Flags are then compared
as today: a covered destination exceeds the boundary when it allows a
private address the boundary does not, or drops a server-name requirement
the boundary has. The intersection kept by a restriction is the narrower of
the two destinations, with `requireTlsSni` combined by OR and
`allowPrivateAddresses` by AND.

## Known limits

- **No public suffix list.** Policy refuses a one-label suffix and nothing
  more: `*.co.uk` or `*.github.io` are accepted, and a wildcard on a
  multi-tenant suffix admits every tenant. A list of public suffixes changes
  over time and would make the identity of a policy depend on the day; the
  contract states the limit instead.
- **A wildcard admits the name, not what is behind it.** Without decrypting
  the connection, the mediator judges the requested name and the server
  name; the path, the method and the content are not its concern.
- **Dead entries are not refused.** An exact destination that a wildcard
  already covers with weaker flags admits nothing; the policy is accepted
  as written.

## Conformance

A mediator conforms when, for every request of the accepted cases of
`corpus/destinations`, it either **enforces** the verdict — the connection is
made exactly when the verdict is `allowed` — or **refuses the policy before
launch** because it cannot guarantee it. A refusal is reported as a refusal,
never counted as an enforced case. A case with `requires` names a capability
the mediator must announce to apply it; without it, refusing before launch
is the conformant answer.
