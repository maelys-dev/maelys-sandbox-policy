# Product and artifact naming

The product is **Maelys Sandbox Policy**. It owns portable, resolved sandbox
decisions and their compilation into immutable host-bound plans. It does not
launch or supervise processes and it contains no operating-system backend.

The names are deliberately split by audience:

| Surface | Canonical name |
|---|---|
| Product | Maelys Sandbox Policy |
| Repository | `maelys-sandbox-policy` |
| Website | `policy.maelys.dev` |
| CLI | `maelys-policy` |
| Distribution package | `maelys-sandbox-policy` |
| Portable binary format | Maelys Intermediate Representation (MIR), `.mir` |
| Format library | `libmaelys-mir`, `<maelys/mir.h>`, `maelys_mir_*` |
| Host-plan compiler | `libmaelys-sandbox-policy`, `<maelys/sandbox_policy.h>` |

MIR is a technical format inside the product, so its public format name and
version remain stable. The former generic `maelys-sandbox` compiler name is
removed in ABI 3 rather than retained as a compatibility alias: there are no
external consumers to preserve, and an alias would keep implying that this
library enforces an operating-system sandbox.

The responsibility boundary is:

```text
policy producer -> canonical MIR -> Sandbox Policy -> immutable SandboxPlan
                                                        |
                                                        v
                                            Warden adapter and backends
```

Maelys Datalog may produce a decision. Maelys Warden applies it and owns
process lifecycle, Seatbelt, Bubblewrap and receipts. Maelys Egress enforces
mediated network access. Maelys System supplies generic system mechanics.
