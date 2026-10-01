# Filesystem permission corpus

The normative cases of the SandboxPlan permission contract
(`MAELYS_SANDBOX_POLICY_PERMISSION_CONTRACT` 2). `VERSION` is the corpus
version; it moves when a case is added, removed or changes its expectation.

The corpus works on **resolved rules**, the level a backend receives. It
needs no filesystem: every path is absolute and already canonical.

## Contract

For one path, among the rules that apply to it:

| Applicable rules | Permission |
|---|---|
| at least one `deny` | `none` |
| no `deny`, at least one `write` | `read-write` |
| only `read` | `read` |
| none | `none` |

An `exact` rule applies to its own path; a `tree` rule to its path and to
every path under it, on segment boundaries. Rule order never matters, and
the precision of a path never beats a deny nor removes an inherited write.

## Case format

One case per `cases/*.case` file, UTF-8, one directive per line; `#` starts
a comment. Paths contain no whitespace.

```
rule <read|write|deny> <exact|tree> <absolute path>
query <absolute path> <none|read|read-write> <default-deny|deny-rule|write-rule|read-rule>
compile <accepted|refused before=<permission> after=<permission>>
```

- `query` lines state what the contract grants. They hold for every case,
  including the refused ones, and for every order of the rules.
- `compile accepted`: `maelys_sandbox_policy_compile` returns these rules.
- `compile refused`: the rules mean something else under the
  most-specific-wins order of contract 1, so compilation fails with
  `MAELYS_MIR_ERR_CONFLICT` rather than reinterpret them. `before` and `after`
  are the two permissions at the first path where they differ.

## Conformance of a backend

A consumer runs every `query` of the accepted cases against what it
enforces. A result is conformant when the permission is **enforced as
stated**, or when the plan is **refused before launch** because the backend
cannot guarantee it. A refusal is not an enforced case and is reported
apart. Refused cases never reach a backend.

What this corpus does not cover yet: a deny whose target does not exist
when the plan is resolved. Its guarantee is specified with the
`protect-create` requirement of resolved rules, in the release that
carries it.
