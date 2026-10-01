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
| no `deny`, a `write` and no `deny-write` | `read-write` |
| no `deny`, a `read`, or a `write` with a `deny-write` | `read` |
| no `read` nor `write` | `none` |

An `exact` rule applies to its own path; a `tree` rule to its path and to
every path under it, on segment boundaries. Rule order never matters, and
the precision of a path never beats a deny nor removes an inherited write.

## Case format

One case per `cases/*.case` file, UTF-8, one directive per line; `#` starts
a comment. Paths contain no whitespace.

```
rule <read|write|deny|deny-write> <exact|tree> <absolute path> [protect-create]
node <file|directory|absent> <absolute path>
requires <capability>
query <absolute path> <none|read|read-write> <default-deny|deny-rule|write-rule|read-rule|deny-write-rule>
compile <accepted|refused before=<permission> after=<permission>>
```

- `node` states what a path is on the host, so that a consumer builds the
  same tree as every other and guesses nothing. Every path named by a `rule`
  or a `query` has exactly one `node` line; an ancestor that no line names is
  a directory. Nothing lies beneath a `file`, and only `absent` paths lie
  beneath an `absent` one. A rule target is `absent` exactly when the rule is
  `protect-create`, which only a `deny` or a `deny-write` may be. The contract itself ignores these types: a rule applies
  to a path whatever it is.
- `protect-create` marks a deny whose target did not exist when the plan was
  resolved (`MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE`). It decides like
  any deny. `requires fs-protect-create` states that the plan needs that
  capability, which it does exactly when a rule carries the mark.
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

An `exact` rule names one path and nothing under it, whatever its type. On
a **directory** that means the directory node alone, none of its entries
(cases 04, 06 and 22): a backend that cannot confine a rule to one directory
node refuses those plans, which is conformant. On a **file** (cases 26 and
27) there is nothing under it to exclude.

### What a backend proves for a `deny` or a `deny-write`

Answering the queries is not enough for a rule that removes access: its
target lies in a tree the sandboxed process may write. For each `deny` and
`deny-write` rule whose target exists, a backend that enforces the case
also proves, in an execution under the plan:

| Obligation | What the backend proves |
|---|---|
| `write` | opening the target, or a file under it, for writing is refused; under a `tree` rule, so is creating or removing an entry under it |
| `metadata` | changing the metadata of the target is refused: mode, times, extended attributes |
| `remove` | removing the target is refused |
| `rename-replace` | renaming the target, and renaming something else over it, is refused |
| `ancestor-rename` | after its writable ancestor is renamed, what the rule protected is still protected under its new name |

The identifiers are stable: a report names an obligation by them.

`ancestor-rename` renames one path: the nearest ancestor of the target,
strictly above it, whose permission is `read-write` and which lies strictly
below the target of a `write tree` rule. Those are the paths the plan lets
the process rename. The target of a `write tree` rule is not one of them
unless another `write tree` rule covers it from above: its parent is not
writable. When no ancestor qualifies, the obligation does not apply. It
applies in case 36 (`/w/project`) and in no other case of this version: in
case 28 the only ancestor, `/workspace`, is the target of the write rule.

A backend that cannot hold every obligation that applies refuses the plan
before launch. These are obligations of the execution, not `query` lines:
they follow from the `rule` and `node` lines of each accepted case, and the
corpus states them once, here.

**Known limit.** A hard link to a protected file that exists before the
launch, elsewhere in a writable tree, still lets that file be written
through the other name. The contract does not cover it, for `deny` as for
`deny-write`, unless a backend checks link counts and says so.

For a `protect-create` rule, enforcing means more than answering the
queries: the backend keeps the path from being created, linked or renamed
into place for the whole execution. A backend that does not announce
`fs-protect-create` refuses the plan before launch, which is conformant and
reported apart. The corpus states the requirement; it cannot prove that
guarantee, which each backend demonstrates with its own tests.
