# Filesystem permission contract

This page is normative for what the filesystem rules of a policy grant. It
is contract **2** (`MAELYS_SANDBOX_POLICY_PERMISSION_CONTRACT`), introduced
with Sandbox Policy ABI 5. The reference evaluator
`maelys_sandbox_policy_plan_evaluate()` and the cases of
[`corpus/permissions`](../corpus/permissions/README.md) make it testable;
where either disagrees with this text, this text wins and the other is
corrected.

## The contract

For one resolved absolute path, take the rules of the plan that **apply**
to it:

| Applicable rules | Permission |
|---|---|
| at least one `deny` | none |
| no `deny`, a `write` and no `deny-write` | read and write |
| no `deny`, a `read`, or a `write` with a `deny-write` | read |
| no `read` nor `write` | none |

- An `exact` rule applies to its own path. A `tree` rule applies to its
  path and to every path under it; `/a` is not an ancestor of `/ab`.
- **A deny is absolute.** No grant reopens a denied path, however precise.
- **A deny-write removes writing and grants nothing.** It is absolute too:
  no write grant, however precise, reopens writing beneath it. What it
  leaves is the reading that a `read` or a `write` rule grants.
- **Grants are additive.** `write` implies `read`, and a `read` rule is a
  grant of reading, never a restriction of writing.
- **Access is denied by default.** A path no rule applies to is not
  accessible.
- The order of the rules, and whether they came from one symbolic root or
  several, never changes the result.

Scope decides whether a rule applies. Nothing else about a path's
precision carries meaning.

### Why a deny is absolute

`maelys_mir_restrict()` lets an untrusted restriction add deny rules and
nothing else. If a more precise grant of the base policy could survive a
broader deny of the restriction, the restriction would not restrict. Under
this contract the composed policy grants nothing the base did not, and
nothing the restriction denies.

### Root mode

`read-only` and `ephemeral-write` say what happens to the **root
filesystem of the execution**; they grant nothing. Under `ephemeral-write`
the root is a throwaway writable layer whose lower layer is never modified
and which is discarded with the execution. The rules above still decide
every permission, and what a rule grants on a host path keeps the
persistence of that path: a `write` on the workspace is a durable write to
the workspace under both root modes. A backend that cannot provide this
combination refuses the plan.

### What removing writing means

A `deny-write` rule, and a `deny` rule, protect a path that usually lies in
a tree the execution may write. The contract therefore says what "write"
covers, so that no backend reads it more narrowly:

- the content of the path, and under a `tree` rule the creation and removal
  of every entry beneath it;
- its metadata: mode, times, extended attributes;
- the path itself: it is neither removed, renamed, nor replaced by renaming
  something over it. These are writes to its parent, which may be writable;
  without this, the rule is undone by replacing its target;
- what the rule protected stays protected when an ancestor is renamed.

A backend that announces `fs-deny-write` guarantees all of it, or refuses
the plan before launch.

## Plan order

A plan lists every grant, then every deny-write, then every deny; inside each group, shorter paths
first, then byte order, `tree` before `exact`, `read` before `write`. A
backend that applies rules in order and lets the last match win enforces
the deny rule of the contract, and additive grants need no order.

**The order is a derived encoding. It proves nothing about a backend:**
conformance is what the backend enforces for each path, measured against
the evaluator and the corpus.

## Migration from contract 1

Until ABI 4, plans were ordered from broad to specific and last-match
backends read them as "the most specific rule wins": a precise grant
reopened a denied tree, and a precise `read` made a subtree of a writable
tree read-only. Policy and its consumers did not agree on this.

MIR bytes and digests do not change, so the same policy must not silently
change meaning. `maelys_sandbox_policy_compile()` therefore compares both
readings **after resolution**, and refuses with `MAELYS_MIR_ERR_CONFLICT`
any plan in which one path would receive different permissions. The
diagnostic names a witness path, the permission before and after, and the
rule deciding each:

```text
permission precedence conflict at /w/private/public: before=read after=none;
most-specific-wins decided by [read tree /w/private/public], deny-wins and
additive grants by [deny tree /w/private]; rewrite the policy so both agree
```

No rule is ever dropped or rewritten to make a policy pass. The comparison
is exact: permissions are constant between rule paths, so checking every
rule path and one unnamed descendant of each visits every region.

Accepting those policies later under contract 2 would give existing bytes
a new meaning. It needs an adoption that is visible in the artifact and
rejected by earlier consumers; it is not part of this contract and the
barrier is not lifted by a library upgrade.

## Known limits

- **A `read` rule under a `write` rule is still refused.** It does not
  remove the inherited write, and contract 1 read it as if it did. A
  read-only subtree of a writable tree is written with `deny-write`; the
  migration check judges the grants and denies by themselves, so the `read`
  rule has to go even beside a `deny-write`.
- **A hard link made before the launch** to a protected file, from
  elsewhere in a writable tree, still lets that file be written through the
  other name. Neither `deny` nor `deny-write` covers it, unless a backend
  checks link counts and says so.
- **An exception inside a denied tree is not expressible**, by design.
- The evaluator answers for the rules of a plan. It does not read the
  filesystem and says nothing about changes between resolution and launch.

## A deny on a path that does not exist

A `deny` with `missing: skip` whose target is absent at resolution used to be
dropped from the plan, so the path was unprotected the day it appeared under
a grant. It is now **kept**:

| Situation at resolution | Result |
|---|---|
| absent path, `missing: error` | compilation fails with `MAELYS_MIR_ERR_MISSING` |
| absent grant, `missing: skip` | rule omitted: it grants nothing |
| absent deny or deny-write, `missing: skip` | rule kept with `missing = protect-create` |

The same holds for a `deny-write`: creating the path is a write, so an
absent target is kept and protected alike.

A kept rule carries `MAELYS_SANDBOX_POLICY_MISSING_PROTECT_CREATE` and its
plan requires the capability `fs-protect-create`
(`MAELYS_SANDBOX_POLICY_CAP_FS_PROTECT_CREATE`). The capability is discovered
by resolution, not readable from the MIR alone;
`maelys_sandbox_policy_resolved_capabilities()` returns the complete set, and
a refusal names every missing capability at once. Without it no plan is
returned: the launch is refused, never run with the rule removed.

The path of such a rule is the **canonical existing prefix** followed by the
**remaining components as written**. A dangling symbolic link or a
non-directory on the way would make that name ambiguous, and a prefix that
leaves its symbolic root is an escape: all three are refused. The path names
the target as it stood at resolution. It is a designation, not a guarantee:
keeping the path from being created, linked or renamed into place, including
by a process outside the sandbox, belongs to the backend that announces the
capability, and it must never treat the rule as `error` or skip it.

**This costs availability, deliberately.** `examples/workspace.json` grants
read on the workspace and denies `.git` with `missing: skip`. In a workspace
that has no `.git`, the policy used to compile, and protected nothing; it is
now refused before launch by every backend that does not announce
`fs-protect-create`. The example is kept as it is. A read-only parent is not
a reason to skip the protection: another process of the host can create the
path during the execution, and the workspace grant would then expose it.

## Containment

`maelys_sandbox_policy_plan_contains(boundary, candidate)` answers whether
the candidate grants nothing the boundary does not. It compares **two
resolved plans**, which is what lets it decide nested paths: a candidate
that reads `workspace/src` is within a boundary that reads `workspace`.

**The comparison is exact for the permissions of the two plans.** Take the
paths named by the rules of both. A path that is none of them receives, from
each plan, what the tree rules at or above its deepest named ancestor grant.
Checking every named path and one unnamed descendant of each therefore
visits every region: at most twice the number of distinct paths. The order
is none < read < read-write.

**A counter-example is a difference in that model.** It names one path and
what each plan grants on it. Whether an access to that path can be realised
on the host is not established: the contract ignores what a path is, so a
witness may lie beneath a file. Hence a candidate may be reported as
exceeding where no real access differs; it is never reported as contained
when a path of the model receives more.

A positive answer holds under three conditions, none of which the function
can check:

- both plans were resolved under the **same host context**;
- the filesystem has **not changed** since, for either resolution;
- the backend **enforces the plans** as the contract states.

Network access is the other permission, compared by its own order:

| Network | The candidate is within the boundary when |
|---|---|
| mode | it is no broader: `none` < `mediated` < `direct` |
| mediated destinations | each is one of the boundary's, requires TLS SNI where the boundary does, and allows private addresses only where the boundary does; a `direct` boundary allows every destination |

### Execution constraints

Root mode and process-tree confinement grant no access to anything: they
constrain how the execution runs. They are compared under a contract of
their own, and never as a permission on a path:

| Constraint | The candidate is within the boundary when |
|---|---|
| root | it is `read-only`, or the boundary is `ephemeral-write` |
| process | it requires tree confinement, or the boundary does not |

Each dimension that exceeds is reported with one witness; the filesystem
witness is the first in component order of paths. A report lists the
dimensions it analysed, and a verdict covers nothing else. Capabilities and
the `missing` requirement of rules are not compared: they say what a
backend must offer, not what a policy grants. Every comparison either
completes or fails: there is no partial or inconclusive answer that could
be read as "contained".

## Difference, equivalence and overlap

These read the same regions as containment and hold under the same three
conditions.

`maelys_sandbox_policy_plan_diff(before, after)` reports what changes. Two
plans are **equivalent** exactly when the diff neither widens nor narrows
any dimension, whatever their rules: equivalence is about what is granted,
not about bytes, and two equivalent policies usually have different digests.

For the filesystem, the diff is a list of paths, each with what both plans
grant on the path itself (`self`) and under it (`below`). An entry
overrides, for its path and beneath, the entries of the paths above it.
Equal `below` permissions say only that nothing changes there; an entry
whose permissions are all equal is an unchanged exception inside a changed
tree. A path under no entry is unchanged. A path that both plans treat
alike under an unchanged tree is not listed.

`maelys_sandbox_policy_plan_overlaps(first, second)` tells whether some
access is granted by both: a path both let read, a path both let write, or
a connection both allow, each with a witness. Execution constraints are not
accesses and have no overlap. An overlap witness is, like a containment
witness, a path of the model.

## Conformance

A consumer conforms when, for every path, it either **enforces** the
permission the evaluator returns, or **refuses the plan before launch**
because it cannot guarantee it. A refusal is reported as a refusal: it is
never counted as an enforced case, and a refused launch is not evidence
that an execution took place.
