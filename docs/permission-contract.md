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
| no `deny`, at least one `write` | read and write |
| only `read` | read |
| none | none |

- An `exact` rule applies to its own path. A `tree` rule applies to its
  path and to every path under it; `/a` is not an ancestor of `/ab`.
- **A deny is absolute.** No grant reopens a denied path, however precise.
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

## Plan order

A plan lists every grant, then every deny; inside each group, shorter paths
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

- **A read-only subtree of a writable tree is not expressible.** A `read`
  rule does not remove an inherited `write`, and a `deny` removes reading
  too. A future `deny-write` access would remove writing only, without
  granting reading. Until then such policies are refused by the migration
  check rather than widened.
- **An exception inside a denied tree is not expressible**, by design.
- **A deny whose target does not exist when the plan is resolved** is not
  yet carried to the backend. The requirement that a backend protect the
  creation of such a path is specified with the release that carries it;
  no guarantee is claimed here.
- The evaluator answers for the rules of a plan. It does not read the
  filesystem and says nothing about changes between resolution and launch.

## Conformance

A consumer conforms when, for every path, it either **enforces** the
permission the evaluator returns, or **refuses the plan before launch**
because it cannot guarantee it. A refusal is reported as a refusal: it is
never counted as an enforced case, and a refused launch is not evidence
that an execution took place.
