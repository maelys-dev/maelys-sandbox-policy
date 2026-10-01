#!/bin/sh
# End-to-end tests of maelys-policy: the policy results, and the agent-cli/v2
# behaviours this program chooses (plan/apply, the exit-2 report, error codes).
# The contract itself is proved by the agent-cli-spec kit (make agent-cli-check).
set -eu
cli=$1
tmp_dir=$(mktemp -d /tmp/maelys-policy-cli.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

fail() {
  echo "test_cli: $*" >&2
  exit 1
}

# compile is a transaction: the plan writes nothing, --apply writes once.
"$cli" compile examples/workspace.json --output "$tmp_dir/policy.mir" \
  --format json --compact >"$tmp_dir/plan.json"
grep -q '"mode":"plan"' "$tmp_dir/plan.json" || fail 'compile plan'
test ! -e "$tmp_dir/policy.mir" || fail 'compile plan wrote its output'
"$cli" compile examples/workspace.json --output "$tmp_dir/policy.mir" --apply >/dev/null
test -f "$tmp_dir/policy.mir" || fail 'compile --apply wrote nothing'
if "$cli" compile examples/workspace.json --output "$tmp_dir/policy.mir" --apply \
  --format json --compact 2>"$tmp_dir/exists.json"; then
  fail 'compile replaced an existing output without --replace'
fi
grep -q '"code":"PRECONDITION_FAILED"' "$tmp_dir/exists.json" || fail 'compile over an existing output'
"$cli" compile examples/workspace.json --output "$tmp_dir/policy.mir" --replace --apply >/dev/null

"$cli" validate "$tmp_dir/policy.mir" | grep -q 'valid MIR v3' || fail 'validate'
cli_hash=$("$cli" hash "$tmp_dir/policy.mir" | sed 's/^sha256://')
file_hash=$(shasum -a 256 "$tmp_dir/policy.mir" | awk '{print $1}')
test "$cli_hash" = "$file_hash" || fail 'hash is not the SHA-256 of the canonical bytes'
test "$("$cli" hash "$tmp_dir/policy.mir" --field digest)" = "$file_hash" || fail 'hash --field digest'
compile_hash=$("$cli" compile examples/workspace.json --output "$tmp_dir/other.mir" --field digest)
test "$compile_hash" = "$file_hash" || fail 'compile plan digest'

"$cli" inspect "$tmp_dir/policy.mir" >"$tmp_dir/inspection.json"
grep -q '"inspectionVersion": 1' "$tmp_dir/inspection.json" || fail 'inspect'
grep -q '"path": ".git"' "$tmp_dir/inspection.json" || fail 'inspect rules'
"$cli" inspect "$tmp_dir/policy.mir" --format json --compact |
  grep -q '"data":{"inspectionVersion":1,' || fail 'inspect envelope'

artifact_hash=$("$cli" artifact-hash examples/workspace.json | sed 's/^sha256://')
source_hash=$(shasum -a 256 examples/workspace.json | awk '{print $1}')
test "$artifact_hash" = "$source_hash" || fail 'artifact-hash'

# A non-canonical file is a completed validation with violations: exit 2.
cp "$tmp_dir/policy.mir" "$tmp_dir/bad.mir"
printf x >>"$tmp_dir/bad.mir"
status=0
"$cli" validate "$tmp_dir/bad.mir" --format json --compact >"$tmp_dir/bad.json" || status=$?
test "$status" = 2 || fail "validate of non-canonical MIR exited $status, not 2"
grep -q '"valid":false' "$tmp_dir/bad.json" || fail 'validate report'
grep -q '"code":"MIR_FORMAT"' "$tmp_dir/bad.json" || fail 'validate diagnostic'

# Reading commands refuse it outright.
status=0
"$cli" hash "$tmp_dir/bad.mir" --format json --compact 2>"$tmp_dir/hash-bad.json" || status=$?
test "$status" = 1 || fail "hash of non-canonical MIR exited $status, not 1"
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/hash-bad.json" || fail 'hash error code'

status=0
"$cli" inspect "$tmp_dir/missing.mir" --format json --compact 2>"$tmp_dir/missing.json" || status=$?
test "$status" = 1 || fail "inspect of a missing file exited $status, not 1"
grep -q '"code":"NOT_FOUND"' "$tmp_dir/missing.json" || fail 'missing file code'

printf '{"formatVersion":2}' >"$tmp_dir/old.json"
status=0
"$cli" compile "$tmp_dir/old.json" --output "$tmp_dir/old.mir" --format json --compact \
  2>"$tmp_dir/old-error.json" || status=$?
test "$status" = 1 || fail "compile of an invalid source exited $status, not 1"
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/old-error.json" || fail 'invalid source code'

# ---- restrict: a transaction that composes a ceiling over a base --------------
cat >"$tmp_dir/ceiling.json" <<'JSON'
{"formatVersion":3,
 "filesystem":{"default":"deny","rules":[
   {"access":"deny","path":{"root":"workspace","relative":"secrets"},"missing":"skip"}]},
 "network":{"mode":"none"},"root":{"mode":"read-only"},
 "process":{"treeConfinement":"required"}}
JSON
"$cli" compile "$tmp_dir/ceiling.json" --output "$tmp_dir/ceiling.mir" --apply >/dev/null
"$cli" restrict "$tmp_dir/policy.mir" "$tmp_dir/ceiling.mir" --output "$tmp_dir/effective.mir" \
  --format json --compact >"$tmp_dir/restrict-plan.json"
grep -q '"mode":"plan"' "$tmp_dir/restrict-plan.json" || fail 'restrict plan'
grep -q "\"baseDigest\":\"$file_hash\"" "$tmp_dir/restrict-plan.json" || fail 'restrict names its base'
test ! -e "$tmp_dir/effective.mir" || fail 'restrict plan wrote its output'
"$cli" restrict "$tmp_dir/policy.mir" "$tmp_dir/ceiling.mir" --output "$tmp_dir/effective.mir" \
  --apply --format json --compact >"$tmp_dir/restrict-apply.json"
grep -q '"mode":"apply"' "$tmp_dir/restrict-apply.json" || fail 'restrict --apply'
"$cli" validate "$tmp_dir/effective.mir" >/dev/null || fail 'restrict wrote non-canonical MIR'
planned=$(sed 's/.*"digest":"\([0-9a-f]*\)".*/\1/' "$tmp_dir/restrict-plan.json")
test "$planned" = "$("$cli" hash "$tmp_dir/effective.mir" --field digest)" ||
  fail 'restrict plan and written policy disagree'
"$cli" inspect "$tmp_dir/effective.mir" >"$tmp_dir/effective.json"
grep -q '"path": "secrets"' "$tmp_dir/effective.json" || fail 'restrict lost the ceiling deny'
grep -q '"path": ".git"' "$tmp_dir/effective.json" || fail 'restrict lost a base rule'
status=0
"$cli" restrict "$tmp_dir/policy.mir" "$tmp_dir/ceiling.mir" --output "$tmp_dir/effective.mir" \
  --apply --format json --compact 2>"$tmp_dir/restrict-exists.json" >/dev/null || status=$?
test "$status" = 1 || fail "restrict over an existing output exited $status, not 1"
grep -q '"code":"PRECONDITION_FAILED"' "$tmp_dir/restrict-exists.json" || fail 'restrict over an existing output'
# A restriction that grants is not a restriction: the base policy is one.
status=0
"$cli" restrict "$tmp_dir/ceiling.mir" "$tmp_dir/policy.mir" --output "$tmp_dir/widened.mir" \
  --apply --format json --compact 2>"$tmp_dir/restrict-grant.json" >"$tmp_dir/restrict-grant.out" || status=$?
test "$status" = 1 || fail "restrict with a granting restriction exited $status, not 1"
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/restrict-grant.json" || fail 'granting restriction code'
grep -q 'filesystem grant' "$tmp_dir/restrict-grant.json" || fail 'granting restriction message'
test ! -s "$tmp_dir/restrict-grant.out" || fail 'restrict wrote to stdout on failure'
test ! -e "$tmp_dir/widened.mir" || fail 'restrict wrote a refused policy'
status=0
"$cli" restrict "$tmp_dir/policy.mir" "$tmp_dir/ceiling.mir" --output "$tmp_dir/x.mir" --dry-run \
  --format json --compact 2>"$tmp_dir/restrict-dry.json" >/dev/null || status=$?
test "$status" = 1 || fail 'restrict --dry-run was accepted'
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/restrict-dry.json" || fail 'restrict --dry-run code'

# ---- capabilities: requirements, or a check against a declared set -----------
"$cli" capabilities "$tmp_dir/policy.mir" --format json --compact >"$tmp_dir/caps.json"
grep -q '"required":\["fs-read","fs-write","fs-deny","network-none","process-tree"\]' \
  "$tmp_dir/caps.json" || fail 'capabilities requirements'
grep -q '"resolutionMayRequire":\["fs-protect-create"\]' "$tmp_dir/caps.json" ||
  fail 'capabilities does not announce what resolution may add'
grep -q '"checked":false' "$tmp_dir/caps.json" || fail 'capabilities without --check'
if grep -q '"supported"' "$tmp_dir/caps.json"; then fail 'a verdict without --check'; fi
# --check with no --available is a check against nothing, not a listing.
status=0
"$cli" capabilities "$tmp_dir/policy.mir" --check --format json --compact >"$tmp_dir/caps-none.json" || status=$?
test "$status" = 2 || fail "capabilities --check against nothing exited $status, not 2"
grep -q '"available":\[\]' "$tmp_dir/caps-none.json" || fail 'empty available set'
grep -q '"missing":\["fs-read","fs-write","fs-deny","network-none","process-tree"\]' \
  "$tmp_dir/caps-none.json" || fail 'capabilities must name every missing one'
grep -q '"supported":false' "$tmp_dir/caps-none.json" || fail 'capabilities verdict'
status=0
"$cli" capabilities "$tmp_dir/policy.mir" --check --available fs-read --available network-none \
  --field missing >"$tmp_dir/caps-some.txt" || status=$?
test "$status" = 2 || fail "partial capabilities exited $status, not 2"
test "$(tr '\n' ' ' <"$tmp_dir/caps-some.txt")" = 'fs-write fs-deny process-tree ' ||
  fail 'partial capabilities list'
"$cli" capabilities "$tmp_dir/policy.mir" --check --available fs-read --available fs-write \
  --available fs-deny --available network-none --available process-tree \
  --format json --compact | grep -q '"supported":true' || fail 'sufficient capabilities'
status=0
"$cli" capabilities "$tmp_dir/policy.mir" --available fs-read --format json --compact \
  2>"$tmp_dir/caps-nocheck.json" >/dev/null || status=$?
test "$status" = 1 || fail '--available without --check was accepted'
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/caps-nocheck.json" || fail '--available needs --check'
status=0
"$cli" capabilities "$tmp_dir/policy.mir" --check --available fs-teleport --format json --compact \
  2>"$tmp_dir/caps-unknown.json" >/dev/null || status=$?
test "$status" = 1 || fail 'an unknown capability was accepted'
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/caps-unknown.json" || fail 'unknown capability code'
# Every capability the catalog offers is one the library names.
"$cli" describe capabilities --format json --compact |
  sed 's/.*"choices":\[\([^]]*\)\].*/\1/' | tr -d '"' | tr ',' '\n' >"$tmp_dir/choices.txt"
test "$(wc -l <"$tmp_dir/choices.txt" | tr -d ' ')" = 12 || fail 'capability choices'
while read -r capability; do
  status=0
  "$cli" capabilities "$tmp_dir/policy.mir" --check --available "$capability" >/dev/null 2>&1 || status=$?
  test "$status" = 2 || fail "capability $capability is offered but not known to the library"
done <"$tmp_dir/choices.txt"

# ---- resolve and evaluate: the policy on one host -----------------------------
mkdir -p "$tmp_dir/ws/src" "$tmp_dir/runtime"
workspace=$(cd "$tmp_dir/ws" && pwd -P)
runtime=$(cd "$tmp_dir/runtime" && pwd -P)
# examples/workspace.json in a workspace with neither build/ nor .git: the
# absent grant is omitted and reported, the absent deny is kept and asks for
# fs-protect-create.
"$cli" resolve "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" --minimal-root "$tmp_dir/runtime" \
  --format json --compact >"$tmp_dir/resolve.json"
grep -q '"resolved":true' "$tmp_dir/resolve.json" || fail 'resolve'
grep -q "{\"access\":\"deny\",\"scope\":\"tree\",\"path\":\"$workspace/.git\",\"missing\":\"protect-create\"}" \
  "$tmp_dir/resolve.json" || fail 'resolve does not keep the absent deny'
grep -q '"omitted":\[{"access":"write","scope":"tree","root":"workspace","relative":"build"' \
  "$tmp_dir/resolve.json" || fail 'resolve does not report the omitted grant'
grep -q '"from":"plan","required":\[.*"fs-protect-create"\]' "$tmp_dir/resolve.json" ||
  fail 'resolve does not name the capability resolution discovered'
grep -q '"blocked":false' "$tmp_dir/resolve.json" || fail 'resolve without --check judges no backend'
# Checked against a backend without it, the report names what prevents the
# execution and exits 2; the policy is not degraded.
status=0
"$cli" resolve "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" --minimal-root "$tmp_dir/runtime" \
  --check --available fs-read --available fs-write --available fs-deny \
  --available network-none --available process-tree \
  --format json --compact >"$tmp_dir/resolve-check.json" || status=$?
test "$status" = 2 || fail "resolve against a backend lacking fs-protect-create exited $status, not 2"
grep -q '"missing":\["fs-protect-create"\]' "$tmp_dir/resolve-check.json" || fail 'resolve missing set'
grep -q '"code":"CAPABILITIES_MISSING"' "$tmp_dir/resolve-check.json" || fail 'resolve blocker'
grep -q '"missing":"protect-create"' "$tmp_dir/resolve-check.json" || fail 'resolve dropped a rule to pass'
mkdir "$tmp_dir/ws/.git"
"$cli" resolve "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" --minimal-root "$tmp_dir/runtime" \
  --check --available fs-read --available fs-write --available fs-deny \
  --available network-none --available process-tree \
  --format json --compact >"$tmp_dir/resolve-ok.json" || fail 'resolve with .git present'
grep -q '"blocked":false' "$tmp_dir/resolve-ok.json" || fail 'resolve verdict with .git present'
# A policy that does not resolve is a report with a blocker, not an error.
status=0
"$cli" resolve "$tmp_dir/policy.mir" --minimal-root "$tmp_dir/runtime" --format json --compact \
  >"$tmp_dir/resolve-noroot.json" || status=$?
test "$status" = 2 || fail "resolve without a workspace exited $status, not 2"
grep -q '"resolved":false' "$tmp_dir/resolve-noroot.json" || fail 'unresolved report'
grep -q '"code":"MIR_UNSUPPORTED"' "$tmp_dir/resolve-noroot.json" || fail 'unresolved blocker'
grep -q '"from":"mir"' "$tmp_dir/resolve-noroot.json" || fail 'unresolved capabilities source'
cat >"$tmp_dir/conflict.json" <<'JSON'
{"formatVersion":3,
 "filesystem":{"default":"deny","rules":[
   {"access":"write","path":{"root":"workspace","relative":""}},
   {"access":"read","path":{"root":"workspace","relative":"src"}}]},
 "network":{"mode":"none"},"root":{"mode":"read-only"},
 "process":{"treeConfinement":"disabled"}}
JSON
"$cli" compile "$tmp_dir/conflict.json" --output "$tmp_dir/conflict.mir" --apply >/dev/null
status=0
"$cli" resolve "$tmp_dir/conflict.mir" --workspace "$tmp_dir/ws" --format json --compact \
  >"$tmp_dir/resolve-conflict.json" || status=$?
test "$status" = 2 || fail "resolve of a precedence conflict exited $status, not 2"
grep -q '"code":"MIR_CONFLICT"' "$tmp_dir/resolve-conflict.json" || fail 'conflict blocker'
grep -q 'before=read after=read-write' "$tmp_dir/resolve-conflict.json" || fail 'conflict witness'
status=0
"$cli" resolve "$tmp_dir/policy.mir" --workspace "$tmp_dir/absent" --format json --compact \
  2>"$tmp_dir/resolve-badroot.json" >/dev/null || status=$?
test "$status" = 1 || fail "resolve with an absent --workspace exited $status, not 1"
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/resolve-badroot.json" || fail 'absent --workspace code'

evaluate() {
  "$cli" evaluate "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" \
    --minimal-root "$tmp_dir/runtime" --path "$1" --format json --compact
}
evaluate "$workspace/src/main.c" >"$tmp_dir/eval-read.json"
grep -q '"permission":"read","reason":"read-rule"' "$tmp_dir/eval-read.json" || fail 'evaluate read'
grep -q "\"decisiveRule\":{\"access\":\"read\",\"scope\":\"tree\",\"path\":\"$workspace\"" \
  "$tmp_dir/eval-read.json" || fail 'evaluate decisive rule'
evaluate "$workspace/.git/config" | grep -q '"permission":"none","reason":"deny-rule"' ||
  fail 'evaluate deny'
evaluate "$runtime/lib" | grep -q '"permission":"read"' || fail 'evaluate minimal runtime'
evaluate /etc/hosts >"$tmp_dir/eval-default.json"
grep -q '"permission":"none","reason":"default-deny","applicableRules":0}' "$tmp_dir/eval-default.json" ||
  fail 'evaluate default deny'
test "$("$cli" evaluate "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" \
  --minimal-root "$tmp_dir/runtime" --path "$workspace/src" --field permission)" = read ||
  fail 'evaluate --field permission'
status=0
evaluate "$workspace/src/../.git" 2>"$tmp_dir/eval-dots.json" >/dev/null || status=$?
test "$status" = 1 || fail 'evaluate accepted a non-canonical path'
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/eval-dots.json" || fail 'non-canonical path code'
status=0
"$cli" evaluate "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" --path relative/path \
  --format json --compact 2>"$tmp_dir/eval-relative.json" >/dev/null || status=$?
test "$status" = 1 || fail 'evaluate accepted a relative path'
grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/eval-relative.json" || fail 'relative path code'
status=0
"$cli" evaluate "$tmp_dir/conflict.mir" --workspace "$tmp_dir/ws" --path "$workspace/src" \
  --format json --compact 2>"$tmp_dir/eval-conflict.json" >"$tmp_dir/eval-conflict.out" || status=$?
test "$status" = 1 || fail "evaluate of a conflicting policy exited $status, not 1"
grep -q '"code":"POLICY_FAILED"' "$tmp_dir/eval-conflict.json" || fail 'evaluate conflict code'
test ! -s "$tmp_dir/eval-conflict.out" || fail 'evaluate answered for a policy that does not resolve'
status=0
"$cli" evaluate "$tmp_dir/policy.mir" --minimal-root "$tmp_dir/runtime" --path /etc/hosts \
  --format json --compact 2>"$tmp_dir/eval-noroot.json" >/dev/null || status=$?
test "$status" = 1 || fail 'evaluate without the workspace it needs'
grep -q '"code":"PRECONDITION_FAILED"' "$tmp_dir/eval-noroot.json" || fail 'evaluate missing root code'

# ---- contains: a candidate stays within its boundary, on this host ------------
policy_from() { # NAME JSON
  printf '%s' "$2" >"$tmp_dir/$1.json"
  "$cli" compile "$tmp_dir/$1.json" --output "$tmp_dir/$1.mir" --replace --apply >/dev/null
}
contains() { # BOUNDARY CANDIDATE
  "$cli" contains "$tmp_dir/$1.mir" "$tmp_dir/$2.mir" --workspace "$tmp_dir/ws" \
    --minimal-root "$tmp_dir/runtime" --format json --compact
}
tail_json=',"root":{"mode":"read-only"},"process":{"treeConfinement":"required"}}'
# The delegation case: a parent reads the workspace, a sub-agent asks for a
# subtree of it. Nested paths are decided, not left unsupported.
policy_from child '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"read","path":{"root":"workspace","relative":"src"}}]},"network":{"mode":"none"}'"$tail_json"
contains policy child >"$tmp_dir/contains-child.json" || fail 'a subtree of the boundary is not contained'
grep -q '"contained":true,"exceeds":\[\]' "$tmp_dir/contains-child.json" || fail 'contains verdict'
grep -q "\"boundaryDigest\":\"$file_hash\"" "$tmp_dir/contains-child.json" || fail 'contains names its boundary'
test "$("$cli" contains "$tmp_dir/policy.mir" "$tmp_dir/policy.mir" --workspace "$tmp_dir/ws" \
  --minimal-root "$tmp_dir/runtime" --field contained)" = true || fail 'a policy does not contain itself'
# The converse exceeds, with the first path in component order as witness.
status=0
contains child policy >"$tmp_dir/contains-parent.json" || status=$?
test "$status" = 2 || fail "an exceeding candidate exited $status, not 2"
grep -q "\"dimension\":\"filesystem\",\"path\":\"$runtime\",\"boundaryPermission\":\"none\",\"candidatePermission\":\"read\"" \
  "$tmp_dir/contains-parent.json" || fail 'filesystem witness'
grep -q '"candidateRule":{"access":"read","scope":"tree"' "$tmp_dir/contains-parent.json" || fail 'deciding rule'
# What the boundary denies stays denied to the candidate.
policy_from peeker '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"read","path":{"root":"workspace","relative":".git"}}]},"network":{"mode":"none"}'"$tail_json"
status=0
contains policy peeker >"$tmp_dir/contains-git.json" || status=$?
test "$status" = 2 || fail 'reading a denied tree is contained'
grep -q "\"path\":\"$workspace/.git\",\"boundaryPermission\":\"none\",\"candidatePermission\":\"read\",\"boundaryRule\":{\"access\":\"deny\"" \
  "$tmp_dir/contains-git.json" || fail 'denied tree witness'
# Every other dimension, each with its own entry.
policy_from loose '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"read","path":{"root":"workspace","relative":"src"}}]},"network":{"mode":"direct"},"root":{"mode":"ephemeral-write"},"process":{"treeConfinement":"disabled"}}'
status=0
contains policy loose >"$tmp_dir/contains-loose.json" || status=$?
test "$status" = 2 || fail 'looser modes are contained'
grep -q '"dimension":"network","reason":"mode","boundaryMode":"none","candidateMode":"direct"' \
  "$tmp_dir/contains-loose.json" || fail 'network mode excess'
grep -q '"dimension":"root"' "$tmp_dir/contains-loose.json" || fail 'root excess'
grep -q '"dimension":"process"' "$tmp_dir/contains-loose.json" || fail 'process excess'
if grep -q '"dimension":"filesystem"' "$tmp_dir/contains-loose.json"; then fail 'a spurious filesystem excess'; fi
mediated='{"formatVersion":3,"filesystem":{"default":"deny","rules":[]},"network":{"mode":"mediated","allow":['
policy_from net-boundary "$mediated"'{"protocol":"tcp","host":"github.com","port":443,"requireTlsSni":true}]}'"$tail_json"
policy_from net-plain "$mediated"'{"protocol":"tcp","host":"github.com","port":443}]}'"$tail_json"
policy_from net-other "$mediated"'{"protocol":"tcp","host":"example.org","port":443,"requireTlsSni":true}]}'"$tail_json"
net() {
  "$cli" contains "$tmp_dir/$1.mir" "$tmp_dir/$2.mir" --mediator egress --format json --compact
}
net net-boundary net-boundary | grep -q '"contained":true' || fail 'mediated self containment'
status=0
net net-boundary net-plain >"$tmp_dir/contains-sni.json" || status=$?
test "$status" = 2 || fail 'dropping TLS SNI is contained'
grep -q '"reason":"require-tls-sni".*"destination":{"protocol":"tcp","host":"github.com","port":443}' \
  "$tmp_dir/contains-sni.json" || fail 'TLS SNI excess'
net net-plain net-boundary | grep -q '"contained":true' || fail 'adding TLS SNI is not contained'
status=0
net net-boundary net-other >"$tmp_dir/contains-dest.json" || status=$?
test "$status" = 2 || fail 'a foreign destination is contained'
grep -q '"reason":"destination".*"host":"example.org"' "$tmp_dir/contains-dest.json" || fail 'destination excess'
# A policy that does not resolve is compared with nothing.
status=0
"$cli" contains "$tmp_dir/policy.mir" "$tmp_dir/conflict.mir" --workspace "$tmp_dir/ws" \
  --minimal-root "$tmp_dir/runtime" --format json --compact 2>"$tmp_dir/contains-conflict.json" \
  >"$tmp_dir/contains-conflict.out" || status=$?
test "$status" = 1 || fail "contains with a conflicting candidate exited $status, not 1"
grep -q '"code":"POLICY_FAILED"' "$tmp_dir/contains-conflict.json" || fail 'contains conflict code'
grep -q 'conflict.mir does not resolve' "$tmp_dir/contains-conflict.json" || fail 'contains names the policy that fails'
test ! -s "$tmp_dir/contains-conflict.out" || fail 'contains answered without two plans'
status=0
"$cli" contains "$tmp_dir/policy.mir" "$tmp_dir/child.mir" --format json --compact \
  2>"$tmp_dir/contains-noroot.json" >/dev/null || status=$?
test "$status" = 1 || fail 'contains without the roots it needs'
grep -q '"code":"PRECONDITION_FAILED"' "$tmp_dir/contains-noroot.json" || fail 'contains missing root code'

# ---- diagnostic priority: the host context before the policy files ------------
# With an invalid context and an invalid policy file at once, every command
# that resolves reports the context: options are judged before operand files.
both_invalid() { # COMMAND [OPERAND...]
  status=0
  "$cli" "$@" --workspace "$tmp_dir/absent-root" --format json --compact \
    2>"$tmp_dir/priority.json" >"$tmp_dir/priority.out" || status=$?
  test "$status" = 1 || fail "$1 with an invalid context and file exited $status, not 1"
  grep -q '"code":"VALIDATION_FAILED"' "$tmp_dir/priority.json" ||
    fail "$1 does not report the invalid context first"
  grep -q -- '--workspace' "$tmp_dir/priority.json" || fail "$1 does not name --workspace"
  if grep -q 'NOT_FOUND' "$tmp_dir/priority.json"; then fail "$1 reported the file first"; fi
  test ! -s "$tmp_dir/priority.out" || fail "$1 wrote to stdout on failure"
}
both_invalid resolve "$tmp_dir/no-such.mir"
both_invalid evaluate "$tmp_dir/no-such.mir" --path /etc/hosts
both_invalid contains "$tmp_dir/no-such.mir" "$tmp_dir/also-missing.mir"
# With a valid context, the file is what fails.
status=0
"$cli" contains "$tmp_dir/no-such.mir" "$tmp_dir/child.mir" --workspace "$tmp_dir/ws" \
  --format json --compact 2>"$tmp_dir/priority-file.json" >/dev/null || status=$?
test "$status" = 1 || fail 'contains with a missing boundary file'
grep -q '"code":"NOT_FOUND"' "$tmp_dir/priority-file.json" || fail 'missing file code'

# ---- diff and overlaps ---------------------------------------------------------
pair() { # COMMAND FIRST SECOND [OPTION...]
  command=$1 first=$2 second=$3
  shift 3
  "$cli" "$command" "$tmp_dir/$first.mir" "$tmp_dir/$second.mir" --workspace "$tmp_dir/ws" \
    --minimal-root "$tmp_dir/runtime" --format json --compact "$@"
}
# From the example to a policy that writes the workspace and still denies .git.
policy_from wider '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"write","path":{"root":"workspace","relative":""}},{"access":"deny","path":{"root":"workspace","relative":".git"}}]},"network":{"mode":"none"}'"$tail_json"
pair diff policy wider >"$tmp_dir/diff.json" || fail 'diff without --check must exit 0'
grep -q '"equivalent":false,"widens":\["filesystem"\],"narrows":\["filesystem"\]' "$tmp_dir/diff.json" ||
  fail 'diff verdict'
grep -q "{\"path\":\"$workspace\",\"self\":{\"before\":\"read\",\"after\":\"read-write\"},\"below\":{\"before\":\"read\",\"after\":\"read-write\"}}" \
  "$tmp_dir/diff.json" || fail 'diff does not report the widened tree'
grep -q "{\"path\":\"$runtime\",\"self\":{\"before\":\"read\",\"after\":\"none\"}" "$tmp_dir/diff.json" ||
  fail 'diff does not report the removed runtime'
# .git is denied before and after: an unchanged exception inside the changed tree.
grep -q "{\"path\":\"$workspace/.git\",\"self\":{\"before\":\"none\",\"after\":\"none\"},\"below\":{\"before\":\"none\",\"after\":\"none\"}}" \
  "$tmp_dir/diff.json" || fail 'diff does not report the unchanged exception'
grep -q '"analysed":\["filesystem","network","root","process"\]' "$tmp_dir/diff.json" || fail 'diff scope'
status=0
pair diff policy wider --check >/dev/null || status=$?
test "$status" = 2 || fail "diff --check on different policies exited $status, not 2"
# Different rules, same permissions: equivalent, nothing to report.
policy_from redundant '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"read","path":{"root":"workspace","relative":"src"}},{"access":"read","path":{"root":"workspace","relative":"src"},"scope":"exact"}]},"network":{"mode":"none"}'"$tail_json"
pair diff child redundant --check >"$tmp_dir/diff-same.json" || fail 'equivalent policies fail diff --check'
grep -q '"equivalent":true,"widens":\[\],"narrows":\[\],"filesystem":\[\]' "$tmp_dir/diff-same.json" ||
  fail 'equivalence'
test "$(pair diff child redundant | sed 's/.*"beforeDigest":"\([0-9a-f]*\)".*"afterDigest":"\([0-9a-f]*\)".*/\1 \2/' |
  awk '{print ($1 == $2) ? "same" : "different"}')" = different || fail 'equivalent policies should differ in digest here'
# Network changes: a destination whose flags change is removed and added.
"$cli" diff "$tmp_dir/net-boundary.mir" "$tmp_dir/net-plain.mir" --mediator egress \
  --format json --compact >"$tmp_dir/diff-net.json"
grep -q '"widens":\["network"\],"narrows":\[\]' "$tmp_dir/diff-net.json" || fail 'dropping SNI widens the network'
grep -q '"added":\[{"protocol":"tcp","host":"github.com","port":443,"requireTlsSni":false' "$tmp_dir/diff-net.json" ||
  fail 'diff added destination'
grep -q '"removed":\[{"protocol":"tcp","host":"github.com","port":443,"requireTlsSni":true' "$tmp_dir/diff-net.json" ||
  fail 'diff removed destination'
pair diff policy loose >"$tmp_dir/diff-loose.json"
grep -q '"root":{"before":"read-only","after":"ephemeral-write"},"process":{"before":"required","after":"disabled"}' \
  "$tmp_dir/diff-loose.json" || fail 'diff of the execution constraints'
grep -q '"widens":\["network","root","process"\]' "$tmp_dir/diff-loose.json" || fail 'diff widened dimensions'

# overlaps: the example and its sub-agent share the subtree, read-only.
pair overlaps policy child >"$tmp_dir/overlaps.json"
grep -q "\"overlaps\":true,\"filesystem\":{\"readablePath\":\"$workspace/src\"}" "$tmp_dir/overlaps.json" ||
  fail 'overlap witness'
grep -q '"analysed":\["filesystem","network"\]' "$tmp_dir/overlaps.json" || fail 'overlap scope'
# The denied tree is shared with nobody.
pair overlaps policy peeker | grep -q '"overlaps":false,"filesystem":{}' || fail 'a denied tree overlaps'
pair overlaps wider wider | grep -q "\"writablePath\":\"$workspace\"" || fail 'common writable path'
"$cli" overlaps "$tmp_dir/net-boundary.mir" "$tmp_dir/net-other.mir" --mediator egress --field overlaps |
  grep -q false || fail 'distinct destinations overlap'
"$cli" overlaps "$tmp_dir/net-boundary.mir" "$tmp_dir/net-plain.mir" --mediator egress \
  --format json --compact | grep -q '"network":{"overlaps":true,"firstDestination":{"protocol":"tcp","host":"github.com"' ||
  fail 'common destination'
status=0
"$cli" diff "$tmp_dir/policy.mir" "$tmp_dir/conflict.mir" --workspace "$tmp_dir/ws" \
  --minimal-root "$tmp_dir/runtime" --format json --compact 2>"$tmp_dir/diff-conflict.json" >/dev/null || status=$?
test "$status" = 1 || fail 'diff with a policy that does not resolve'
grep -q '"code":"POLICY_FAILED"' "$tmp_dir/diff-conflict.json" || fail 'diff conflict code'
grep -q '"analysed":\["filesystem","network","root","process"\]' "$tmp_dir/contains-child.json" ||
  fail 'contains scope'
both_invalid diff "$tmp_dir/no-such.mir" "$tmp_dir/also-missing.mir"
both_invalid overlaps "$tmp_dir/no-such.mir" "$tmp_dir/also-missing.mir"

# ---- deny-write: a read-only subtree of a writable tree -------------------------
policy_from readonly-git '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"write","path":{"root":"workspace","relative":""}},{"access":"deny-write","path":{"root":"workspace","relative":".git"}}]},"network":{"mode":"none"}'"$tail_json"
"$cli" inspect "$tmp_dir/readonly-git.mir" | grep -q '"access": "deny-write"' || fail 'inspect deny-write'
"$cli" capabilities "$tmp_dir/readonly-git.mir" --format json --compact |
  grep -q '"required":\["fs-write","network-none","process-tree","fs-deny-write"\]' ||
  fail 'deny-write capability'
"$cli" evaluate "$tmp_dir/readonly-git.mir" --workspace "$tmp_dir/ws" --path "$workspace/.git/config" \
  --format json --compact >"$tmp_dir/eval-denywrite.json"
grep -q '"permission":"read","reason":"deny-write-rule"' "$tmp_dir/eval-denywrite.json" || fail 'evaluate deny-write'
grep -q '"decisiveRule":{"access":"deny-write","scope":"tree"' "$tmp_dir/eval-denywrite.json" ||
  fail 'evaluate deny-write deciding rule'
test "$("$cli" evaluate "$tmp_dir/readonly-git.mir" --workspace "$tmp_dir/ws" \
  --path "$workspace/src/main.c" --field permission)" = read-write || fail 'evaluate beside deny-write'
"$cli" resolve "$tmp_dir/readonly-git.mir" --workspace "$tmp_dir/ws" --format json --compact |
  grep -q "{\"access\":\"deny-write\",\"scope\":\"tree\",\"path\":\"$workspace/.git\",\"missing\":\"error\"}" ||
  fail 'resolve deny-write'
# It is within the policy that writes everything, and narrows it.
contains wider readonly-git >/dev/null && fail 'a readable .git is within a boundary that denies it'
pair diff wider readonly-git >"$tmp_dir/diff-denywrite.json"
grep -q "{\"path\":\"$workspace/.git\",\"self\":{\"before\":\"none\",\"after\":\"read\"}" "$tmp_dir/diff-denywrite.json" ||
  fail 'diff from deny to deny-write'
# A restriction may remove writing.
policy_from no-write-git '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"deny-write","path":{"root":"workspace","relative":".git"}}]},"network":{"mode":"none"}'"$tail_json"
policy_from writer '{"formatVersion":3,"filesystem":{"default":"deny","rules":[{"access":"write","path":{"root":"workspace","relative":""}}]},"network":{"mode":"none"}'"$tail_json"
"$cli" restrict "$tmp_dir/writer.mir" "$tmp_dir/no-write-git.mir" --output "$tmp_dir/restricted.mir" --apply >/dev/null
test "$("$cli" hash "$tmp_dir/restricted.mir" --field digest)" = "$("$cli" hash "$tmp_dir/readonly-git.mir" --field digest)" ||
  fail 'restricting by a deny-write gives another policy than writing it'
contains writer restricted | grep -q '"contained":true' || fail 'a restricted policy exceeds its base'
