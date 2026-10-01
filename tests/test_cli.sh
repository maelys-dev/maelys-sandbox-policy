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
test "$(wc -l <"$tmp_dir/choices.txt" | tr -d ' ')" = 11 || fail 'capability choices'
while read -r capability; do
  status=0
  "$cli" capabilities "$tmp_dir/policy.mir" --check --available "$capability" >/dev/null 2>&1 || status=$?
  test "$status" = 2 || fail "capability $capability is offered but not known to the library"
done <"$tmp_dir/choices.txt"
