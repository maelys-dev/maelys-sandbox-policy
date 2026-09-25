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
