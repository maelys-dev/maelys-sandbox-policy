#!/bin/sh
set -eu
cli=$1
tmp_dir=$(mktemp -d /tmp/maelys-policy-cli.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
"$cli" compile examples/workspace.json -o "$tmp_dir/policy.mir"
"$cli" validate "$tmp_dir/policy.mir" | grep 'valid MIR v3' >/dev/null
cli_hash=$("$cli" hash "$tmp_dir/policy.mir" | sed 's/^sha256://')
file_hash=$(shasum -a 256 "$tmp_dir/policy.mir" | awk '{print $1}')
test "$cli_hash" = "$file_hash"
"$cli" inspect "$tmp_dir/policy.mir" >"$tmp_dir/inspection.json"
grep '"inspectionVersion": 1' "$tmp_dir/inspection.json" >/dev/null
grep '"path": ".git"' "$tmp_dir/inspection.json" >/dev/null
artifact_hash=$("$cli" artifact-hash examples/workspace.json | sed 's/^sha256://')
source_hash=$(shasum -a 256 examples/workspace.json | awk '{print $1}')
test "$artifact_hash" = "$source_hash"
cp "$tmp_dir/policy.mir" "$tmp_dir/bad.mir"
printf x >> "$tmp_dir/bad.mir"
if "$cli" validate "$tmp_dir/bad.mir" >/dev/null 2>&1; then
  echo 'non-canonical MIR unexpectedly accepted' >&2
  exit 1
fi
