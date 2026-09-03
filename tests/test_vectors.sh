#!/bin/sh
set -eu

cli=$1
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d /tmp/maelys-policy-vectors.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

for source in "$root"/tests/vectors/*.source.json; do
  stem=$(basename "$source" .source.json)
  "$cli" compile "$source" -o "$tmp_dir/$stem.mir"
  cmp "$tmp_dir/$stem.mir" "$root/tests/vectors/$stem.mir"
  "$cli" inspect "$tmp_dir/$stem.mir" >"$tmp_dir/$stem.inspect.json"
  cmp "$tmp_dir/$stem.inspect.json" "$root/tests/vectors/$stem.inspect.json"
  digest=$("$cli" hash "$tmp_dir/$stem.mir" | sed 's/^sha256://')
  test "$digest" = "$(sed -n '1p' "$root/tests/vectors/$stem.sha256")"
done
