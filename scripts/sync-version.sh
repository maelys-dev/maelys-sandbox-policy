#!/bin/sh
# Copy VERSION into the public header, which consumers read at compile time.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cat "$root/VERSION")
header="$root/include/maelys/sandbox_policy.h"
tmp="$header.tmp"
sed "s/^#define MAELYS_SANDBOX_POLICY_VERSION \".*\"$/#define MAELYS_SANDBOX_POLICY_VERSION \"$version\"/" \
  "$header" >"$tmp"
mv "$tmp" "$header"
grep -Fq "#define MAELYS_SANDBOX_POLICY_VERSION \"$version\"" "$header"
