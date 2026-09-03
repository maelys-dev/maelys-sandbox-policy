#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if command -v rg >/dev/null 2>&1; then
  process_hits=$(rg -n '\b(fork|vfork|posix_spawn|execve|system|popen)\s*\(' src include cli || true)
  backend_hits=$(rg -ni '\b(sandbox-exec|bubblewrap|bwrap|seatbelt)\b' src include || true)
else
  process_hits=$(grep -ERn '(^|[^[:alnum:]_])(fork|vfork|posix_spawn|execve|system|popen)[[:space:]]*\(' src include cli || true)
  backend_hits=$(grep -ERni '(sandbox-exec|bubblewrap|bwrap|seatbelt)' src include || true)
fi

if test -n "$process_hits"; then
  printf '%s\n' "$process_hits"
  echo 'process-launch primitive crossed the library boundary' >&2
  exit 1
fi

if test -n "$backend_hits"; then
  printf '%s\n' "$backend_hits"
  echo 'backend-specific vocabulary crossed the MIR/SandboxPlan boundary' >&2
  exit 1
fi

header_hits=$(grep -ERn '^#include[[:space:]]+[<"]' include/maelys | \
  grep -Ev '(maelys/|stddef\.h|stdint\.h)' || true)
if test -n "$header_hits"; then
  printf '%s\n' "$header_hits"
  echo 'public header includes a non-contract dependency' >&2
  exit 1
fi

version=$(sed -n '1p' VERSION)
if ! grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' VERSION ||
  test "$(wc -l <VERSION | tr -d ' ')" != 1; then
  echo 'VERSION must contain exactly one semantic version' >&2
  exit 1
fi
if ! grep -Fq "## $version " CHANGELOG.md; then
  echo 'VERSION has no matching changelog entry' >&2
  exit 1
fi
