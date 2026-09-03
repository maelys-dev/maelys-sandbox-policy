#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="${1:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 X.Y.Z" >&2; exit 1; }
tag="v${version}"
test -z "$(git status --porcelain)" || { echo "working tree is not clean" >&2; exit 1; }
test "$(git branch --show-current)" = main || { echo "release must start on main" >&2; exit 1; }
git fetch origin --quiet
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" || { echo "HEAD must equal origin/main" >&2; exit 1; }
test "$(cat VERSION)" = "$version" || { echo "VERSION does not match $version" >&2; exit 1; }
grep -Fq "#define MAELYS_SANDBOX_POLICY_VERSION \"${version}\"" include/maelys/sandbox_policy.h
grep -Eq "^## ${version}([[:space:]]|$)" CHANGELOG.md
test -n "$(git config user.signingkey || true)" || { echo "no signing key configured" >&2; exit 1; }
make clean check CC=clang
git tag -s "$tag" -m "Maelys Sandbox Policy ${version}"
git tag -v "$tag"
git push origin "$tag"
bash scripts/update-tap-formula.sh "$tag"
