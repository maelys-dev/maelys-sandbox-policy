#!/usr/bin/env bash
set -euo pipefail

tap_repo="maelys-dev/homebrew-tap"
source_repo="maelys-dev/maelys-sandbox-policy"
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="${1:-v$(cat "$root/VERSION")}"
version="${tag#v}"
archive_url="https://github.com/${source_repo}/archive/refs/tags/${tag}.tar.gz"
git ls-remote --exit-code --tags "https://github.com/${source_repo}.git" "$tag" >/dev/null

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 5 --retry-delay 5 -o "$tmp/source.tar.gz" "$archive_url"
digest="$(shasum -a 256 "$tmp/source.tar.gz" | cut -d' ' -f1)"
git clone -q "https://github.com/${tap_repo}.git" "$tmp/tap"
formula="$tmp/tap/Formula/maelys-sandbox-policy.rb"
sed -e "s|@URL@|$archive_url|g" -e "s|@SHA256@|$digest|g" \
  "$root/packaging/homebrew/maelys-sandbox-policy.rb.in" >"$formula"
if command -v brew >/dev/null 2>&1; then brew style "$formula"; fi
git -C "$tmp/tap" add "$formula"
if git -C "$tmp/tap" diff --cached --quiet; then echo "formula already serves $tag"; exit 0; fi
git -C "$tmp/tap" commit -S -m "Add Maelys Sandbox Policy ${version}"
git -C "$tmp/tap" push origin main
