#!/bin/sh
# Render packaging/homebrew/maelys-sandbox-policy.rb.in for one released tag.
# usage: scripts/render-homebrew-formula.sh vX.Y.Z [OUTPUT [FORMULA]]
# The source archive of the tag is downloaded to compute its digest, and the
# maelys-cli pin is read from the tag's own dependencies/ file, so the formula
# builds the framework the release was verified with.
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
tag=${1:?usage: render-homebrew-formula.sh vX.Y.Z [OUTPUT [FORMULA]]}
output=${2:-$root/dist/homebrew/maelys-sandbox-policy.rb}
formula=${3:-maelys-sandbox-policy}
test "$formula" = maelys-sandbox-policy || { echo "unknown formula: $formula" >&2; exit 64; }
repository=${MAELYS_SOURCE_REPOSITORY:-maelys-dev/maelys-sandbox-policy}
version=${tag#v}
url="https://github.com/$repository/archive/refs/tags/$tag.tar.gz"

temp_base=${TMPDIR:-/tmp}
temp_base=${temp_base%/}
work=$(mktemp -d "$temp_base/maelys-sandbox-policy-formula.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl -fsSL --retry 5 --retry-delay 3 -o "$work/source.tar.gz" "$url"
digest=$(shasum -a 256 "$work/source.tar.gz" | awk '{print $1}')
mkdir -p "$work/tag"
tar -xzf "$work/source.tar.gz" -C "$work/tag" --strip-components=1
test "$(cat "$work/tag/VERSION")" = "$version" || {
    echo "tag $tag carries VERSION $(cat "$work/tag/VERSION")" >&2
    exit 1
}
cli_tag=$(sed -n '1p' "$work/tag/dependencies/maelys-cli.pin")
cli_pin=$(sed -n '2p' "$work/tag/dependencies/maelys-cli.pin")
mkdir -p "$(dirname "$output")"
sed -e "s|@URL@|$url|g" -e "s|@VERSION@|$version|g" -e "s|@SHA256@|$digest|g" \
    -e "s|@CLI_TAG@|$cli_tag|g" -e "s|@CLI_PIN@|$cli_pin|g" \
    "$work/tag/packaging/homebrew/maelys-sandbox-policy.rb.in" >"$output"
if grep -q '@[A-Z_]*@' "$output"; then
    echo "unrendered placeholder in $output" >&2
    exit 1
fi
printf '%s\n' "rendered $output"
