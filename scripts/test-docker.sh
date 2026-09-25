#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${MAELYS_DEPENDENCIES_DIR:?run 'sh scripts/checkout-dependencies.sh DIR' and export the lines it prints}"
docker build --file "$root/docker/Dockerfile.test" \
  --build-context dependencies="$MAELYS_DEPENDENCIES_DIR" \
  --tag maelys-sandbox-policy-test:local "$root"
