#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker build --file "$root/docker/Dockerfile.test" --tag maelys-sandbox-policy-test:local "$root"
