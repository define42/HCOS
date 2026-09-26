#!/bin/sh
# Adapted from NetDesk's Apache-2.0 container build wrapper.
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.' >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'HCOS requires an x86_64 build host.' >&2; exit 1; }

mkdir -p dist
docker build --platform linux/amd64 --tag hcos-builder:3.24.1 .
docker run --rm --platform linux/amd64 \
    --mount "type=bind,src=$repo,dst=/src,readonly" \
    --mount "type=bind,src=$repo/dist,dst=/out" \
    --env "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}" \
    --env "OUTPUT_UID=$(id -u)" --env "OUTPUT_GID=$(id -g)" \
    hcos-builder:3.24.1 /src/scripts/build-rootfs.sh
