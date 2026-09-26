#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )) || [[ ! $2 =~ ^[0-9a-f]{40}$ ]]; then
    echo "Usage: $0 IMAGE COMMIT_SHA" >&2
    exit 2
fi

image=$1
commit=$2
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
container=

cleanup() {
    if [[ -n $container ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT

if [[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image") != linux/amd64 ]]; then
    echo "Container must target linux/amd64: $image" >&2
    exit 1
fi
if [[ $(docker image inspect --format '{{json .Config.Entrypoint}}' "$image") != '["/usr/local/bin/hcos-controller"]' ]]; then
    echo "Container entrypoint must be hcos-controller: $image" >&2
    exit 1
fi

if [[ $(docker image inspect --format '{{json .Config.Cmd}}' "$image") != '["--config","/etc/hcos-controller/config.json"]' ]]; then
    echo "Container default command must use the controller config: $image" >&2
    exit 1
fi

container=$(docker create "$image")

verify_file() {
    local source=$1 destination=$2
    docker cp "$container:$destination" "$work/file"
    if ! cmp -s "$root/dist/$source" "$work/file"; then
        echo "Container file differs from dist/$source: $destination" >&2
        exit 1
    fi
    rm -f -- "$work/file"
}

verify_file hcos-base.efi "/var/lib/hcos/images/hcos-sha-${commit}.efi"
verify_file hcos-agent "/var/lib/hcos/agents/sha-${commit}/hcos-agent"
verify_file hcos-controller /usr/local/bin/hcos-controller
verify_file hcos-server /usr/local/bin/hcos-server
verify_file ipxe-source.tar.gz /usr/share/source/ipxe-source.tar.gz

echo "Verified container assets for $commit"
