#!/usr/bin/env bash
set -euo pipefail

# Build the x86_64 UEFI PXE-to-HTTP loader used by HCOS. The source revision is
# pinned so the bootloader can be rebuilt from a local source checkout offline.
readonly IPXE_REVISION=ff6e52063e0b37062394fe37b9788af25175e7af
readonly IPXE_URL=https://github.com/ipxe/ipxe.git

usage() {
    cat <<'HELP'
Usage: scripts/build-ipxe.sh

Build dist/bootx64.efi from a pinned iPXE source revision and copy it into the
controller package so Go embeds the exact loader served over TFTP. The iPXE script
obtains DHCP settings, then requests http://${next-server}/boot/boot.ipxe.
The loader, source revision, bootstrap script, and upstream license notices are
written below dist/. Only the small loader is transferred by TFTP.

Environment:
  IPXE_SOURCE   Existing local iPXE Git checkout containing the pinned commit.
                Set this to build without network access.
  IPXE_CA_CERT  Optional PEM root certificate to embed and trust for HTTPS boot.
                Required when the HCOS bootserver uses a private site CA that
                iPXE cannot otherwise trust. Do not pass a private key.
  IPXE_JOBS     Number of parallel build jobs (default: 4).
  SOURCE_DATE_EPOCH  Optional build timestamp override (Unix seconds).
                     Defaults to the pinned iPXE commit time.

Build tools: git, gcc, binutils, make, Perl, xz, mtools, liblzma headers, tar.
The EFI loader is unsigned; Secure Boot requires a trusted signed loader.
HELP
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
if (( $# != 0 )); then
    usage >&2
    exit 2
fi

jobs=${IPXE_JOBS:-4}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then
    echo 'IPXE_JOBS must be a positive integer' >&2
    exit 2
fi
for tool in git gcc ld objcopy make perl xz mformat tar install tail mv cat cksum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing build tool: $tool" >&2
        exit 1
    fi
done
if ! printf '#include <lzma.h>\nint main(void) { return lzma_version_number() == 0; }\n' |
    gcc -x c - -o /dev/null -llzma >/dev/null 2>&1; then
    echo 'Missing liblzma development headers/library' >&2
    exit 1
fi
if [[ -n ${IPXE_CA_CERT:-} && ! -f $IPXE_CA_CERT ]]; then
    echo "IPXE_CA_CERT is not a file: $IPXE_CA_CERT" >&2
    exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=$repo_root/dist
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/hcos-ipxe.XXXXXXXX")
embed_temp=
trap 'rm -rf -- "$work_dir"; if [[ -n $embed_temp ]]; then rm -f -- "$embed_temp"; fi' EXIT
source_dir=$work_dir/upstream
mkdir -p -- "$source_dir"

if [[ -n ${IPXE_SOURCE:-} ]]; then
    if ! git -C "$IPXE_SOURCE" cat-file -e "$IPXE_REVISION^{commit}" 2>/dev/null; then
        echo "IPXE_SOURCE does not contain pinned commit $IPXE_REVISION" >&2
        exit 2
    fi
    git -C "$IPXE_SOURCE" archive "$IPXE_REVISION" | tar -xf - -C "$source_dir"
else
    git -C "$source_dir" init --quiet
    git -C "$source_dir" fetch --depth=1 --quiet "$IPXE_URL" "$IPXE_REVISION"
    git -C "$source_dir" checkout --quiet --detach FETCH_HEAD
fi

if [[ ! ${SOURCE_DATE_EPOCH+x} ]]; then
    SOURCE_DATE_EPOCH=$(git -C "${IPXE_SOURCE:-$source_dir}" show -s --format=%ct "$IPXE_REVISION")
fi
if [[ ! $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]]; then
    echo 'SOURCE_DATE_EPOCH must be a nonnegative Unix timestamp' >&2
    exit 2
fi
export SOURCE_DATE_EPOCH

cat > "$source_dir/src/hcos-bootstrap.ipxe" <<'SCRIPT'
#!ipxe
dhcp
chain http://${next-server}/boot/boot.ipxe
SCRIPT

make_args=("bin-x86_64-efi/ipxe-legacy.efi" "EMBED=hcos-bootstrap.ipxe" "DEBUG=")
if [[ -n ${IPXE_CA_CERT:-} ]]; then
    install -m 0644 -- "$IPXE_CA_CERT" "$source_dir/src/hcos-ca.crt"
    make_args+=("CERT=hcos-ca.crt" "TRUST=hcos-ca.crt")
fi
printf 'Upstream: %s\nRevision: %s\nBuild target: %s\n' \
    "$IPXE_URL" "$IPXE_REVISION" 'bin-x86_64-efi/ipxe-legacy.efi' > "$source_dir/HCOS-BUILD.txt"
# Archive the corresponding source before make creates host tools in the tree.
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 \
    --numeric-owner --exclude='./.git' \
    -czf "$work_dir/ipxe-source.tar.gz" -C "$source_dir" .
# iPXE's default build ID hashes intermediates that contain temporary build
# paths. Derive the ID from the fixed loader inputs instead.
build_id=$(
    {
        printf '%s\0' "$IPXE_REVISION" "$SOURCE_DATE_EPOCH"
        cat "$source_dir/src/hcos-bootstrap.ipxe"
        printf '\0'
        if [[ -n ${IPXE_CA_CERT:-} ]]; then
            cat "$source_dir/src/hcos-ca.crt"
        fi
    } | cksum
)
build_id=${build_id%% *}
make_args+=("GITVERSION=$IPXE_REVISION" "BUILD_ID_CMD=printf $build_id")
printf 'Building x64 UEFI iPXE from %s...\n' "$IPXE_REVISION"
if ! make -C "$source_dir/src" -j "$jobs" "${make_args[@]}" > "$work_dir/build.log" 2>&1; then
    tail -n 100 "$work_dir/build.log" >&2
    exit 1
fi
loader=$source_dir/src/bin-x86_64-efi/ipxe-legacy.efi
if [[ ! -s $loader ]]; then
    echo 'iPXE build did not produce an EFI loader' >&2
    exit 1
fi

install -d -m 0755 -- "$output_dir/ipxe"
install -m 0644 -- "$loader" "$output_dir/bootx64.efi"
embed_temp=$(mktemp "$repo_root/internal/controller/.bootx64.efi.XXXXXXXX")
install -m 0644 -- "$loader" "$embed_temp"
mv -f -- "$embed_temp" "$repo_root/internal/controller/bootx64.efi"
embed_temp=
install -m 0644 -- "$source_dir/src/hcos-bootstrap.ipxe" "$output_dir/ipxe/bootstrap.ipxe"
install -m 0644 -- "$source_dir"/COPYING* "$output_dir/ipxe/"
printf '%s\n' "$IPXE_REVISION" > "$output_dir/ipxe/ipxe-revision.txt"
printf 'source=%s\nrevision=%s\ntarget=%s\n' \
    "$IPXE_URL" "$IPXE_REVISION" 'bin-x86_64-efi/ipxe-legacy.efi' > "$output_dir/ipxe/provenance.txt"
if [[ -n ${IPXE_CA_CERT:-} ]]; then
    install -m 0644 -- "$IPXE_CA_CERT" "$output_dir/ipxe/root-ca.crt"
else
    rm -f -- "$output_dir/ipxe/root-ca.crt"
fi
# Ship the source alongside the exact loader that was built from it.
install -m 0644 -- "$work_dir/ipxe-source.tar.gz" "$output_dir/ipxe-source.tar.gz"
printf 'Built %s from iPXE %s\n' "$output_dir/bootx64.efi" "$IPXE_REVISION"
