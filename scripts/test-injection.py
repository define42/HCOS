#!/usr/bin/env python3
"""Inject a dummy HCOS agent into a UKI and prove it starts after HTTP boot."""

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parent.parent
BUILDER_IMAGE = "hcos-builder:3.24.1"
FIRST_EXIT_MARKER = "HCOS injected agent first exit"
AGENT_MARKER = "HCOS injected agent ready"
SECTIONS = (".linux", ".initrd", ".cmdline", ".osrel", ".uname")


def read_sections(path):
    """Return the meaningful contents of the UKI sections used by ukify."""
    with path.open("rb") as image:
        dos = image.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("base image lacks a DOS/EFI header")
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        image.seek(pe_offset)
        coff = image.read(24)
        if len(coff) != 24 or coff[:4] != b"PE\0\0":
            raise ValueError("base image lacks a PE header")
        machine, count, _, _, _, optional_size, _ = struct.unpack("<HHIIIHH", coff[4:])
        if machine != 0x8664 or not 0 < count <= 96:
            raise ValueError("base image is not an x86-64 EFI image")
        image.seek(optional_size, 1)
        locations = {}
        for _ in range(count):
            header = image.read(40)
            if len(header) != 40:
                raise ValueError("truncated PE section table")
            name = header[:8].rstrip(b"\0").decode("ascii")
            virtual_size, _, raw_size, offset = struct.unpack_from("<IIII", header, 8)
            if name in SECTIONS:
                if name in locations or not 0 < virtual_size <= raw_size:
                    raise ValueError(f"invalid PE section {name}")
                locations[name] = (offset, virtual_size)
        if set(locations) != set(SECTIONS):
            raise ValueError("base image lacks a required UKI section")
        contents = {}
        for name, (offset, size) in locations.items():
            image.seek(offset)
            contents[name] = image.read(size)
            if len(contents[name]) != size:
                raise ValueError(f"truncated UKI section {name}")
        return contents


def add_cpio_entry(archive, inode, name, mode, content=b""):
    """Append one root-owned Linux newc entry, aligned to four bytes."""
    encoded_name = name.encode("utf-8") + b"\0"
    fields = (inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
              len(content), 0, 0, 0, 0, len(encoded_name), 0)
    archive.extend(b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields))
    archive.extend(encoded_name)
    archive.extend(b"\0" * (-len(archive) % 4))
    archive.extend(content)
    archive.extend(b"\0" * (-len(archive) % 4))


def supplemental_archive(certificate):
    agent = f"""#!/bin/sh
set -eu
fail() {{
    printf 'HCOS injected agent failed: %s\\n' "$1" > /dev/console
    exit 1
}}
[ "$#" -eq 2 ] && [ "$1" = --config ] && [ "$2" = /etc/hcos/config.json ] || fail arguments
grep -Fq '"node_id": "injection-smoke"' /etc/hcos/config.json || fail config
[ -s /etc/hcos/root-ca.crt ] || fail certificate
cmp -s /etc/hcos/root-ca.crt /usr/local/share/ca-certificates/hcos-root-ca.crt || fail installed-ca
[ -s /etc/ssl/certs/ca-certificates.crt ] || fail trust-bundle
cert_line=$(sed -n '2p' /etc/hcos/root-ca.crt)
grep -Fq "$cert_line" /etc/ssl/certs/ca-certificates.crt || fail trust-bundle-content
if [ ! -e /run/hcos-agent-smoke-first-run ]; then
    : > /run/hcos-agent-smoke-first-run
    printf '%s\\n' '{FIRST_EXIT_MARKER}' > /dev/console
    exit 23
fi
printf '%s\\n' '{AGENT_MARKER}' > /dev/console
while :; do sleep 3600; done
""".encode("utf-8")
    config = json.dumps({"node_id": "injection-smoke"}, indent=2).encode() + b"\n"
    entries = (
        ("etc", stat.S_IFDIR | 0o755, b""),
        ("etc/hcos", stat.S_IFDIR | 0o755, b""),
        ("etc/hcos/root-ca.crt", stat.S_IFREG | 0o644, certificate),
        ("etc/hcos/config.json", stat.S_IFREG | 0o600, config),
        ("usr", stat.S_IFDIR | 0o755, b""),
        ("usr/local", stat.S_IFDIR | 0o755, b""),
        ("usr/local/bin", stat.S_IFDIR | 0o755, b""),
        ("usr/local/bin/hcos-agent", stat.S_IFREG | 0o755, agent),
    )
    archive = bytearray()
    for inode, (name, mode, content) in enumerate(entries, start=1):
        add_cpio_entry(archive, inode, name, mode, content)
    add_cpio_entry(archive, len(entries) + 1, "TRAILER!!!", 0)
    return bytes(archive)


def make_certificate(temporary):
    certificate = temporary / "root-ca.crt"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", "1", "-subj", "/CN=HCOS Injection Smoke CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-keyout", str(temporary / "root-ca.key"), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return certificate.read_bytes()


def build_injected_image(base, temporary):
    sections = read_sections(base)
    if not sections[".initrd"].startswith(b"\x1f\x8b"):
        raise ValueError("base .initrd is not gzip-compressed")
    certificate = make_certificate(temporary)
    supplement = supplemental_archive(certificate)
    initrd = sections[".initrd"]
    combined = initrd + b"\0" * (-len(initrd) % 4) + supplement
    for name, content in sections.items():
        (temporary / name.removeprefix(".")).write_bytes(content)
    (temporary / "combined.initrd").write_bytes(combined)

    uname = sections[".uname"].rstrip(b"\0\n").decode("ascii")
    final = temporary / "hcos.efi"
    subprocess.run([
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,src={temporary},dst=/data",
        "--entrypoint", "/usr/sbin/ukify", BUILDER_IMAGE,
        "build", "--linux", "/data/linux", "--initrd", "/data/combined.initrd",
        "--cmdline", "@/data/cmdline", "--os-release", "@/data/osrel",
        "--uname", uname, "--efi-arch", "x64",
        "--stub", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
        "--output", "/data/hcos.efi",
    ], check=True)
    if read_sections(final)[".initrd"] != combined:
        raise ValueError("rebuilt EFI does not contain the full supplemental initramfs")
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path,
                        default=Path("dist/hcos-base.efi"))
    parser.add_argument("--timeout", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--memory", type=int, default=2048, metavar="MIB")
    args = parser.parse_args()
    if args.timeout <= 0 or args.memory < 512:
        parser.error("--timeout must be positive and --memory must be at least 512 MiB")
    for tool in ("docker", "openssl", "qemu-system-x86_64"):
        if shutil.which(tool) is None:
            parser.error(f"{tool} is required")
    try:
        base = args.image.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="hcos-injection-") as directory:
            final = build_injected_image(base, Path(directory))
            subprocess.run([
                sys.executable, str(REPO / "scripts/smoke-test.py"), str(final),
                "--timeout", str(args.timeout), "--memory", str(args.memory),
                "--expect", FIRST_EXIT_MARKER, "--expect", AGENT_MARKER,
            ], cwd=REPO, check=True)
    except (OSError, ValueError, UnicodeError, struct.error,
            subprocess.CalledProcessError) as error:
        print(f"Injection smoke test failed: {error}", file=sys.stderr)
        return 1
    print("PASS: injected agent restarted and validated config/CA after HTTP EFI boot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
