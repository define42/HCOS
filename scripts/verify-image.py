#!/usr/bin/env python3
# Adapted from NetDesk's Apache-2.0 UKI verifier for HCOS.
"""Verify that an HCOS UKI contains a bootable x86-64 QEMU/libvirt host."""

import argparse
from dataclasses import dataclass
import gzip
import io
from pathlib import Path
import posixpath
import re
import shlex
import stat
import struct
import sys


CHUNK = 1024 * 1024
KVM_MODULES = ("kvm", "kvm_intel", "kvm_amd")
LIBVIRT_DRIVERS = ("qemu", "storage", "network")
DEFAULT_SERVICES = ("dhcpcd", "hcos-kvm", "virtlogd", "virtlockd",
                    "libvirtd", "hcos-ready")


def check(ok, message):
    if not ok:
        raise ValueError(message)


def read_exact(stream, size):
    parts = []
    while size:
        part = stream.read(size)
        check(part, "truncated EFI image or initramfs")
        parts.append(part)
        size -= len(part)
    return b"".join(parts)


@dataclass(frozen=True)
class Section:
    offset: int
    size: int


@dataclass
class Entry:
    mode: int
    uid: int
    gid: int
    size: int
    major: int
    minor: int
    target: str = ""


class SectionStream(io.RawIOBase):
    """Read only the meaningful bytes of one PE section."""

    def __init__(self, image, section):
        self.image = image
        self.remaining = section.size
        image.seek(section.offset)

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = self.remaining
        data = self.image.read(min(size, self.remaining))
        self.remaining -= len(data)
        return data


def pe_sections(image, image_size):
    dos = read_exact(image, 64)
    check(dos[:2] == b"MZ", "missing DOS/EFI header")
    pe_offset = struct.unpack_from("<I", dos, 60)[0]
    check(64 <= pe_offset <= image_size - 24, "PE header outside image")
    image.seek(pe_offset)
    header = read_exact(image, 24)
    check(header[:4] == b"PE\0\0", "missing PE signature")
    machine, count, _, _, _, optional_size, _ = struct.unpack("<HHIIIHH", header[4:])
    check(machine == 0x8664, "EFI image is not x86-64")
    check(0 < count <= 96 and optional_size >= 70, "invalid PE header dimensions")
    optional = read_exact(image, optional_size)
    check(struct.unpack_from("<H", optional)[0] == 0x20B, "image is not PE32+")
    check(struct.unpack_from("<H", optional, 68)[0] == 10,
          "PE subsystem is not EFI application")

    sections = {}
    for _ in range(count):
        header = read_exact(image, 40)
        name = header[:8].rstrip(b"\0").decode("ascii")
        virtual_size, _, raw_size, offset = struct.unpack_from("<IIII", header, 8)
        check(name and name not in sections, f"invalid or duplicate PE section {name!r}")
        check(offset <= image_size and raw_size <= image_size - offset,
              f"PE section {name} lies outside image")
        check(virtual_size <= raw_size, f"PE section {name} has invalid size")
        sections[name] = Section(offset, virtual_size)

    for name in (".linux", ".initrd", ".cmdline", ".osrel", ".uname"):
        check(name in sections and sections[name].size,
              f"missing or empty UKI section {name}")
    return sections


def section_text(image, section):
    check(section.size <= 65536, "UKI metadata section is too large")
    image.seek(section.offset)
    return read_exact(image, section.size).rstrip(b"\0\n").decode("utf-8")


def read_archive(stream):
    entries = {}
    contents = {}
    capture = {"init", "etc/inittab", "etc/os-release", "etc/fstab",
               "etc/init.d/hcos-agent"}
    while True:
        header = read_exact(stream, 110)
        check(header[:6] == b"070701", "initramfs is not a newc cpio archive")
        fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        _, mode, uid, gid, _, _, size, _, _, major, minor, name_size, _ = fields
        check(0 < name_size <= 4096, "invalid cpio name length")
        raw_name = read_exact(stream, name_size)
        check(raw_name.endswith(b"\0"), "unterminated cpio path")
        name = raw_name[:-1].decode("utf-8")
        read_exact(stream, -(110 + name_size) % 4)
        if name == "TRAILER!!!":
            check(size == 0, "nonempty cpio trailer")
            break

        name = posixpath.normpath(name)
        check(name not in entries and name != ".." and
              not name.startswith(("/", "../")), f"unsafe or duplicate cpio path {name}")
        entry = Entry(mode, uid, gid, size, major, minor)
        entries[name] = entry
        if stat.S_ISLNK(mode) or name in capture:
            check(size <= CHUNK, f"oversized config or symlink {name}")
            content = read_exact(stream, size).decode("utf-8")
            if stat.S_ISLNK(mode):
                entry.target = content
            else:
                contents[name] = content
        else:
            remaining = size
            while remaining:
                amount = min(remaining, CHUNK)
                read_exact(stream, amount)
                remaining -= amount
        read_exact(stream, -size % 4)

    # Drain the stream to check gzip's CRC and reject a second payload.
    while data := stream.read(CHUNK):
        check(not data.strip(b"\0"), "unexpected data after cpio trailer")
    return entries, contents


def resolve(entries, name):
    for _ in range(24):
        check(name in entries, f"missing /{name}")
        entry = entries[name]
        if not stat.S_ISLNK(entry.mode):
            return entry
        if entry.target.startswith("/"):
            name = posixpath.normpath(entry.target).lstrip("/")
        else:
            name = posixpath.normpath(posixpath.join(posixpath.dirname(name),
                                                    entry.target))
        check(name != ".." and not name.startswith("../"), "symlink escapes rootfs")
    raise ValueError("runtime symlink loop")


def executable(entries, name):
    entry = resolve(entries, name)
    check(stat.S_ISREG(entry.mode) and entry.mode & 0o111,
          f"/{name} is not executable")


def driver(entries, name):
    path = f"usr/lib/libvirt/connection-driver/libvirt_driver_{name}.so"
    entry = resolve(entries, path)
    check(stat.S_ISREG(entry.mode) and entry.size,
          f"missing libvirt {name} driver")


def enabled_service(entries, name):
    link = f"etc/runlevels/default/{name}"
    entry = entries.get(link)
    check(entry is not None and stat.S_ISLNK(entry.mode),
          f"OpenRC service {name} is not enabled in the default runlevel")
    if entry.target.startswith("/"):
        target = posixpath.normpath(entry.target).lstrip("/")
    else:
        target = posixpath.normpath(posixpath.join(posixpath.dirname(link),
                                                  entry.target))
    check(target == f"etc/init.d/{name}",
          f"OpenRC service {name} points to the wrong init script")
    executable(entries, target)


def verify_console_logins(entries, inittab):
    executable(entries, "sbin/getty")
    consoles = set()
    shells = {"sh", "ash", "bash", "dash", "zsh"}
    for raw_line in inittab.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":", 3)
        check(len(fields) == 4, "invalid inittab entry")
        terminal, _, action, command = fields
        argv = shlex.split(command)
        check(argv, "empty inittab command")
        check(not any(posixpath.basename(arg.lstrip("-")) in shells for arg in argv),
              "inittab starts a shell directly")
        if action in {"respawn", "askfirst"}:
            check(action == "respawn" and terminal in {"tty1", "ttyS0"},
                  "unexpected interactive inittab entry")
            check(terminal not in consoles, f"duplicate {terminal} getty")
            check(argv[0] == "/sbin/getty" and terminal in argv[1:],
                  f"{terminal} must run getty for its own console")
            for arg in argv[1:]:
                if arg.startswith("--"):
                    check(not any(arg == option or arg.startswith(option + "=")
                                  for option in ("--skip-login", "--autologin",
                                                 "--login-program")),
                          f"{terminal} getty bypasses login")
                elif arg.startswith("-"):
                    check(not any(option in arg[1:] for option in "nla"),
                          f"{terminal} getty bypasses login")
            consoles.add(terminal)
    check(consoles == {"tty1", "ttyS0"},
          "authenticated getty must run on tty1 and ttyS0")


def verify_rootfs(entries, contents, kernel_version):
    for name in ("init", "sbin/init", "sbin/openrc", "usr/bin/qemu-system-x86_64",
                 "usr/bin/qemu-img", "usr/bin/virsh", "usr/sbin/libvirtd",
                 "usr/sbin/virtlogd", "usr/sbin/virtlockd",
                 "usr/sbin/update-ca-certificates", "etc/init.d/hcos-agent"):
        executable(entries, name)
    for name in LIBVIRT_DRIVERS:
        driver(entries, name)

    for name in ("etc/libvirt/libvirtd.conf", "etc/libvirt/qemu.conf",
                 "etc/init.d/libvirtd", "etc/init.d/virtlogd", "etc/init.d/virtlockd"):
        check(name in entries and stat.S_ISREG(entries[name].mode),
              f"missing libvirt configuration or OpenRC service /{name}")
    for name in DEFAULT_SERVICES:
        enabled_service(entries, name)
    check("etc/runlevels/default/hcos-agent" not in entries,
          "generic base must enable hcos-agent only after injection")
    for name in ("etc/hcos/root-ca.crt", "etc/hcos/config.json",
                 "usr/local/bin/hcos-agent"):
        check(name not in entries, f"generic base includes node-specific /{name}")
    agent_service = contents.get("etc/init.d/hcos-agent", "")
    check('command="/usr/local/bin/hcos-agent"' in agent_service and
          'command_args="--config /etc/hcos/config.json"' in agent_service and
          'supervisor="supervise-daemon"' in agent_service,
          "hcos-agent service has the wrong command or supervisor")
    console = resolve(entries, "dev/console")
    check(stat.S_ISCHR(console.mode) and (console.major, console.minor) == (5, 1),
          "initramfs needs character device /dev/console (5:1)")

    init = contents.get("init", "")
    check(re.search(r"\bexec\s+/sbin/init\b", init), "/init must start OpenRC init")
    check("/etc/hcos/root-ca.crt" in init and
          "update-ca-certificates" in init and
          "etc/runlevels/default/hcos-agent" in init,
          "/init must trust the injected CA and enable the agent")
    inittab = contents.get("etc/inittab", "")
    check(re.search(r"/sbin/openrc\s+sysinit", inittab) and
          re.search(r"/sbin/openrc\s+default", inittab),
          "inittab must run OpenRC sysinit and default runlevels")
    verify_console_logins(entries, inittab)

    modules = {name.split("/")[2] for name in entries
               if name.startswith("lib/modules/") and
               re.search(r"\.ko(?:\.(?:gz|xz|zst))?$", name)}
    check(modules == {kernel_version},
          f"kernel module versions {sorted(modules)} do not match .uname {kernel_version}")
    for module in KVM_MODULES:
        matches = []
        for name in entries:
            if not name.startswith(f"lib/modules/{kernel_version}/"):
                continue
            found = re.search(r"/([^/]+)\.ko(?:\.(?:gz|xz|zst))?$", name)
            if found and found.group(1).replace("-", "_") == module:
                matches.append(name)
        check(len(matches) == 1 and entries[matches[0]].size,
              f"missing {module} kernel module for {kernel_version}")
    check(f"lib/modules/{kernel_version}/modules.dep" in entries,
          "missing kernel module dependency index")
    check(not any(name.startswith("boot/vmlinuz") for name in entries),
          "rootfs contains a redundant kernel copy")

    other_systems = sorted(name for name, entry in entries.items()
                           if posixpath.dirname(name) in {"bin", "sbin", "usr/bin",
                                                           "usr/sbin", "usr/libexec"} and
                           posixpath.basename(name).startswith("qemu-system-") and
                           posixpath.basename(name) != "qemu-system-x86_64" and
                           (stat.S_ISLNK(entry.mode) or
                            stat.S_ISREG(entry.mode) and entry.mode & 0o111))
    check(not other_systems,
          "unneeded QEMU system emulators: " + ", ".join(other_systems[:8]))
    check("usr/bin/qemu-microblazeel" not in entries,
          "unneeded QEMU MicroBlaze executable is present")
    for name in ("virtchd", "virtlxcd", "virtvboxd", "virtxend"):
        check(f"usr/sbin/{name}" not in entries,
              f"unneeded libvirt hypervisor daemon: {name}")
    check("usr/lib/libvirt/connection-driver/libvirt_driver_ch.so" not in entries,
          "unneeded Cloud Hypervisor driver")
    return len(entries)


def verify(path):
    image_size = path.stat().st_size
    with path.open("rb") as image:
        sections = pe_sections(image, image_size)
        kernel_version = section_text(image, sections[".uname"])
        check(re.fullmatch(r"[A-Za-z0-9_.+-]+", kernel_version), "invalid .uname")
        cmdline = shlex.split(section_text(image, sections[".cmdline"]))
        check("rdinit=/init" in cmdline, "kernel must start embedded /init")
        check(not any(arg.startswith(("root=", "nfsroot=")) for arg in cmdline),
              "kernel command line requests an external root filesystem")
        check(re.search(r"^ID=", section_text(image, sections[".osrel"]), re.MULTILINE),
              "UKI has no OS identity")
        check(sections[".linux"].size >= 0x206, "embedded kernel is too small")
        image.seek(sections[".linux"].offset + 0x202)
        check(read_exact(image, 4) == b"HdrS", "embedded kernel has no Linux boot header")
        with gzip.GzipFile(fileobj=SectionStream(image, sections[".initrd"])) as archive:
            count = verify_rootfs(*read_archive(archive), kernel_version)
    print(f"Verified {path}: {image_size / (1024 * 1024):.1f} MiB EFI, "
          f"kernel {kernel_version}, {count} rootfs entries; x86-64 KVM/QEMU/libvirt present")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, default=Path("dist/hcos-base.efi"))
    args = parser.parse_args()
    try:
        verify(args.image)
    except (OSError, ValueError, EOFError, UnicodeError, struct.error) as error:
        print(f"Image verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
