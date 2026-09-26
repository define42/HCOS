#!/usr/bin/env python3
# Adapted from NetDesk's Apache-2.0 OVMF smoke test for HCOS.
"""Boot the release EFI image over HTTP and wait for HCOS's runtime checks."""

import argparse
import functools
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time


READY_MARKER = "HCOS virtualization ready"
IMAGE_NAME = "hcos.efi"
FIRMWARE_DIRS = (
    Path("/usr/share/OVMF"),
    Path("/usr/share/edk2/ovmf"),
    Path("/usr/share/edk2/x64"),
    Path("/usr/share/edk2-ovmf/x64"),
    Path("/usr/share/qemu"),
)
FIRMWARE_NAMES = (
    "OVMF_CODE_4M.fd",
    "OVMF_CODE.4m.fd",
    "OVMF_CODE.fd",
    "OVMF_CODE_2M.fd",
)


def firmware_pair(code):
    """Find a matching writable VARS template next to an OVMF CODE image."""
    if "CODE" not in code.name:
        return None
    variables = code.with_name(code.name.replace("CODE", "VARS", 1))
    if code.is_file() and variables.is_file():
        return code, variables
    return None


def find_firmware():
    code_override = os.environ.get("OVMF_CODE")
    vars_override = os.environ.get("OVMF_VARS")
    if code_override or vars_override:
        if code_override and vars_override:
            code, variables = Path(code_override), Path(vars_override)
            if code.is_file() and variables.is_file():
                return code, variables
        elif code_override:
            pair = firmware_pair(Path(code_override))
            if pair:
                return pair
        raise ValueError("OVMF_CODE and OVMF_VARS must point to matching readable firmware files")

    for directory in FIRMWARE_DIRS:
        for name in FIRMWARE_NAMES:
            pair = firmware_pair(directory / name)
            if pair:
                return pair

    # Distribution packages sometimes place OVMF one directory below these paths.
    for directory in FIRMWARE_DIRS:
        if not directory.is_dir():
            continue
        for code in sorted(directory.glob("**/*CODE*.fd")):
            if any(part in code.name.lower() for part in ("secboot", "snakeoil", "ms.fd")):
                continue
            pair = firmware_pair(code)
            if pair:
                return pair
    raise ValueError("OVMF firmware not found; install ovmf or set OVMF_CODE and OVMF_VARS")


class ImageServer(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".efi": "application/efi"}

    def do_GET(self):
        if self.path == f"/{IMAGE_NAME}":
            self.server.downloaded.set()
        super().do_GET()

    def log_message(self, format_string, *args):
        print("HTTP: " + format_string % args, flush=True)


def recent_output(path, limit=16000):
    if not path.exists():
        return "(no output)"
    with path.open("rb") as output:
        output.seek(max(0, path.stat().st_size - limit))
        return output.read().decode(errors="replace")


def run(image, timeout, memory):
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        raise ValueError("qemu-system-x86_64 not found; install qemu-system-x86")
    code, variables = find_firmware()

    logs = Path("build").resolve()
    logs.mkdir(exist_ok=True)
    serial_path = logs / "smoke-serial.log"
    qemu_path = logs / "smoke-qemu.log"
    serial_path.write_bytes(b"")

    handler = functools.partial(ImageServer, directory=str(image.parent))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.downloaded = threading.Event()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="hcos-smoke-") as temporary:
            vars_copy = Path(temporary) / "OVMF_VARS.fd"
            shutil.copyfile(variables, vars_copy)
            url = f"http://10.0.2.2:{server.server_port}/{IMAGE_NAME}"
            command = [
                qemu,
                "-machine", "q35,accel=tcg",
                "-cpu", "max",
                "-m", str(memory),
                "-smp", "2",
                "-no-reboot",
                # Keep OVMF HTTP Boot and avoid PXE's unrelated TFTP timeouts.
                "-fw_cfg", "name=opt/org.tianocore/IPv4PXESupport,string=no",
                "-fw_cfg", "name=opt/org.tianocore/IPv6PXESupport,string=no",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={vars_copy}",
                "-device", "virtio-vga", "-vga", "none",
                "-device", "virtio-net-pci,netdev=net0,bootindex=1",
                "-netdev", f"user,id=net0,bootfile={url}",
                "-display", "none",
                "-serial", f"file:{serial_path}",
                "-monitor", "none",
            ]
            print(f"Booting {image} through OVMF HTTP Boot with TCG and {memory} MiB RAM.",
                  flush=True)
            with qemu_path.open("wb") as qemu_output:
                process = subprocess.Popen(command, stdout=qemu_output,
                                           stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + timeout
                    serial_offset = 0
                    serial_text = ""
                    while time.monotonic() < deadline:
                        with serial_path.open("rb") as serial:
                            serial.seek(serial_offset)
                            chunk = serial.read()
                            serial_offset = serial.tell()
                        if chunk:
                            serial_text = (serial_text + chunk.decode(errors="replace"))[-65536:]
                            if "Kernel panic" in serial_text:
                                raise RuntimeError("guest kernel panicked")
                            if READY_MARKER in serial_text and "login:" in serial_text and server.downloaded.is_set():
                                print(f"PASS: HTTP-loaded EFI reached {READY_MARKER!r}, "
                                      f"active guest networking, and the serial login prompt; "
                                      f"logs in {logs}.")
                                return
                        if process.poll() is not None:
                            raise RuntimeError(f"QEMU exited with status {process.returncode}")
                        time.sleep(0.5)
                    raise RuntimeError(f"guest did not report {READY_MARKER!r} "
                                       f"and an authenticated login prompt within {timeout} seconds")
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    except (RuntimeError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        for path in (qemu_path, serial_path):
            print(f"--- {path} ---\n{recent_output(path)}", file=sys.stderr)
        raise SystemExit(1) from error
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, default=Path("dist/hcos.efi"))
    parser.add_argument("--timeout", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--memory", type=int, default=2048, metavar="MIB")
    args = parser.parse_args()
    if args.timeout <= 0 or args.memory < 512:
        parser.error("--timeout must be positive and --memory must be at least 512 MiB")
    try:
        image = args.image.resolve(strict=True)
        if image.name != IMAGE_NAME:
            parser.error(f"image must be named {IMAGE_NAME}")
        run(image, args.timeout, args.memory)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
