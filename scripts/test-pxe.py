#!/usr/bin/env python3
"""Exercise the controller PXE HTTP and TFTP listeners on loopback."""

import hashlib
import http.client
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent
CONTROLLER = ROOT / "dist/hcos-controller"
LOADER = ROOT / "dist/bootx64.efi"
IMAGE = b"MZtest-personalized-efi"


def port(socktype):
    with socket.socket(socket.AF_INET, socktype) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_get(host, port_number, path, source="127.0.0.1", method="GET"):
    connection = http.client.HTTPConnection(host, port_number, timeout=5,
                                            source_address=(source, 0))
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def tftp_loader(port_number):
    original = LOADER.read_bytes()
    request = b"\x00\x01bootx64.efi\x00octet\x00blksize\x001024\x00tsize\x000\x00"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.2", 0))
        client.settimeout(5)
        client.sendto(request, ("127.0.0.1", port_number))
        packet, transfer = client.recvfrom(2048)
        if packet[:2] != b"\x00\x06" or b"blksize\x001024\x00" not in packet:
            raise AssertionError(f"TFTP option negotiation failed: {packet[:80]!r}")
        client.sendto(struct.pack("!HH", 4, 0), transfer)
        digest = hashlib.sha256()
        count = 0
        block = 1
        while True:
            packet, peer = client.recvfrom(2048)
            if peer != transfer or packet[:4] != struct.pack("!HH", 3, block & 0xffff):
                raise AssertionError("TFTP used an unexpected peer or block number")
            data = packet[4:]
            if count == 0 and data[:2] != b"MZ":
                raise AssertionError("TFTP loader is not an EFI executable")
            digest.update(data)
            count += len(data)
            client.sendto(struct.pack("!HH", 4, block & 0xffff), transfer)
            if len(data) < 1024:
                break
            block += 1
        if count != len(original) or digest.digest() != hashlib.sha256(original).digest():
            raise AssertionError("TFTP loader differs from the local bootx64.efi")


def main():
    if not CONTROLLER.is_file() or not LOADER.is_file():
        raise SystemExit("Run 'make ipxe components' first")
    admin_port = port(socket.SOCK_STREAM)
    http_port = port(socket.SOCK_STREAM)
    dhcp_port = port(socket.SOCK_DGRAM)
    tftp_port = port(socket.SOCK_DGRAM)
    admin_token = secrets.token_hex(32)
    node_token = secrets.token_hex(32)
    boot_token = secrets.token_hex(32)

    class MockBootserver(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_image(False)

        def do_GET(self):
            self.send_image(True)

        def send_image(self, include_body):
            from urllib.parse import parse_qs, urlsplit
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if (url.path != "/boot/hcos.efi" or query.get("node") != ["compute-01"]
                    or query.get("token") != [boot_token]):
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(IMAGE)))
            self.end_headers()
            if include_body:
                self.wfile.write(IMAGE)

        def log_message(self, *_args):
            pass  # Never log the boot token in a test URL.

    bootserver = ThreadingHTTPServer(("127.0.0.1", 0), MockBootserver)
    bootthread = threading.Thread(target=bootserver.serve_forever, daemon=True)
    bootthread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="hcos-pxe-") as temporary:
            work = Path(temporary)
            config = {
                "listen_address": f"127.0.0.1:{admin_port}",
                "state_dir": str(work / "state"),
                "admin_token": admin_token,
                "nodes": [{"id": "compute-01", "token": node_token}],
                "pxe": {
                    "http_listen_address": f"127.0.0.1:{http_port}",
                    "boot_server_url": f"http://127.0.0.1:{bootserver.server_port}",
                    "boot_tokens": {"compute-01": boot_token},
                    "dhcp": {
                        "listen_address": f"127.0.0.1:{dhcp_port}",
                        "interface": "lo", "server_ip": "127.0.0.1",
                        "subnet_mask": "255.0.0.0",
                        "leases": [{"node_id": "compute-01", "mac": "52:54:00:12:34:56", "ip": "127.0.0.2"}],
                    },
                    "tftp": {"listen_address": f"127.0.0.1:{tftp_port}"},
                },
            }
            config_path = work / "controller.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            with (work / "controller.log").open("wb") as output:
                process = subprocess.Popen([str(CONTROLLER), "-config", str(config_path)],
                                           stdout=output, stderr=subprocess.STDOUT, cwd=work)
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            raise AssertionError(f"controller exited {process.returncode}: "
                                                 + (work / "controller.log").read_text(errors="replace"))
                        try:
                            status, _, _ = http_get("127.0.0.1", http_port,
                                                    "/boot/boot.ipxe", source="127.0.0.2")
                            if status == 200:
                                break
                        except (ConnectionError, OSError):
                            time.sleep(0.1)
                    else:
                        raise AssertionError("PXE HTTP did not become ready")
                    status, _, script = http_get("127.0.0.1", http_port,
                                                 "/boot/boot.ipxe", source="127.0.0.2")
                    if (status != 200 or not script.startswith(b"#!ipxe\n")
                            or boot_token.encode() in script):
                        raise AssertionError("bad PXE boot script or boot token leaked")
                    status, headers, image = http_get("127.0.0.1", http_port,
                                                      "/boot/hcos.efi", source="127.0.0.2")
                    if status != 200 or image != IMAGE or int(headers["Content-Length"]) != len(IMAGE):
                        raise AssertionError("PXE HTTP did not deliver the node EFI")
                    status, _, _ = http_get("127.0.0.1", http_port,
                                            "/boot/hcos.efi", source="127.0.0.3")
                    if status != 403:
                        raise AssertionError("unknown PXE IP received an EFI")
                    tftp_loader(tftp_port)
                    status, _, _ = http_get("127.0.0.1", admin_port, "/readyz")
                    if status != 200:
                        raise AssertionError("controller admin API is not ready")
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    if process.returncode != 0:
                        raise AssertionError(f"controller shutdown returned {process.returncode}: "
                                             + (work / "controller.log").read_text(errors="replace"))
    finally:
        bootserver.shutdown()
        bootserver.server_close()
    print("PASS: controller served the iPXE script, complete TFTP loader, and node EFI proxy")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise
