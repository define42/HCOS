#!/usr/bin/env python3
"""Build a node EFI through hcos-server and boot its output with OVMF."""

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


REPO = Path(__file__).resolve().parent.parent
MARKER = "HCOS boot server agent ready"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def make_ca(directory):
    certificate = directory / "root-ca.crt"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", "1", "-subj", "/CN=HCOS Boot Server Smoke CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-keyout", str(directory / "root-ca.key"), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_server(url, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"hcos-server exited with status {process.returncode}")
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("hcos-server did not become healthy")


def fetch_image(url, token, image):
    endpoint = url + "/boot/hcos.efi?node=smoke&token=" + token
    with urllib.request.urlopen(url + "/readyz", timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("hcos-server is not ready")
    try:
        urllib.request.urlopen(url + "/boot/hcos.efi?node=smoke&token=wrong", timeout=10)
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403):
            raise RuntimeError(f"invalid boot token returned HTTP {error.code}") from error
    else:
        raise RuntimeError("invalid boot token was accepted")

    request = urllib.request.Request(endpoint, method="HEAD")
    with urllib.request.urlopen(request, timeout=60) as response:
        expected = int(response.headers["Content-Length"])
        if expected <= 0:
            raise RuntimeError("HEAD returned no EFI length")
    with urllib.request.urlopen(endpoint, timeout=120) as response:
        body = response.read()
        if response.status != 200 or len(body) != expected or body[:2] != b"MZ":
            raise RuntimeError("GET did not return the complete EFI image")
        image.write_bytes(body)
    with urllib.request.urlopen(endpoint, timeout=120) as response:
        if hashlib.sha256(response.read()).digest() != hashlib.sha256(body).digest():
            raise RuntimeError("a repeated boot request changed the EFI bytes")
    print(f"Boot server assembled {len(body) / (1024 * 1024):.1f} MiB EFI; repeated request matched.",
          flush=True)


def run(base, timeout, memory):
    server_binary = REPO / "dist/hcos-server"
    if not server_binary.is_file():
        raise ValueError("dist/hcos-server is missing; run make components")
    for tool in ("openssl", "qemu-system-x86_64"):
        if shutil.which(tool) is None:
            raise ValueError(f"{tool} is required")
    logs = REPO / "build"
    logs.mkdir(exist_ok=True)
    server_log = logs / "server-smoke.log"
    server_log.write_bytes(b"")

    with tempfile.TemporaryDirectory(prefix="hcos-server-smoke-") as temporary:
        directory = Path(temporary)
        images = directory / "images"
        agents = directory / "agents" / "1.0.0"
        trust = directory / "trust" / "site-v1"
        cache = directory / "cache"
        for path in (images, agents, trust, cache):
            path.mkdir(parents=True)
        cache.chmod(0o700)
        shutil.copyfile(base, images / "hcos-1.0.0.efi")
        make_ca(trust)
        agent = agents / "hcos-agent"
        agent.write_text(f'''#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = --config ] && [ "$2" = /etc/hcos/config.json ] || exit 1
grep -Fq '"node_id": "smoke"' /etc/hcos/config.json || exit 1
[ -s /etc/hcos/root-ca.crt ] || exit 1
printf '%s\\n' '{MARKER}' > /dev/console
while :; do sleep 3600; done
''')
        agent.chmod(0o755)
        token = secrets.token_hex(32)
        nodes = directory / "nodes.json"
        write_json(nodes, {"nodes": [{
            "id": "smoke", "boot_token": token,
            "hcos_version": "1.0.0", "agent_version": "1.0.0", "ca_version": "site-v1",
            "config": {
                "api_version": "hcos/v1", "node_id": "smoke", "hostname": "smoke",
                "controller": "https://controller.internal", "controller_token": "smoke-token",
                "storage": {"path": "/vm-storage"},
                "network": {"management_interface": "eth0", "vm_bridge": "br-vm"},
            },
        }]})
        port = free_port()
        config = directory / "server.json"
        write_json(config, {
            "listen": f"127.0.0.1:{port}", "images_dir": str(images),
            "agents_dir": str(agents.parent), "trust_dir": str(trust.parent),
            "cache_dir": str(cache), "nodes_file": str(nodes),
        })
        url = f"http://127.0.0.1:{port}"
        with server_log.open("wb") as output:
            process = subprocess.Popen([str(server_binary), "-config", str(config)],
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                wait_for_server(url, process)
                image = directory / "hcos.efi"
                fetch_image(url, token, image)
                subprocess.run([
                    sys.executable, str(REPO / "scripts/smoke-test.py"), str(image),
                    "--timeout", str(timeout), "--memory", str(memory),
                    "--expect", MARKER,
                ], cwd=REPO, check=True)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, default=Path("dist/hcos-base.efi"))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--memory", type=int, default=2048)
    args = parser.parse_args()
    if args.timeout <= 0 or args.memory < 512:
        parser.error("--timeout must be positive and --memory at least 512 MiB")
    try:
        run(args.image.resolve(strict=True), args.timeout, args.memory)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Boot server smoke test failed: {error}", file=sys.stderr)
        log = REPO / "build/server-smoke.log"
        if log.exists():
            print(log.read_text(errors="replace")[-12000:], file=sys.stderr)
        return 1
    print("PASS: HCOS Boot Webserver EFI booted with its injected agent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
