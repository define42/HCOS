#!/usr/bin/env python3
"""Exercise controller API and real agent against an isolated fake virsh."""

import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
CONTROLLER = ROOT / "dist/hcos-controller"
AGENT = ROOT / "dist/hcos-agent"
DOMAIN_XML = (
    '<domain type="kvm"><name>guest-a</name><memory unit="KiB">262144</memory>'
    '<vcpu>1</vcpu><os><type arch="x86_64">hvm</type></os>'
    '<devices><emulator>/usr/bin/qemu-system-x86_64</emulator></devices></domain>'
)


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def request(base, path, token=None, method="GET", body=None, tls=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=tls, timeout=5) as response:
            data = response.read()
            return response.status, json.loads(data) if data.startswith(b"{") else data
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def expect_status(actual, expected, context):
    if actual != expected:
        raise AssertionError(f"{context}: expected HTTP {expected}, got {actual}")


def main():
    if not CONTROLLER.is_file() or not AGENT.is_file():
        raise SystemExit("Run 'make components' before this integration test")
    with tempfile.TemporaryDirectory(prefix="hcos-control-") as temp:
        work = Path(temp)
        cert = work / "controller.crt"
        key = work / "controller.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"https://127.0.0.1:{port}"
        admin_token = secrets.token_hex(32)
        node_token = secrets.token_hex(32)
        controller_config = work / "controller.json"
        write_json(controller_config, {
            "listen_address": f"127.0.0.1:{port}",
            "tls_cert_file": str(cert), "tls_key_file": str(key),
            "state_dir": str(work / "state"), "admin_token": admin_token,
            "nodes": [{"id": "compute-01", "token": node_token}],
        })
        agent_config = work / "agent.json"
        write_json(agent_config, {
            "api_version": "hcos/v1", "node_id": "compute-01",
            "hostname": "compute-01", "controller": base,
            "controller_token": node_token, "registry": "",
            "storage": {"path": ""},
            "network": {"management_interface": "eno1", "vm_bridge": "br-vm"},
        })
        virsh = work / "virsh"
        virsh.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
assert args[:2] == ["-c", "qemu:///system"], args
command = args[2]
state = Path(os.environ["HCOS_FAKE_VIRSH_STATE"])
log = Path(os.environ["HCOS_FAKE_VIRSH_LOG"])
with log.open("a", encoding="utf-8") as output:
    output.write(command + "\\n")
if command == "define":
    if not state.exists():
        state.write_text("shut off", encoding="utf-8")
elif command == "domstate":
    if not state.exists():
        raise SystemExit(1)
    print(state.read_text(encoding="utf-8"))
elif command == "start":
    state.write_text("running", encoding="utf-8")
elif command == "shutdown":
    state.write_text("shut off", encoding="utf-8")
else:
    raise SystemExit("unexpected virsh command: " + command)
''', encoding="utf-8")
        virsh.chmod(0o700)
        env = os.environ.copy()
        env["HCOS_FAKE_VIRSH_STATE"] = str(work / "guest-state")
        env["HCOS_FAKE_VIRSH_LOG"] = str(work / "virsh.log")
        tls = ssl.create_default_context(cafile=str(cert))
        with (work / "controller.log").open("wb") as log:
            controller = subprocess.Popen(
                [str(CONTROLLER), "-config", str(controller_config)],
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(100):
                    if controller.poll() is not None:
                        raise AssertionError(f"controller exited with {controller.returncode}")
                    try:
                        status, _ = request(base, "/readyz", tls=tls)
                        if status == 200:
                            break
                    except (OSError, ssl.SSLError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("controller did not become ready")
                path = "/v1/nodes/compute-01/desired"
                status, _ = request(base, path, "wrong-token", tls=tls)
                expect_status(status, 401, "unauthorized desired fetch")
                status, desired = request(base, path, node_token, tls=tls)
                expect_status(status, 200, "initial desired fetch")
                assert desired["revision"] == "0" and desired["domains"] == [], desired
                running = {"api_version": "hcos/v1", "revision": "1", "domains": [
                    {"name": "guest-a", "xml": DOMAIN_XML, "running": True}
                ]}
                status, _ = request(base, path, admin_token, "PUT", running, tls)
                expect_status(status, 204, "publish running desired state")
                status, _ = request(base, path, admin_token, "PUT", {
                    **running, "domains": [{**running["domains"][0], "running": False}]
                }, tls)
                expect_status(status, 409, "revision conflict")
                agent_command = [str(AGENT), "--config", str(agent_config),
                                 "--ca", str(cert), "--virsh", str(virsh), "--once"]
                subprocess.run(agent_command, env=env, check=True, timeout=20,
                               stdout=subprocess.DEVNULL)
                assert (work / "guest-state").read_text() == "running"
                report_path = "/v1/nodes/compute-01/report"
                status, report = request(base, report_path, admin_token, tls=tls)
                expect_status(status, 200, "running report")
                assert report["revision"] == "1" and report["domains"] == [
                    {"name": "guest-a", "state": "running"}
                ], report
                stopped = {"api_version": "hcos/v1", "revision": "2", "domains": [
                    {"name": "guest-a", "xml": DOMAIN_XML, "running": False}
                ]}
                status, _ = request(base, path, admin_token, "PUT", stopped, tls)
                expect_status(status, 204, "publish stopped desired state")
                subprocess.run(agent_command, env=env, check=True, timeout=20,
                               stdout=subprocess.DEVNULL)
                assert (work / "guest-state").read_text() == "shut off"
                status, report = request(base, report_path, admin_token, tls=tls)
                expect_status(status, 200, "stopped report")
                assert report["revision"] == "2" and report["domains"] == [
                    {"name": "guest-a", "state": "shut off"}
                ], report
                actions = (work / "virsh.log").read_text().splitlines()
                assert "define" in actions and "start" in actions and "shutdown" in actions, actions
            finally:
                controller.terminate()
                try:
                    controller.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
    print("PASS: controller and agent exchanged desired state and reports over TLS; virsh was reconciled")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise
