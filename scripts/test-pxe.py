#!/usr/bin/env python3
"""Exercise DHCP, personalized TFTP scripts, and direct HTTP/HTTPS boot on loopback."""

from contextlib import ExitStack
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
CONTROLLER = ROOT / "dist/hcos-controller"
BOOTSERVER = ROOT / "dist/hcos-server"
LOADER = ROOT / "dist/bootx64.efi"
SERVER_IP = "127.0.0.1"


class TFTPError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(f"TFTP returned error code {code}")


def request(port, path, source="127.0.0.2", method="GET", tls=None, headers=None):
    client_type = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    options = {"timeout": 10, "source_address": (source, 0)}
    if tls:
        options["context"] = tls
    connection = client_type(SERVER_IP, port, **options)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def dhcp_boot_file(mac, source, ipxe=False):
    packet = bytearray(240)
    packet[:3] = b"\x01\x01\x06"
    packet[4:8] = secrets.token_bytes(4)
    packet[12:16] = socket.inet_aton(source)
    packet[28:34] = bytes.fromhex(mac.replace(":", ""))
    packet[236:240] = b"\x63\x82\x53\x63"
    # DHCPREQUEST renewal for this static address, with UEFI x64 architecture.
    packet.extend(b"\x35\x01\x03\x5d\x02\x00\x09")
    if ipxe:
        packet.extend(b"\x3c\x04iPXE")
    packet.append(255)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((source, 68))
        client.settimeout(1)
        for _ in range(5):
            client.sendto(packet, (SERVER_IP, 67))
            try:
                reply, peer = client.recvfrom(4096)
                break
            except socket.timeout:
                continue
        else:
            raise AssertionError("DHCP did not reply to the configured node")
    if (peer != (SERVER_IP, 67) or len(reply) < 240 or reply[:3] != b"\x02\x01\x06"
            or reply[4:8] != packet[4:8] or reply[16:20] != socket.inet_aton(source)
            or reply[20:24] != socket.inet_aton(SERVER_IP) or reply[28:34] != packet[28:34]
            or reply[236:240] != packet[236:240]):
        raise AssertionError("DHCP replied with the wrong node address or next server")
    options = {}
    offset = 240
    while offset < len(reply):
        code = reply[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        if offset >= len(reply) or offset + 1 + reply[offset] > len(reply):
            raise AssertionError("DHCP returned a truncated option")
        length = reply[offset]
        offset += 1
        options[code] = reply[offset:offset + length]
        offset += length
    if options.get(53) != b"\x05" or options.get(54) != socket.inet_aton(SERVER_IP):
        raise AssertionError("DHCP did not acknowledge the static lease")
    return options.get(67, b"").decode("ascii")


def tftp_file(filename, source="127.0.0.2"):
    rrq = b"\x00\x01" + filename.encode() + b"\x00octet\x00blksize\x001024\x00tsize\x000\x00"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((source, 0))
        client.settimeout(5)
        client.sendto(rrq, (SERVER_IP, 69))
        packet, transfer = client.recvfrom(2048)
        if packet[:2] == b"\x00\x05":
            raise TFTPError(struct.unpack("!H", packet[2:4])[0])
        if packet[:2] != b"\x00\x06" or b"blksize\x001024\x00" not in packet:
            raise AssertionError("TFTP option negotiation failed")
        options = packet[2:].rstrip(b"\x00").split(b"\x00")
        options = dict(zip(options[::2], options[1::2]))
        expected_size = int(options[b"tsize"])
        client.sendto(struct.pack("!HH", 4, 0), transfer)
        output = bytearray()
        block = 1
        while True:
            packet, peer = client.recvfrom(2048)
            if peer != transfer or packet[:4] != struct.pack("!HH", 3, block & 0xffff):
                raise AssertionError("TFTP used an unexpected peer or block number")
            data = packet[4:]
            output.extend(data)
            client.sendto(struct.pack("!HH", 4, block & 0xffff), transfer)
            if len(data) < 1024:
                break
            block += 1
        if len(output) != expected_size:
            raise AssertionError("TFTP returned an incomplete file")
        return bytes(output)


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def encoded_token(token):
    return (json.dumps(token, ensure_ascii=False)
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").encode())


def base_efi():
    # Minimal PE fixture, matching the assembler unit tests; it is never executed.
    image = bytearray(0x600)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3c, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HH", image, coff, 0x8664, 2)
    struct.pack_into("<H", image, coff + 16, 240)
    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x20b)
    for offset, value in ((8, 0x400), (32, 0x1000), (36, 0x200),
                          (56, 0x3000), (60, 0x200), (108, 16)):
        struct.pack_into("<I", image, optional + offset, value)
    struct.pack_into("<H", image, optional + 68, 10)
    section = optional + 240
    for name, address, file_offset in ((b".text", 0x1000, 0x200),
                                       (b".initrd", 0x2000, 0x400)):
        image[section:section + len(name)] = name
        struct.pack_into("<IIII", image, section + 8, 3, address, 0x200, file_offset)
        struct.pack_into("<I", image, section + 36, 0x40000040)
        section += 40
    image[0x200:0x203] = b"EFI"
    image[0x400:0x403] = b"\x1f\x8b\x08"
    return bytes(image)


def make_certificates(work):
    ca_cert, ca_key = work / "boot-ca.crt", work / "boot-ca.key"
    server_cert, server_key = work / "boot.crt", work / "boot.key"
    server_csr, extensions = work / "boot.csr", work / "boot.ext"
    extensions.write_text("subjectAltName=IP:127.0.0.1\n"
                          "basicConstraints=critical,CA:FALSE\n"
                          "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-days", "1", "-subj", "/CN=HCOS PXE Smoke CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-keyout", str(ca_key), "-out", str(ca_cert)],
        ["openssl", "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-subj", "/CN=127.0.0.1", "-keyout", str(server_key), "-out", str(server_csr)],
        ["openssl", "x509", "-req", "-in", str(server_csr),
         "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
         "-out", str(server_cert), "-days", "1", "-sha256", "-extfile", str(extensions)],
    ]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ca_cert, server_cert, server_key


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.returncode != 0:
        raise AssertionError(f"{Path(process.args[0]).name} exited with {process.returncode}")


def wait_ready(process, port, tls=None):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(f"{Path(process.args[0]).name} exited before readiness")
        try:
            status, _, _ = request(port, "/readyz", tls=tls)
            if status == 200:
                return
        except (ConnectionError, OSError):
            pass
        time.sleep(0.1)
    raise AssertionError(f"service on port {port} did not become ready")


def main():
    if not all(path.is_file() for path in (CONTROLLER, BOOTSERVER, LOADER)):
        raise SystemExit("Run 'make ipxe components' first")
    node_tokens = [secrets.token_hex(24) + "&+?#%=$" * 66 + "{}", secrets.token_hex(32)]
    node_ids = ["compute-01", "compute-02"]

    with tempfile.TemporaryDirectory(prefix="hcos-pxe-") as temporary, ExitStack() as stack:
        work = Path(temporary)
        ca_cert, server_cert, server_key = make_certificates(work)
        for directory in ("images", "agents/1.0.0", "trust/site-v1", "cache"):
            (work / directory).mkdir(parents=True, mode=0o700)
        (work / "images/hcos-1.0.0.efi").write_bytes(base_efi())
        agent = work / "agents/1.0.0/hcos-agent"
        agent.write_bytes(b"#!/bin/sh\n# HCOS PXE smoke agent\nexit 0\n")
        agent.chmod(0o755)
        (work / "trust/site-v1/root-ca.crt").write_bytes(ca_cert.read_bytes())
        nodes = []
        for index, node_id in enumerate(node_ids):
            nodes.append({
                "id": node_id,
                "hcos_version": "1.0.0", "agent_version": "1.0.0", "ca_version": "site-v1",
                "config": {
                    "api_version": "hcos/v1", "node_id": node_id, "hostname": node_id,
                    "controller": "http://127.0.0.1:9443",
                    "controller_token": node_tokens[index],
                    "storage": {"path": ""},
                    "network": {"management_interface": "eth0", "vm_bridge": "br-vm"},
                },
            })
        write_json(work / "nodes.json", {"nodes": nodes})
        server_config = {
            "listen": "127.0.0.1:8443", "pxe_http": True,
            "tls_cert": str(server_cert), "tls_key": str(server_key),
            "images_dir": str(work / "images"), "agents_dir": str(work / "agents"),
            "trust_dir": str(work / "trust"), "cache_dir": str(work / "cache"),
            "nodes_file": str(work / "nodes.json"),
        }
        write_json(work / "server.json", server_config)
        write_json(work / "controller.json", {
            "server_ip": SERVER_IP, "state_dir": str(work / "state"),
            "admin_token": secrets.token_hex(32),
            "nodes": [{
                "id": node_id, "token": node_tokens[index],
                "mac": f"52:54:00:12:34:{index + 56:02d}", "ip": f"127.0.0.{index + 2}",
            } for index, node_id in enumerate(node_ids)],
            "pxe": {
                "dhcp": {"interface": "lo", "subnet_mask": "255.0.0.0"},
            },
        })
        processes = []
        for binary, config_name, log_name in (
                (BOOTSERVER, "server.json", "server.log"),
                (CONTROLLER, "controller.json", "controller.log")):
            output = stack.enter_context((work / log_name).open("wb"))
            process = subprocess.Popen([str(binary), "-config", str(work / config_name)],
                                       stdout=output, stderr=subprocess.STDOUT, cwd=work)
            stack.callback(stop_process, process)
            processes.append(process)
        bootserver, controller = processes
        tls = ssl.create_default_context(cafile=str(ca_cert))
        wait_ready(bootserver, 8443, tls=tls)
        wait_ready(controller, 9443)
        wait_ready(bootserver, 80)
        firmware_file = dhcp_boot_file("52:54:00:12:34:56", "127.0.0.2")
        if firmware_file != "bootx64.efi":
            raise AssertionError("DHCP did not advertise the embedded iPXE loader")
        loader = tftp_file(firmware_file)
        if not loader.startswith(b"MZ") or hashlib.sha256(loader).digest() != hashlib.sha256(LOADER.read_bytes()).digest():
            raise AssertionError("TFTP loader differs from the embedded release loader")
        paths = []
        for index, node_id in enumerate(node_ids):
            source = f"127.0.0.{index + 2}"
            mac = f"52:54:00:12:34:{index + 56:02d}"
            script_url = urlsplit(dhcp_boot_file(mac, source, ipxe=True))
            if (script_url.scheme != "tftp" or script_url.netloc != SERVER_IP
                    or script_url.path != "/boot.ipxe" or script_url.query or script_url.fragment):
                raise AssertionError("DHCP did not advertise the controller TFTP script")
            script = tftp_file(script_url.path.lstrip("/"), source=source).decode()
            lines = script.splitlines()
            if len(lines) != 2 or lines[0] != "#!ipxe" or not lines[1].startswith("chain "):
                raise AssertionError("TFTP did not return the expected iPXE script")
            url = urlsplit(lines[1][6:])
            query = parse_qs(url.query, strict_parsing=True)
            if (url.scheme != "http" or url.netloc != SERVER_IP or url.path != "/boot/hcos.efi"
                    or query != {"node": [node_id], "token": [node_tokens[index]]}):
                raise AssertionError("iPXE script did not select the matching node and token")
            paths.append(url.path + "?" + url.query)
            # Use the exact credential from the boot script for agent API access.
            credential = query["token"][0]
            for target, expected_status in ((node_id, 200), (node_ids[1 - index], 401)):
                status, _, _ = request(
                    9443, f"/v1/nodes/{target}/desired",
                    headers={"Authorization": "Bearer " + credential},
                )
                if status != expected_status:
                    raise AssertionError("script credential did not preserve controller node isolation")
        try:
            tftp_file("boot.ipxe", source="127.0.0.4")
        except TFTPError as error:
            if error.code not in (1, 2):
                raise AssertionError("unknown TFTP client returned an unexpected error") from None
        else:
            raise AssertionError("unknown source IP received a personalized script")

        images = []
        for index, path in enumerate(paths):
            source = f"127.0.0.{index + 2}"
            status, headers, image = request(80, path, source=source)
            if (status != 200 or not image.startswith(b"MZ")
                    or len(image) != int(headers.get("Content-Length", "0"))
                    or encoded_token(node_tokens[index]) not in image
                    or encoded_token(node_tokens[1 - index]) in image
                    or b"usr/local/bin/hcos-agent" not in image):
                raise AssertionError("HTTP did not deliver the correct personalized EFI")
            status, headers, body = request(80, path, source=source, method="HEAD")
            if status != 200 or body or int(headers.get("Content-Length", "0")) != len(image):
                raise AssertionError("HTTP HEAD differs from the personalized EFI")
            status, _, secure_image = request(8443, path, source=source, tls=tls)
            if status != 200 or secure_image != image:
                raise AssertionError("HTTP and HTTPS did not serve the same personalized EFI")
            images.append(image)
        if images[0] == images[1] or len(list((work / "cache").glob("*.efi"))) != 2:
            raise AssertionError("node cache entries were not distinct and shared between listeners")
        for port, context in ((80, None), (8443, tls)):
            for path in ("/boot/hcos.efi", "/boot/hcos.efi?node=compute-01&token=wrong",
                         "/boot/hcos.efi?node=compute-02&token=" + quote(node_tokens[0], safe="")):
                status, _, _ = request(port, path, tls=context)
                if status != 403:
                    raise AssertionError(f"port {port} accepted a missing or incorrect node token")
        # Downloads remain available after DHCP/TFTP and the controller API stop.
        stop_process(controller)
        status, _, image = request(80, paths[0])
        if status != 200 or image != images[0]:
            raise AssertionError("direct EFI download depended on the controller")
        stop_process(bootserver)
        for log_name in ("server.log", "controller.log"):
            log = (work / log_name).read_text(encoding="utf-8")
            if any(token in log or quote(token, safe="") in log
                   or encoded_token(token).decode() in log for token in node_tokens):
                raise AssertionError("a service logged a node token")
    print("PASS: DHCP to TFTP to direct HTTP EFI; shared node authentication; HTTPS; downloads with controller stopped")


if __name__ == "__main__":
    main()
