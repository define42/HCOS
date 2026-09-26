# HCOS

HCOS is a small, diskless x86_64 virtualization host built from Alpine Linux. The build produces one generic Unified Kernel Image (UKI), `dist/hcos-base.efi`. Following the [NetDesk boot design](https://github.com/define42/NetDesk/blob/83c7d1a4ac93ba72ebcac305678917aa524b72df/docs/boot-design.md), it embeds the Linux kernel, command line, and a compressed initramfs containing the complete root filesystem. Firmware loads one EFI file; Linux unpacks the filesystem into RAM and starts OpenRC.

The runtime includes KVM modules for Intel and AMD CPUs, the x86_64 QEMU system emulator, `qemu-img`, libvirt's QEMU, storage, and network drivers, `virtlogd`, `virtlockd`, and `virsh`. It does not install QEMU system emulators for other guest architectures. Package selection is in [`config/packages.txt`](config/packages.txt).

## Build and test

Use an x86_64 Linux host with Docker, Git, Make, Go 1.27 or newer, shellcheck, and Python 3. The build uses a digest-pinned Alpine 3.24.1 container and needs no privileged container. Packages are resolved from Alpine's 3.24 repositories when you build, so their versions can change within that branch.

```sh
make check                # Check scripts; run Go tests with the race detector and go vet.
make build                # Write dist/hcos-base.efi.
make components           # Build static linux/amd64 hcos-server, hcos-controller, hcos-agent.
make verify               # Check EFI sections, rootfs, modules, and tools.
make smoke                # Boot the generic base EFI in OVMF/QEMU.
make smoke-injected       # Boot an EFI with a sample agent and CA.
make smoke-server         # Build an EFI through the Go boot server and boot it.
make smoke-control-plane  # Exercise the real controller and agent with a fake virsh.
```

The EFI smoke tests need host `qemu-system-x86_64` and OVMF firmware. The injected and server tests also need OpenSSL. They use software emulation, so host KVM is not required. Run `make build` and `make components` before `make smoke-server`; `make smoke-control-plane` builds the Go components itself. Set both `OVMF_CODE` and `OVMF_VARS` to override firmware discovery. The default EFI test allows 300 seconds and 2 GiB guest RAM. Serial and QEMU logs are kept under `build/`.

GitHub Actions builds and tests on pushes, pull requests, and manual dispatch. A push to `main` builds each new mainline commit and publishes four immutable GitHub Release assets tagged `hcos-<commit SHA>`: `hcos-base.efi`, `hcos-server`, `hcos-controller`, and `hcos-agent`. A merge commit is a mainline state; commits that existed only on a merged feature branch are not separate mainline states. The newest successfully built main tip is marked as the latest release. The EFI asset remains generic; the boot server injects the selected agent and node config when requested.

Root login on the local VGA and serial consoles is locked by default. To enable it in a custom image, create a SHA-512 crypt hash in the local, ignored `config/root-password-hash` file before building. `openssl passwd -6` prompts for the password without putting it in the command line:

```sh
umask 077
openssl passwd -6 > config/root-password-hash
make build
```

Anyone with the EFI file can attempt to guess its embedded password hash offline. Use a strong, unique password and limit access to custom images.

## Boot-server injection

The Go boot server stores the generic `hcos-base.efi`. On an authorized `GET /boot/hcos.efi?node=<ID>&token=<BOOT_TOKEN>`, it selects the node's local assets and creates a root-owned, uncompressed Linux `newc` CPIO archive containing exactly these deployment files:

| Path | Mode | Purpose |
| --- | --- | --- |
| `/etc/hcos/root-ca.crt` | `0644` | Site root CA |
| `/etc/hcos/config.json` | `0600` or `0640` | Node configuration |
| `/usr/local/bin/hcos-agent` | `0755` | Foreground agent binary |

The server appends that archive to the **base EFI's `.initrd` payload**, after four-byte padding if needed, then constructs a new PE/EFI image whose `.initrd` section contains the combined bytes. The base initramfs is gzip-compressed CPIO; the supplemental archive is raw `newc` CPIO. [Linux permits both in one initramfs stream](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html). Appending CPIO bytes after the complete `.efi` file does not change the `.initrd` section seen by the [UKI stub](https://uapi-group.org/specifications/specs/unified_kernel_image/).

The server can then sign the final EFI for Secure Boot and return it as `/boot/hcos.efi` with `Content-Type: application/octet-stream`. Signing must happen after personalization, because changing a signed EFI invalidates its signature. This repository builds and releases an unsigned base image; without final signing, Secure Boot must be disabled.

During startup, `/init` checks that all three injected files exist. It copies the CA to `/usr/local/share/ca-certificates/hcos-root-ca.crt`, runs `update-ca-certificates`, then enables `/etc/init.d/hcos-agent` in OpenRC's default runlevel. The service uses `supervise-daemon` with a five-second respawn delay and passes `--config /etc/hcos/config.json`. The injected agent must remain in the foreground so OpenRC can supervise it. OpenRC orders it after `libvirtd` and waits for the `net` virtual service supplied by `dhcpcd`. A base image without an injected payload boots for diagnostics with no agent service enabled; an incomplete payload halts startup with an error on the console.

The boot server selects the base EFI, agent, and CA from local versioned directories. Its cache key includes the hashes of those assets, the injected config, and the signing identity. `scripts/test-injection.py` provides a build-and-boot example of the CPIO and EFI reconstruction steps. It does not put test credentials or the dummy agent into `hcos-base.efi`.

## Component setup

Place the release files and site CA in the paths selected by each node record. For the examples below, the layout is:

```text
/var/lib/hcos/
├── images/hcos-1.0.0.efi           # Copy of hcos-base.efi
├── agents/1.0.0/hcos-agent         # Executable release binary
├── trust/site-v1/root-ca.crt       # Public site CA certificate
└── cache/                          # Private, mode 0700
```

The boot server reads `/etc/hcos-server/server.json` by default. All configured paths must be absolute. Store `nodes.json` with mode `0600`; its embedded controller tokens are secrets. The cache directory must be owned by the boot server user and have mode `0700`, because cached personalized EFIs also contain those tokens.

```json
{
  "listen": "0.0.0.0:8443",
  "tls_cert": "/etc/hcos-server/boot.crt",
  "tls_key": "/etc/hcos-server/boot.key",
  "images_dir": "/var/lib/hcos/images",
  "agents_dir": "/var/lib/hcos/agents",
  "trust_dir": "/var/lib/hcos/trust",
  "cache_dir": "/var/lib/hcos/cache",
  "nodes_file": "/etc/hcos-server/nodes.json"
}
```

For `/etc/hcos-server/nodes.json`, use distinct secret boot and controller tokens. Generate each token separately, for example with `openssl rand -hex 32`. The `controller_token` must match the token for this node in the controller config. Optional `hcos_sha256`, `agent_sha256`, and `ca_sha256` fields pin the selected asset bytes.

```json
{
  "nodes": [{
    "id": "compute-01",
    "boot_token": "REPLACE_WITH_RANDOM_BOOT_TOKEN_AT_LEAST_32_CHARS",
    "hcos_version": "1.0.0",
    "agent_version": "1.0.0",
    "ca_version": "site-v1",
    "config": {
      "api_version": "hcos/v1",
      "node_id": "compute-01",
      "hostname": "compute-01",
      "controller": "https://controller.internal:9443",
      "controller_token": "REPLACE_WITH_RANDOM_NODE_TOKEN_AT_LEAST_32_CHARS",
      "storage": {"path": "/vm-storage"},
      "network": {"management_interface": "eno1", "vm_bridge": "br-vm"}
    }
  }]
}
```

The `network.management_interface` and `network.vm_bridge` fields are carried in node config; the current agent does not configure interfaces or create the named bridge. Configure a VM bridge separately before attaching guest interfaces to it.

The controller reads `/etc/hcos-controller/config.json` by default. Its `state_dir` must be a dedicated, clean absolute non-root path. Missing state directories are created privately; preexisting directories must already deny group and other access (use mode `0700`). Desired state and reports are stored there. The admin token must differ from every node token. Each token must contain 32–512 non-whitespace ASCII characters.

```json
{
  "listen_address": "0.0.0.0:9443",
  "tls_cert_file": "/etc/hcos-controller/controller.crt",
  "tls_key_file": "/etc/hcos-controller/controller.key",
  "state_dir": "/var/lib/hcos-controller",
  "admin_token": "REPLACE_WITH_RANDOM_ADMIN_TOKEN_AT_LEAST_32_CHARS",
  "nodes": [{
    "id": "compute-01",
    "token": "REPLACE_WITH_RANDOM_NODE_TOKEN_AT_LEAST_32_CHARS"
  }]
}
```

Run the two services with `dist/hcos-server --config /etc/hcos-server/server.json` and `dist/hcos-controller --config /etc/hcos-controller/config.json`. Both expose `GET /healthz` and `GET /readyz`. They require TLS on non-loopback listeners. The boot server also accepts `HEAD` for these endpoints and for the EFI endpoint.

A node boots from `https://boot.internal:8443/boot/hcos.efi?node=compute-01&token=<BOOT_TOKEN>` (also available at `/hcos.efi`). The boot token is a secret carried in the URL; protect firmware configuration and any proxy access logs that contain it. Firmware must already trust the boot server's HTTPS certificate. The injected `root-ca.crt` is installed only after download and must validate the controller's HTTPS certificate. No private CA key belongs in the image.

For Secure Boot, add a `signing` object to `server.json` with absolute `command`, `key`, and `certificate` paths plus a nonempty `revision`. For example, with [`sbsign`](https://github.com/msekletar/sbsigntool/blob/master/src/sbsign.c):

```json
"signing": {
  "command": "/usr/bin/sbsign",
  "key": "/etc/hcos-server/secure-boot.key",
  "certificate": "/etc/hcos-server/secure-boot.crt",
  "revision": "site-key-v1"
}
```

The command is called with `--key <key> --cert <certificate> --output <output.efi> <unsigned.efi>`; it must produce a signed PE image while preserving the assembled initramfs. Keep the signing key private. The cache includes the signing identity, so update `revision` when rotating the signing setup.

## Controller API and agent

The controller API uses `hcos/v1` JSON and bearer tokens. A node token can read its own desired state and post its own report. The admin token can read desired state, replace it with `PUT`, and read reports.

| Method and path | Token | Result |
| --- | --- | --- |
| `GET /v1/nodes/{id}/desired` | Node or admin | Current target; initially revision `0` with no domains |
| `PUT /v1/nodes/{id}/desired` | Admin | Replace the complete target; `204` on success |
| `POST /v1/nodes/{id}/report` | Node | Store the latest observed report; `204` on success |
| `GET /v1/nodes/{id}/report` | Admin | Latest report; `404` until the first report |

Save a desired state as `desired.json`. Use a new `revision` whenever its content changes; reusing a revision with different content returns `409`. The controller and agent accept at most 32 domains, each with an x86_64 KVM `hvm` libvirt XML definition.

```json
{
  "api_version": "hcos/v1",
  "revision": "1",
  "domains": [{
    "name": "guest-a",
    "xml": "<domain type='kvm'><name>guest-a</name><memory unit='KiB'>262144</memory><vcpu>1</vcpu><os><type arch='x86_64'>hvm</type></os><devices><emulator>/usr/bin/qemu-system-x86_64</emulator></devices></domain>",
    "running": true
  }]
}
```

```sh
curl --cacert /var/lib/hcos/trust/site-v1/root-ca.crt \
  -H "Authorization: Bearer $HCOS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @desired.json -X PUT \
  https://controller.internal:9443/v1/nodes/compute-01/desired

curl --cacert /var/lib/hcos/trust/site-v1/root-ca.crt \
  -H "Authorization: Bearer $HCOS_ADMIN_TOKEN" \
  https://controller.internal:9443/v1/nodes/compute-01/report
```

The agent reads `/etc/hcos/config.json` and `/etc/hcos/root-ca.crt` from the injected initramfs, then polls its controller every 15 seconds. It calls `virsh -c qemu:///system` to define requested persistent guests and start or gracefully shut them down. An absent guest in the desired list is left in libvirt; removal is an explicit administrative task. After each pass, the agent posts the revision, domain states (for example `running` or `shut off`), and any error. For diagnostics, `hcos-agent --config <file> --ca <CA> --virsh <path> --once` runs one pass; `--poll-interval` adjusts the continuous mode interval.

If `storage.path` is nonempty, it must name an exact mount point before the agent starts or resumes a guest. The base image does not mount a storage device, so attach and mount durable storage at that path first. An empty `storage.path` skips this check for installations that arrange storage separately. The sample XML above has no disk; add a libvirt disk pointing into mounted durable storage before using it for a real VM.

## Boot and administration

For UEFI HTTPS Boot, configure firmware to request its node-specific boot URL. For UEFI iPXE, for example:

```ipxe
dhcp
chain https://boot.internal:8443/boot/hcos.efi?node=compute-01&token=<BOOT_TOKEN>
```

Allow RAM for the downloaded EFI, its unpacked root filesystem, and the virtual machines you intend to run. Hardware acceleration requires CPU virtualization support enabled in firmware; the KVM loader permits QEMU software emulation when KVM is unavailable.

BusyBox `getty` offers authenticated login on the local VGA and serial consoles. With a root password configured, use these diagnostics:

```sh
rc-service hcos-agent status
rc-service libvirtd status
rc-service virtlogd status
rc-service virtlockd status
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system pool-list --all
qemu-system-x86_64 --version
qemu-img --version
```

The embedded root filesystem is temporary. `/var/lib/libvirt/images` starts in RAM, and VM disks placed there disappear on reboot. Attach and mount durable storage before creating VM disks, then point a libvirt storage pool at that mount. Persist libvirt definitions and other configuration under `/etc/libvirt` if they must survive reboot. The sample injected config names `/vm-storage` as a mount point but does not identify a block device or filesystem. The agent reports an error and leaves a stopped guest stopped until that path is mounted.

## Hardware and image size

[`config/modules.txt`](config/modules.txt) names the retained host kernel modules, including both x86 KVM variants, common wired NIC and storage drivers, bridge and TAP support. The build keeps their recursive dependencies and the netfilter module families needed by libvirt networking, then removes other modules. It also removes a duplicate kernel, package caches, documentation, locales, selected QEMU firmware files for unrelated platforms, and bundled libvirt daemons for other hypervisors. `linux-firmware-none` avoids Alpine's all-hardware firmware bundle; the package list adds Realtek NIC firmware.

For another host adapter or filesystem, add its module name to `config/modules.txt`. Add a matching firmware package to `config/packages.txt` when that device needs one. Rebuild and run both smoke tests. The build fails if a listed module is absent from the packaged kernel.

The NetDesk-derived boot and build code retains its [Apache 2.0 license and attribution](overlay/usr/share/licenses/NetDesk/NOTICE), which are embedded in the EFI image.
