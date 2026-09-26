# HCOS

HCOS is a small, diskless x86_64 virtualization host built from Alpine Linux. The build produces one deployable file, `dist/hcos.efi`. Following the [NetDesk boot design](https://github.com/define42/NetDesk/blob/83c7d1a4ac93ba72ebcac305678917aa524b72df/docs/boot-design.md), this Unified Kernel Image (UKI) embeds the Linux kernel, its command line, and a compressed initramfs containing the complete root filesystem. Firmware loads the EFI file; Linux unpacks the filesystem into RAM and starts BusyBox init and OpenRC. No separate root filesystem is fetched or mounted.

The runtime includes KVM modules for Intel and AMD CPUs, the x86_64 QEMU system emulator, `qemu-img`, libvirt's QEMU, storage, and network drivers, `virtlogd`, `virtlockd`, and `virsh`. It does not install QEMU system emulators for other guest architectures. The package selection is in [`config/packages.txt`](config/packages.txt); Alpine's [package index](https://pkgs.alpinelinux.org/packages?branch=v3.24&name=libvirt-qemu) shows the libvirt QEMU package and its current dependencies.

## Build and test

Use an x86_64 Linux host with Docker, Git, and Make. The build uses a digest-pinned Alpine 3.24.1 container and needs no privileged container. Packages are resolved from Alpine's 3.24 repositories when you build, so their versions can change within that branch.

```sh
make check    # Requires shellcheck and Python 3 on the host.
make build    # Writes dist/hcos.efi.
make verify   # Checks EFI sections, the rootfs, modules, and virtualization tools.
make smoke    # Boots the real EFI file over HTTP in a diskless OVMF/QEMU VM.
```

GitHub Actions runs these checks on every push, pull request, and manual dispatch. It uploads `hcos.efi` as a 14-day Actions artifact. Each successful push to `main` also publishes a GitHub Release tagged `hcos-<commit SHA>` with the EFI file attached. As in NetDesk, a push containing several commits creates one release for the push's head commit.

`make smoke` needs host `qemu-system-x86_64` and OVMF firmware. It uses software emulation, so host KVM is not required. It discovers common OVMF locations; set both `OVMF_CODE` and `OVMF_VARS` to override them. The default test allows 300 seconds and 2 GiB guest RAM. Serial and QEMU logs are kept under `build/`. A passing test means OpenRC reached `hcos-ready`, which checked the QEMU tools, connected to libvirt's QEMU and storage interfaces, confirmed the default guest network is active, and reached the authenticated serial login prompt.

Root login on the local VGA and serial consoles is locked by default. To enable it in a custom image, create a SHA-512 crypt hash in the local, ignored `config/root-password-hash` file before building. `openssl passwd -6` prompts for the password without putting it in the command line:

```sh
umask 077
openssl passwd -6 > config/root-password-hash
make build
```

The build reads that file and sets the root password hash in the image. Anyone with the EFI file can attempt to guess the embedded hash offline, so use a strong, unique password and limit access to the image. Omit the file to keep root login locked.

## Boot

Serve `hcos.efi` as a direct HTTP download with `Content-Type: application/efi`. From x86_64 UEFI iPXE, for example:

```ipxe
dhcp
chain http://192.0.2.10/hcos.efi
```

For UEFI HTTP Boot, configure the firmware boot URL to the same EFI file. The image is unsigned, so Secure Boot must be disabled. Allow RAM for the downloaded image, its unpacked root filesystem, and the virtual machines you intend to run.

OpenRC starts device discovery, DHCP, the KVM loader, libvirt logging and locking, `libvirtd`, and a runtime readiness check. Hardware acceleration requires CPU virtualization support enabled in firmware; the KVM loader permits QEMU software emulation when KVM is unavailable.

## Hardware and image size

[`config/modules.txt`](config/modules.txt) names the host kernel modules to retain, including both x86 KVM variants, common wired NIC and storage drivers, bridge and TAP support. The build keeps their recursive dependencies and the netfilter module families needed by libvirt networking, then removes other modules. It also removes a duplicate kernel, package caches, documentation, locales, selected QEMU firmware files for unrelated platforms, and bundled libvirt daemons for other hypervisors. `linux-firmware-none` avoids Alpine's all-hardware firmware bundle; the current package list adds Realtek NIC firmware.

For another host adapter or filesystem, add its module name to `config/modules.txt`. Add a matching firmware package to `config/packages.txt` when that device needs one. Rebuild and run `make verify` and `make smoke`. The build fails if a listed module is absent from the packaged kernel.

## Administration and storage

BusyBox `getty` offers authenticated login on the local VGA and serial consoles. Root remains locked unless `config/root-password-hash` was supplied at build time. With that password configured, log in as root at either console to run these diagnostics. HCOS does not start SSH or another remote login service.

```sh
rc-service libvirtd status
rc-service virtlogd status
rc-service virtlockd status
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system pool-list --all
qemu-system-x86_64 --version
qemu-img --version
```

The embedded root filesystem is temporary. In particular, `/var/lib/libvirt/images` starts in RAM, and VM disk files placed there disappear on reboot. Attach and mount durable storage before creating VM disks, then point a libvirt storage pool at that mount. Persist libvirt definitions and other configuration under `/etc/libvirt` as well if they must survive reboot. HCOS does not mount persistent storage automatically; add the required mount to the boot configuration before `libvirtd` starts.

The NetDesk-derived boot and build code retains its [Apache 2.0 license and attribution](overlay/usr/share/licenses/NetDesk/NOTICE), which are embedded in the EFI image.
