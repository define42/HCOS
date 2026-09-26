#!/bin/sh
# Adapted from NetDesk's Apache-2.0 image builder for HCOS.
# shellcheck disable=SC2016
# Runs as root inside the disposable Alpine builder.
set -eu
# Alpine's BusyBox ash supports pipefail.
# shellcheck disable=SC3040
set -o pipefail
umask 022
export LC_ALL=C

if [ ! -f /etc/alpine-release ] || [ ! -d /out ] || [ ! -d /src/overlay ]; then
    echo 'Run make build to invoke this script in its container.' >&2
    exit 1
fi
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set}"
work=$(mktemp -d /tmp/hcos.XXXXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
root=$work/rootfs
mkdir -p "$root/etc/apk/keys" "$root/dev" "$root/proc" "$root/sys" "$root/run"
cp /etc/apk/keys/* "$root/etc/apk/keys/"
cp /etc/apk/repositories "$root/etc/apk/repositories"
cp /etc/resolv.conf "$root/etc/resolv.conf"
mknod -m 600 "$root/dev/console" c 5 1
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/random" c 1 8
mknod -m 666 "$root/dev/urandom" c 1 9

set --
while IFS= read -r line || [ -n "$line" ]; do
    package=${line%%#*}
    package=$(printf '%s' "$package" | tr -d '[:space:]')
    [ -n "$package" ] || continue
    case "$package" in
        -*|*[!a-zA-Z0-9._+-]*) echo "Invalid package: $package" >&2; exit 1 ;;
    esac
    set -- "$@" "$package"
done < /src/config/packages.txt
apk --root "$root" --initdb --no-cache add "$@"

cp -a --no-preserve=ownership /src/overlay/. "$root/"
chmod 0755 "$root/init" "$root"/etc/init.d/hcos-*
if [ -f /src/config/root-password-hash ]; then
    hash=$(cat /src/config/root-password-hash)
    if ! printf '%s\n' "$hash" |
        grep -Eq '^\$6\$(rounds=[0-9]+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]+$'; then
        echo 'root-password-hash must contain one SHA-512 crypt hash.' >&2
        exit 1
    fi
    printf 'root:%s\n' "$hash" | chroot "$root" chpasswd -e
else
    chroot "$root" passwd -l root
fi

# dhcpcd needs localmount; fstab contains no host disks.
rm -rf "$root/etc/runlevels"
mkdir -p "$root/etc/runlevels/sysinit" "$root/etc/runlevels/boot" \
    "$root/etc/runlevels/default" "$root/etc/runlevels/shutdown"
for service in devfs dmesg udev udev-trigger udev-settle; do
    chroot "$root" rc-update add "$service" sysinit
done
for service in hostname modules sysctl bootmisc localmount loopback; do
    chroot "$root" rc-update add "$service" boot
done
for service in dhcpcd hcos-kvm virtlogd virtlockd libvirtd hcos-ready; do
    chroot "$root" rc-update add "$service" default
done
chroot "$root" rc-update add killprocs shutdown

set -- "$root"/lib/modules/*
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo 'Expected one kernel module tree.' >&2
    exit 1
fi
module_root=$1
kernel_version=${module_root##*/}
chroot "$root" depmod "$kernel_version"
cp "$root/boot/vmlinuz-lts" "$work/vmlinuz"

# Retain selected host drivers and all recursive module dependencies.
# Keep netfilter as a group because libvirt builds NAT rules dynamically.
keep=$work/modules.keep
: > "$keep"
retain_module() {
    module=$1
    modprobe --show-depends --dirname "$root" --set-version "$kernel_version" \
        "$module" > "$work/modprobe.out" || {
            echo "Kernel lacks required module: $module" >&2
            exit 1
        }
    awk '$1 == "insmod" { print $2 }' "$work/modprobe.out" >> "$keep"
}
while IFS= read -r line || [ -n "$line" ]; do
    module=${line%%#*}
    module=$(printf '%s' "$module" | tr -d '[:space:]')
    [ -n "$module" ] || continue
    case "$module" in
        -*|*[!a-zA-Z0-9_+-]*) echo "Invalid module: $module" >&2; exit 1 ;;
    esac
    retain_module "$module"
done < /src/config/modules.txt
for tree in kernel/net/netfilter kernel/net/ipv4/netfilter \
    kernel/net/ipv6/netfilter kernel/net/bridge/netfilter; do
    [ -d "$module_root/$tree" ] || continue
    find "$module_root/$tree" -type f -name '*.ko*' | while IFS= read -r path; do
        name=${path##*/}
        name=${name%%.ko*}
        retain_module "$name"
    done
done
sort -u "$keep" -o "$keep"
find "$module_root/kernel" -type f -name '*.ko*' | while IFS= read -r path; do
    grep -Fxq "$path" "$keep" || rm "$path"
done
find "$module_root/kernel" -depth -type d -empty -delete
chroot "$root" depmod "$kernel_version"

# The kernel is the UKI's .linux section, not a duplicate in .initrd.
rm -rf "${root:?}/boot" "$root/var/cache/apk" "$root/var/log"/* "$root/tmp"/*
rm -f "$module_root/vmlinuz" "$root/usr/bin/qemu-microblazeel" \
    "$root/usr/share/qemu/edk2-i386-vars.fd"
# Alpine's libvirt base APK bundles daemons for unrelated hypervisors.
for daemon in virtchd virtlxcd virtvboxd virtxend; do
    rm -f "$root/usr/sbin/$daemon" "$root/etc/init.d/$daemon" \
        "$root/etc/libvirt/$daemon.conf"
done
rm -f "$root/etc/libvirt/ch.conf" \
    "$root/usr/lib/libvirt/connection-driver/libvirt_driver_ch.so"
rm -rf "$root/usr/share/qemu/dtb" "$root/usr/share/man" "$root/usr/share/doc" \
    "$root/usr/share/info" "$root/usr/share/locale"
for blob in 'QEMU,cgthree.bin' 'QEMU,tcx.bin' ast27x0_bootrom.bin \
    npcm7xx_bootrom.bin npcm8xx_bootrom.bin pnv-pnor.bin skiboot.lid \
    slof.bin vof.bin vof-nvram.bin qemu_vga.ndrv; do
    rm -f "$root/usr/share/qemu/$blob"
done
mkdir -p "$root/boot" "$root/var/cache/apk" "$root/tmp" \
    "$root/var/lib/libvirt/images"
chmod 1777 "$root/tmp"
: > "$root/etc/resolv.conf"
rm -f "$root/etc/machine-id" "$root/var/lib/dbus/machine-id" "$root/etc/.pwd.lock"
chroot "$root" apk list --installed > "$root/etc/hcos-packages.txt"

printf 'HCOS root filesystem: '
du -sh "$root"
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(
    cd "$root"
    find . -print0 | sort -z | cpio --null --create --format=newc --reproducible --quiet | gzip -n -6
) > "$work/rootfs.cpio.gz"
ukify build --linux "$work/vmlinuz" --initrd "$work/rootfs.cpio.gz" \
    --cmdline @/src/config/cmdline --os-release "@$root/etc/os-release" \
    --uname "$kernel_version" --efi-arch x64 \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "$work/hcos.efi"
python3 /src/scripts/verify-image.py "$work/hcos.efi"
install -m 0644 "$work/hcos.efi" /out/.hcos.efi.tmp
chown "${OUTPUT_UID:-0}:${OUTPUT_GID:-0}" /out/.hcos.efi.tmp
mv /out/.hcos.efi.tmp /out/hcos.efi
printf 'Built '
ls -lh /out/hcos.efi
