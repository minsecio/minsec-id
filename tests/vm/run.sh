#!/usr/bin/env bash
# Run a script as root in a throwaway VM booted from the host's own kernel,
# with the host's root filesystem shared read-only (9p) under a tmpfs
# overlay. For testing the eBPF daemon and root-only checks without root on
# the host: only /dev/kvm access is needed.
#
#   tests/vm/run.sh SCRIPT [ARGS...]
#
# SCRIPT runs inside the VM with the current directory set to the repo; its
# output appears on stdout and its exit status is this script's.
set -euo pipefail

script=$(realpath "$1")
shift
repo=$(cd "$(dirname "$0")/../.." && pwd)
kver=${KVER:-$(uname -r)}
kernel=${KERNEL:-/boot/vmlinuz-$kver}
# Not under /tmp: the VM mounts its own tmpfs there.
mkdir -p "$repo/target"
work=$(mktemp -d "$repo/target/vm.XXXXXX")
[ -n "${VM_KEEP:-}" ] || trap 'rm -rf "$work"' EXIT

ir=$work/initramfs
mkdir -p "$ir"/{bin,lib64,proc,sys,dev,lower,upper,newroot,modules}

# Tools for the init script, with their libraries.
for b in bash mount insmod chroot mkdir cat; do
	p=$(command -v "$b" || echo "/usr/sbin/$b")
	cp -L "$p" "$ir/bin/$b"
	ldd "$p" | awk '/=>/ {print $3} /^\t\// {print $1}' | while read -r l; do
		[ -n "$l" ] && cp -Ln "$l" "$ir/lib64/" 2>/dev/null || true
	done
done
for m in netfs 9pnet 9pnet_virtio 9p overlay; do
	cp "$(modinfo -k "$kver" -n "$m")" "$ir/modules/"
done

cat >"$ir/init" <<'INIT'
#!/bin/bash
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
for m in netfs 9pnet 9pnet_virtio 9p overlay; do insmod /modules/$m.ko* || true; done
mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=524288 hostroot /lower
mount -t tmpfs -o size=1G upper /upper
mkdir -p /upper/u /upper/w
mount -t overlay overlay -o lowerdir=/lower,upperdir=/upper/u,workdir=/upper/w /newroot
exec chroot /newroot /bin/bash -c '
	mount -t proc proc /proc
	mount -t sysfs sys /sys
	mount -t devtmpfs dev /dev
	mount -t tmpfs tmp /tmp
	mount -t tmpfs run /run
	mount -t bpf bpf /sys/fs/bpf 2>/dev/null
	mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
	mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
	mkdir -p /var/lib/minsec-id
	set -- $(cat /proc/cmdline)
	for a; do case $a in minsec.repo=*) repo=${a#*=};; minsec.script=*) script=${a#*=};; esac; done
	echo VM-START
	cd "$repo" && bash "$script"
	echo "VM-EXIT-STATUS=$?"
	echo o >/proc/sysrq-trigger
	sleep 10
'
INIT
chmod +x "$ir/init"
(cd "$ir" && find . | cpio -o -H newc --quiet) >"$work/initramfs.cpio"

# Arguments for the script go through a file in the shared tree.
args=$work/args
printf '%q ' "$@" >"$args"
cp "$script" "$work/script.sh"
wrapper=$work/wrapper.sh
printf 'source %q %s\n' "$work/script.sh" "$(cat "$args")" >"$wrapper"
chmod 644 "$wrapper"
chmod 755 "$work"

out=$work/console
timeout "${VM_TIMEOUT:-300}" qemu-system-x86_64 \
	-enable-kvm -cpu host -smp 2 -m 2G -nographic -no-reboot \
	-kernel "$kernel" -initrd "$work/initramfs.cpio" \
	-append "console=ttyS0 quiet loglevel=3 panic=-1 rdinit=/init minsec.repo=$repo minsec.script=$wrapper" \
	-virtfs local,path=/,mount_tag=hostroot,security_model=none,readonly=on,multidevs=remap \
	</dev/null | tee "$out" | tr -d "\r" | sed -un "/VM-START$/,/^VM-EXIT-STATUS=/{/VM-START$/d;/^VM-EXIT-STATUS=/d;p}" || true
status=$(grep -ao 'VM-EXIT-STATUS=[0-9]*' "$out" | tail -1 | cut -d= -f2)
exit "${status:-1}"
