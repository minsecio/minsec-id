#!/usr/bin/env bash
# Run a script as root in a throwaway VM of a distribution's own cloud
# image, for what run.sh (the host's kernel and root) cannot test: snapd on
# Ubuntu, an ostree-booted Fedora CoreOS. Only /dev/kvm access and network
# are needed.
#
#   tests/vm/cloud.sh IMAGE SCRIPT [ARGS...]
#
# IMAGE is one of: ubuntu-24.04, fcos. The image is downloaded once, checked
# against its published SHA-256, and kept in target/vm-images/; each run
# boots it with -snapshot, so it is never modified. The repo is shared
# read-only at /repo (9p) and SCRIPT runs there as root, with network
# through qemu's user mode. Its output appears on stdout and its exit
# status is this script's. VM_TIMEOUT (seconds, default 900) bounds a run.
set -euo pipefail

image=$1
script=$2
shift 2
repo=$(cd "$(dirname "$0")/../.." && pwd)
case $script in
/*) rel=${script#"$repo"/} ;;
*) rel=$script ;;
esac
[ -f "$repo/$rel" ] || {
	echo "cloud.sh: $script is not in the repo" >&2
	exit 1
}
cache=$repo/target/vm-images
mkdir -p "$cache"
work=$(mktemp -d "$repo/target/vm.XXXXXX")
[ -n "${VM_KEEP:-}" ] || trap 'rm -rf "$work"' EXIT

# fetch URL SUMS_URL: download into the cache once, verified.
fetch() {
	local url=$1 sums=$2 name
	name=$(basename "$url")
	if ! [ -f "$cache/$name" ]; then
		echo "cloud.sh: downloading $name" >&2
		curl -fsSL --retry 3 -o "$cache/$name.part" "$url"
		curl -fsSL --retry 3 -o "$cache/$name.sums" "$sums"
		local want
		want=$(grep -E "[ *]$name\$|\($name\)" "$cache/$name.sums" | grep -Eo '[0-9a-f]{64}' | head -1)
		[ -n "$want" ] || {
			echo "cloud.sh: no checksum for $name" >&2
			exit 1
		}
		echo "$want  $cache/$name.part" | sha256sum -c --quiet
		mv "$cache/$name.part" "$cache/$name"
	fi
	echo "$cache/$name"
}

# The runner: mount the repo, run the script between markers on the second
# serial port (the first is the console), power off.
args=$(printf ' %q' "$@")
runner="mkdir -p /repo && mount -t 9p -o trans=virtio,version=9p2000.L,ro repo /repo && cd /repo && { echo VM-START; bash $(printf %q "$rel")$args; echo \"VM-EXIT-STATUS \$?\"; } >/dev/ttyS1 2>&1; systemctl poweroff"

case $image in
ubuntu-24.04)
	base=https://cloud-images.ubuntu.com/releases/noble/release
	disk=$(fetch "$base/ubuntu-24.04-server-cloudimg-amd64.img" "$base/SHA256SUMS")
	# cloud-init's NoCloud seed: a volume labelled cidata.
	mkdir -p "$work/seed"
	echo "instance-id: minsec-id-test" >"$work/seed/meta-data"
	cat >"$work/seed/user-data" <<EOF
#cloud-config
runcmd:
  - [bash, -c, $(printf '%s' "$runner" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')]
EOF
	genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/seed"
	extra=(-drive "file=$work/seed.iso,if=virtio,format=raw,readonly=on")
	fmt=qcow2
	;;
fcos)
	stream=https://builds.coreos.fedoraproject.org/streams/stable.json
	meta=$(curl -fsSL "$stream")
	loc=$(printf '%s' "$meta" | python3 -c 'import json,sys; d=json.load(sys.stdin)["architectures"]["x86_64"]["artifacts"]["qemu"]["formats"]["qcow2.xz"]["disk"]; print(d["location"], d["sha256"])')
	url=${loc% *}
	sum=${loc#* }
	name=$(basename "$url" .xz)
	if ! [ -f "$cache/$name" ]; then
		echo "cloud.sh: downloading $(basename "$url")" >&2
		curl -fsSL --retry 3 -o "$cache/$name.xz.part" "$url"
		echo "$sum  $cache/$name.xz.part" | sha256sum -c --quiet
		xz -dc "$cache/$name.xz.part" >"$cache/$name.part"
		rm "$cache/$name.xz.part"
		mv "$cache/$name.part" "$cache/$name"
	fi
	disk=$cache/$name
	# Ignition: a unit that runs the script once the system is up.
	python3 - "$runner" >"$work/config.ign" <<'EOF'
import json, sys
unit = """[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash -c %s
[Install]
WantedBy=multi-user.target
""" % json.dumps(sys.argv[1])
print(json.dumps({
    "ignition": {"version": "3.4.0"},
    "systemd": {"units": [{"name": "minsec-id-test.service", "enabled": True, "contents": unit}]},
}))
EOF
	extra=(-fw_cfg "name=opt/com.coreos/config,file=$work/config.ign")
	fmt=qcow2
	;;
*)
	echo "cloud.sh: unknown image $image (ubuntu-24.04, fcos)" >&2
	exit 1
	;;
esac

timeout "${VM_TIMEOUT:-900}" qemu-system-x86_64 \
	-machine q35,accel=kvm -cpu host -m 3072 -smp 2 \
	-display none -no-reboot -snapshot \
	-drive "file=$disk,if=virtio,format=$fmt" \
	"${extra[@]}" \
	-virtfs "local,path=$repo,mount_tag=repo,security_model=none,readonly=on" \
	-nic user,model=virtio-net-pci \
	-serial "file:$work/console" -serial "file:$work/out" \
	</dev/null >"$work/qemu.log" 2>&1 || true

touch "$work/out"
status=$(sed -n 's/^VM-EXIT-STATUS \([0-9]*\).*/\1/p' "$work/out" | tr -d '\r' | tail -1)
if [ -z "$status" ]; then
	echo "cloud.sh: the script did not finish; console:" >&2
	tail -50 "$work/console" "$work/qemu.log" | tr -d '\r' >&2
	exit 1
fi
tr -d '\r' <"$work/out" | sed -n '/^VM-START/,/^VM-EXIT-STATUS/p' | sed '1d;$d'
exit "$status"
