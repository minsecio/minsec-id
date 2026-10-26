#!/usr/bin/env bash
# End-to-end test of the snap checks: install a store snap and a local one,
# tamper with them, and check each tampering is reported. Needs root, snapd,
# and network (for the store snap). Run it in a throwaway VM
# (tests/vm/cloud.sh ubuntu-24.04 tests/e2e-snap.sh) or a CI runner. It
# modifies installed snaps: do not run it on a host you care about.
#
#   tests/e2e-snap.sh [path/to/minsec-id]
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
work=$(mktemp -d /tmp/minsec-id-e2e-snap.XXXXXX)
cfg=$work/etc
mkdir -p "$cfg"
cat >"$cfg/minsec-id.toml" <<EOF
[output]
journal = false
[paths]
socket = "$work/sock"
state_dir = "$work/state"
EOF

fail=0
pass() { echo "ok   $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}
die() {
	echo "FAIL $*"
	exit 1
}

snap wait system seed.loaded
snap install hello-world >/dev/null || die "snap install hello-world"
# A local snap, installed without assertions.
mkdir -p "$work/local/meta"
printf 'name: minsec-e2e\nversion: "1"\nsummary: e2e\ndescription: e2e\nconfinement: strict\n' >"$work/local/meta/snap.yaml"
mksquashfs "$work/local" "$work/minsec-e2e.snap" -noappend -comp xz -no-progress >/dev/null
snap install --dangerous "$work/minsec-e2e.snap" >/dev/null || die "snap install --dangerous"
pass "installed hello-world and a local snap"

scan() {
	"$bin" -c "$cfg" --json scan --check snap-verify --check snap-mounts >"$work/scan.json"
}
expect() {
	local what=$1 pattern=$2
	if grep -Eq "$pattern" "$work/scan.json"; then pass "$what"; else bad "$what not reported"; fi
}

scan
expect "local snap unasserted" '"check":"snap-unasserted","severity":"low","subject":"/var/lib/snapd/snaps/minsec-e2e_x1.snap"'
if grep -Eq '"check":"snap-(modified|mounts)"' "$work/scan.json"; then
	bad "intact snaps reported: $(cat "$work/scan.json")"
else
	pass "intact store snaps: clean"
fi

s=/var/lib/snapd/snaps
hw=$(basename "$(ls $s/hello-world_*.snap)")
core=$(basename "$(ls $s/core_*.snap)")
# Replaced: same size, one byte different, a new file in place of the
# mounted one.
cp "$s/$hw" "$work/hw.snap"
printf 'X' | dd of="$work/hw.snap" bs=1 seek=8192 conv=notrunc status=none
mv "$work/hw.snap" "$s/$hw"
# Grown in place.
printf 'X' >>"$s/$core"
# A squashfs mounted where a snap would be, from elsewhere.
mkdir -p /snap/fake/1
mount -o ro,loop "$work/minsec-e2e.snap" /snap/fake/1

scan
expect "replaced snap's digest" "\"check\":\"snap-modified\",\"severity\":\"high\",\"subject\":\"$s/$hw\""
expect "grown snap's size" "\"check\":\"snap-modified\",\"severity\":\"high\",\"subject\":\"$s/$core\""
expect "mounted file replaced" "\"check\":\"snap-mounts\",\"severity\":\"high\",\"subject\":\"/snap/hello-world/[0-9]+\",\"message\":\"[^\"]*replaced or deleted"
expect "mount from elsewhere" '"check":"snap-mounts","severity":"high","subject":"/snap/fake/1"'

umount /snap/fake/1
if [ $fail != 0 ]; then
	echo "--- scan"
	cat "$work/scan.json"
fi
rm -rf "$work"
exit $fail
