#!/usr/bin/env bash
# End-to-end test of ima-verify: with an IMA measurement policy active, run
# a packaged program after changing its content, put the content back, and
# check the measurement is reported. Needs root, rpm, and ima_policy=tcb;
# it modifies the system's files. Run it in a throwaway VM:
#
#   VM_KARGS=ima_policy=tcb tests/vm/cloud.sh fcos tests/e2e-ima.sh
#
#   tests/e2e-ima.sh [path/to/minsec-id]
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
grep -q 'ima_policy=tcb' /proc/cmdline || {
	echo "FAIL boot with ima_policy=tcb"
	exit 1
}
work=$(mktemp -d /tmp/minsec-id-e2e-ima.XXXXXX)
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
scan() { "$bin" -c "$cfg" --json scan --check ima-verify >"$work/scan.json"; }

scan
rc=$?
if [ $rc = 0 ]; then pass "measurements match packages"; else bad "intact system: exit $rc: $(cat "$work/scan.json")"; fi

# The file that /usr/bin/less is: on an ostree system, its repository object.
target=/usr/bin/less
if [ -e /run/ostree-booted ]; then
	d=$(readlink -f "/ostree/$(sed -n 's/.*ostree=\/ostree\/\([^ ]*\).*/\1/p' /proc/cmdline)")
	commit=$(basename "$d" | cut -d. -f1)
	obj=$(ostree ls -C "$commit" /usr/bin/less | awk '{print $5}')
	mount -o remount,rw /sysroot
	target=/sysroot/ostree/repo/objects/${obj:0:2}/${obj:2}.file
fi
cp -a "$target" "$work/orig"
echo tampered >>"$target"
less --version >/dev/null 2>&1
cat "$work/orig" >"$target"

scan
if grep -q '"check":"ima-mismatch","severity":"high","subject":"/usr/bin/less"' "$work/scan.json"; then
	pass "a program run with other content, then restored"
else
	bad "the changed program was not reported: $(cat "$work/scan.json")"
fi
rm -rf "$work"
exit $fail
