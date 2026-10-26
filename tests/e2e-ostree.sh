#!/usr/bin/env bash
# End-to-end test of the ostree system checks: on an ostree-booted host,
# tamper with the booted deployment the way root could, and check each
# change is reported. It breaks the system: run it only in a throwaway VM
# (tests/vm/cloud.sh fcos tests/e2e-ostree.sh).
#
#   tests/e2e-ostree.sh [path/to/minsec-id]
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
[ -e /run/ostree-booted ] || {
	echo "FAIL not an ostree-booted system"
	exit 1
}
work=$(mktemp -d /tmp/minsec-id-e2e-ostree.XXXXXX)
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

checks=(--check ostree-deployment --check ostree-verify --check pkg-verify)
"$bin" -c "$cfg" --json scan "${checks[@]}" >"$work/scan.json"
rc=$?
if [ $rc = 0 ]; then
	pass "intact deployment: clean"
else
	bad "intact deployment: exit $rc: $(cat "$work/scan.json")"
fi
if grep -q '"id":"pkg-verify","status":"unavailable"' "$work/scan.json"; then
	pass "pkg-verify defers to ostree-verify"
else
	bad "pkg-verify ran on an ostree system"
fi

# Changes must come after the deployment, to the second.
sleep 1.1
d=$(readlink -f "/ostree/$(sed -n 's/.*ostree=\/ostree\/\([^ ]*\).*/\1/p' /proc/cmdline)")
stateroot=$(basename "$(dirname "$(dirname "$d")")")
commit=$(basename "$d" | cut -d. -f1)
mount -o remount,rw /sysroot
# A repository object changed in place: with composefs, what /usr serves.
obj=$(ostree ls -C "$commit" /usr/bin/less | awk '{print $5}')
echo tampered >>"/sysroot/ostree/repo/objects/${obj:0:2}/${obj:2}.file"
# The checkout: a file removed, a program added.
rm "$d/usr/share/licenses/less/LICENSE"
cp /usr/bin/true "$d/usr/bin/minsec-e2e-added"
# The composefs image rewritten.
printf 'X' | dd of="$d/.ostree.cfs" bs=1 seek=4096 conv=notrunc status=none
# /usr unlocked for transient changes.
ostree admin unlock >/dev/null
# A deployment of another image staged for the next boot.
printf '[origin]\ncontainer-image-reference=ostree-unverified-registry:evil.example/os:latest\n' >"$work/evil.origin"
ostree admin deploy --stage --os="$stateroot" --origin-file="$work/evil.origin" "$commit" >/dev/null 2>&1 ||
	echo "note: ostree admin deploy --stage failed"

"$bin" -c "$cfg" --json scan "${checks[@]}" >"$work/scan.json"
expect() {
	local what=$1 pattern=$2
	if grep -Eq "$pattern" "$work/scan.json"; then pass "$what"; else bad "$what not reported"; fi
}
s="ostree:$stateroot"
expect "modified object" "\"check\":\"ostree-modified\",\"severity\":\"high\",\"subject\":\"$s/usr/bin/less\""
expect "added program" "\"check\":\"ostree-modified\",\"severity\":\"high\",\"subject\":\"$s/usr/bin/minsec-e2e-added\""
expect "missing file" "\"check\":\"ostree-missing\",[^}]*\"subject\":\"$s/usr/share/licenses/less/LICENSE\""
expect "composefs image changed" '"check":"ostree-deployment","severity":"critical","subject":"composefs"'
expect "unlocked /usr" '"check":"ostree-deployment","severity":"medium","subject":"unlocked"'
expect "staged switch" '"check":"ostree-deployment","severity":"high","subject":"next-boot","message":"[^"]*evil.example'
if grep -q "usr/bin/bash\"" "$work/scan.json"; then bad "an intact file reported"; else pass "intact files not reported"; fi

if [ $fail != 0 ]; then
	echo "--- scan"
	cat "$work/scan.json"
fi
rm -rf "$work"
exit $fail
