#!/usr/bin/env bash
# End-to-end test of the sysext check: merge a directory extension and an
# image extension over /usr, change the directory one, and check what is
# reported, and that exe-unowned leaves the extensions' programs to it.
# Needs root and systemd-sysext. The image extension is IMAGE (a squashfs
# sysext named minsec-img), or one built here with mksquashfs; without
# either, only the directory extension is tested. It merges and unmerges
# extensions: run it in a throwaway VM
# (tests/vm/cloud.sh fcos tests/e2e-sysext.sh BIN IMAGE) or a CI runner.
#
#   tests/e2e-sysext.sh [path/to/minsec-id] [IMAGE]
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
image=${2:-}
work=$(mktemp -d /tmp/minsec-id-e2e-sysext.XXXXXX)
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
scan() { "$bin" -c "$cfg" --json scan --check sysext --check exe-unowned >"$work/scan.json"; }
expect() {
	local what=$1 pattern=$2
	if grep -Eq "$pattern" "$work/scan.json"; then pass "$what"; else bad "$what not reported"; fi
}

if [ -z "$image" ] && command -v mksquashfs >/dev/null; then
	mkdir -p "$work/img/usr/bin" "$work/img/usr/lib/extension-release.d"
	cp /usr/bin/true "$work/img/usr/bin/minsec-e2e-ext"
	echo ID=_any >"$work/img/usr/lib/extension-release.d/extension-release.minsec-img"
	mksquashfs "$work/img" "$work/minsec-img.raw" -noappend -quiet -all-root >/dev/null
	image=$work/minsec-img.raw
fi

scan
if grep -q '"check":"sysext' "$work/scan.json"; then bad "extensions before any were merged"; else pass "baseline: no extensions"; fi

ext=/var/lib/extensions
mkdir -p "$ext/minsec-dir/usr/bin" "$ext/minsec-dir/usr/lib/extension-release.d"
cp /usr/bin/true "$ext/minsec-dir/usr/bin/minsec-e2e-dir"
echo ID=_any >"$ext/minsec-dir/usr/lib/extension-release.d/extension-release.minsec-dir"
[ -n "$image" ] && cp "$image" "$ext/minsec-img.raw"
systemd-sysext merge >/dev/null 2>&1 || bad "systemd-sysext merge"

scan
expect "directory extension" '"check":"sysext","severity":"medium","subject":"sysext:minsec-dir"'
[ -n "$image" ] && expect "image extension" '"check":"sysext","severity":"medium","subject":"sysext:minsec-img"'
if grep -q '"check":"exe-unowned","severity":"[a-z]*","subject":"/usr/bin/minsec-e2e-' "$work/scan.json"; then
	bad "exe-unowned reports an extension's program"
else
	pass "exe-unowned leaves extension programs to sysext"
fi

# The directory extension changed in place, and merged again.
cp /usr/bin/true "$ext/minsec-dir/usr/bin/minsec-e2e-added"
systemd-sysext refresh >/dev/null 2>&1 || bad "systemd-sysext refresh"
scan
expect "changed extension" '"check":"sysext-changed","severity":"high","subject":"sysext:minsec-dir"'

systemd-sysext unmerge >/dev/null 2>&1
rm -rf "$ext/minsec-dir" "$ext/minsec-img.raw"
scan
if grep -q '"check":"sysext' "$work/scan.json"; then bad "unmerged extensions still reported"; else pass "unmerged: nothing reported"; fi

if [ $fail != 0 ]; then
	echo "--- scan"
	cat "$work/scan.json"
fi
rm -rf "$work"
exit $fail
