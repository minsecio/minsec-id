#!/usr/bin/env bash
# End-to-end test of the flatpak checks: build a tiny runtime, sign it with a
# throwaway key, install it system-wide from a local repository, tamper with
# it, and check each tampering is reported. Needs root, flatpak, and gpg; no
# network. Run it in a throwaway VM (tests/vm/run.sh tests/e2e-flatpak.sh)
# or a CI runner. It installs and removes the runtime and its remote.
#
#   tests/e2e-flatpak.sh [path/to/minsec-id]
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
work=$(mktemp -d /tmp/minsec-id-e2e-flatpak.XXXXXX)
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

case $(uname -m) in
x86_64) arch=x86_64 ;;
aarch64) arch=aarch64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
ref=runtime/org.minsec.E2E/$arch/1
remote=minsec-e2e

# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
	flatpak --system uninstall -y --noninteractive "$ref" >/dev/null 2>&1
	flatpak --system remote-delete --force "$remote" >/dev/null 2>&1
	rm -rf "$work"
}
trap cleanup EXIT

# A signing key, and a runtime with a program, data, and a symlink.
export GNUPGHOME=$work/gnupg
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' \
	--quick-gen-key 'minsec-id e2e <e2e@invalid>' rsa2048 sign never 2>/dev/null ||
	die "gpg could not make a key"
key=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --export "$key" >"$work/key.gpg"
# A runtime's build directory has usr/, deployed as files/ (build-export
# also wants an empty files/).
b=$work/build
mkdir -p "$b/files" "$b/usr/bin" "$b/usr/share/e2e" "$b/usr/lib"
cp /usr/bin/true "$b/usr/bin/hello"
echo data >"$b/usr/share/e2e/data"
echo doc >"$b/usr/share/e2e/doc"
ln -s ../bin/hello "$b/usr/lib/link"
printf '[Runtime]\nname=org.minsec.E2E\n' >"$b/metadata"
flatpak build-export --runtime --gpg-sign="$key" --gpg-homedir="$GNUPGHOME" "$work/repo" "$b" 1 >/dev/null ||
	die "flatpak build-export"
flatpak build-update-repo --gpg-sign="$key" --gpg-homedir="$GNUPGHOME" "$work/repo" >/dev/null ||
	die "flatpak build-update-repo"
flatpak --system remote-add --gpg-import="$work/key.gpg" "$remote" "file://$work/repo" ||
	die "flatpak remote-add"
flatpak --system install -y --noninteractive "$remote" "$ref" >/dev/null || die "flatpak install"
pass "installed $ref"

scan() {
	"$bin" -c "$cfg" --json scan --check flatpak-signatures --check flatpak-verify >"$work/scan.json"
}
# The first scan records the baseline; the runtime is intact.
scan
rc=$?
if [ $rc = 0 ]; then
	pass "intact runtime: clean"
else
	bad "intact runtime: exit $rc: $(cat "$work/scan.json")"
fi

# Changes must come after the deployment, to the second.
sleep 1.1
d=/var/lib/flatpak/$ref/active
commit=$(readlink "$d")
# In place: the checkout's file is the repository's object.
echo tampered >>"$d/files/bin/hello"
rm "$d/files/share/e2e/doc"
cp /usr/bin/true "$d/files/bin/added"
ln -sf /tmp/elsewhere "$d/files/lib/link"
# The commit's signature, one byte changed.
meta=/var/lib/flatpak/repo/objects/${commit:0:2}/${commit:2}.commitmeta
python3 -c '
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0xff
open(p, "wb").write(b)' "$meta"

scan
expect() {
	local what=$1 pattern=$2
	if grep -Eq "$pattern" "$work/scan.json"; then pass "$what"; else bad "$what not reported"; fi
}
expect "modified program" "\"check\":\"flatpak-modified\",\"severity\":\"high\",\"subject\":\"$ref/files/bin/hello\""
expect "added program" "\"check\":\"flatpak-modified\",\"severity\":\"high\",\"subject\":\"$ref/files/bin/added\""
expect "retargeted symlink" "\"check\":\"flatpak-modified\",[^}]*\"subject\":\"$ref/files/lib/link\""
expect "missing file" "\"check\":\"flatpak-missing\",[^}]*\"subject\":\"$ref/files/share/e2e/doc\""
expect "bad signature" "\"check\":\"flatpak-signatures\",\"severity\":\"high\",\"subject\":\"$ref\""
if grep -q "files/share/e2e/data" "$work/scan.json"; then bad "an intact file reported"; else pass "intact files not reported"; fi

if [ $fail != 0 ]; then
	echo "--- scan"
	cat "$work/scan.json"
fi
exit $fail
