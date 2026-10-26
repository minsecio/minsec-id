#!/usr/bin/env bash
# End-to-end test of the eBPF daemon: start it, do the things it watches
# for, and check that each produced its finding. Needs root and a kernel
# with BTF; run it in a throwaway VM (tests/vm/run.sh tests/e2e-daemon.sh)
# or a CI runner. It writes to /etc and /usr/bin and removes what it wrote.
#
#   tests/e2e-daemon.sh [path/to/minsec-id]
#
# MAX_RSS_KB (optional) fails the test if the daemon's resident memory,
# after the events, is larger.
set -uo pipefail

bin=$(realpath "${1:-target/release/minsec-id}")
work=$(mktemp -d /tmp/minsec-id-e2e.XXXXXX)
cfg=$work/etc
mkdir -p "$cfg"
cat >"$cfg/minsec-id.toml" <<EOF
[output]
journal = false
[paths]
socket = "$work/daemon.sock"
state_dir = "$work/state"
EOF

fail=0
pass() { echo "ok   $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}
# assert DESCRIPTION COMMAND...: pass if the command succeeds.
assert() {
	local what=$1
	shift
	if "$@"; then pass "$what"; else bad "$what"; fi
}

"$bin" -c "$cfg" daemon 2>"$work/daemon.log" &
daemon=$!
for _ in $(seq 600); do
	[ -S "$work/daemon.sock" ] && break
	sleep 0.1
done
if ! [ -S "$work/daemon.sock" ]; then
	cat "$work/daemon.log"
	echo "FAIL daemon did not start"
	exit 1
fi
pass "daemon started"

py=$(command -v python3)
arch=$(uname -m)

# exec-writable: a program run from /tmp.
cp /usr/bin/true "$work/t" && "$work/t"
# exec-memfd: fileless execution.
"$py" -c 'import os; fd=os.memfd_create("e2e"); os.write(fd, open("/usr/bin/true","rb").read()); os.execv("/proc/self/fd/%d"%fd, ["e2e"])'
# exec-deleted: a program run after its file was deleted.
mkdir -p /var/lib/minsec-e2e
cp /usr/bin/true /var/lib/minsec-e2e/del
(exec 3</var/lib/minsec-e2e/del && rm /var/lib/minsec-e2e/del && /proc/self/fd/3)
rmdir /var/lib/minsec-e2e
# write-sensitive: the dynamic loader's preload list.
had_preload=0
[ -e /etc/ld.so.preload ] && had_preload=1
if [ $had_preload = 0 ]; then
	: >/etc/ld.so.preload && rm -f /etc/ld.so.preload
fi
# write-sensitive (new program) and exec-unowned: a binary dropped in /usr/bin.
cp /usr/bin/true /usr/bin/minsec-e2e-unowned && /usr/bin/minsec-e2e-unowned
rm -f /usr/bin/minsec-e2e-unowned
# dirty.list: an ordinary write under /usr.
mkdir -p /usr/share/minsec-e2e && echo x >/usr/share/minsec-e2e/file
# devmem-open: reading kernel memory.
head -c 1 /proc/kcore >/dev/null 2>&1 || true
# priv-escalation: uid 0 from no uid 0, without a setuid exec.
if command -v setpriv >/dev/null; then
	setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=+setuid --ambient-caps=+setuid \
		"$py" -c 'import os; os.setuid(0)' 2>/dev/null
fi
# ptrace-attach: root attaching to another user's process.
setpriv --reuid=65534 --regid=65534 --clear-groups sleep 5 &
victim=$!
sleep 0.2
"$py" -c 'import ctypes,sys; ctypes.CDLL(None).ptrace(0x4206, int(sys.argv[1]), 0, 0)' "$victim"
kill $victim 2>/dev/null
# kexec-load: the syscall is enough (it fails on bad descriptors).
case $arch in
x86_64) nr=320 ;;
aarch64) nr=294 ;;
*) nr= ;;
esac
[ -n "$nr" ] && "$py" -c "import ctypes; ctypes.CDLL(None).syscall($nr, -1, -1, 0, 0, 0)"
# bpf-load: a kprobe program load request (it fails verification; the request is enough).
"$py" - <<'EOF'
import ctypes
attr = ctypes.create_string_buffer(144)
attr[0] = 2  # BPF_PROG_TYPE_KPROBE
attr[48:51] = b"e2e"
ctypes.CDLL(None).syscall({"x86_64": 321, "aarch64": 280}.get(__import__("os").uname().machine, -1), 5, attr, 144)
EOF

# exec-service-shell: a service account's shell with a socket on stdio. A
# UDP socket is an internet socket without needing a network.
setpriv --reuid=65534 --regid=65534 --clear-groups "$py" -c '
import os, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1)
os.execv("/bin/sh", ["sh", "-c", "exit 0"])'

# The scanner, while the daemon runs: its BPF view of processes, and the
# daemon's own programs and trampolines, which are not findings.
for c in proc-hidden bpf-prog-unknown ftrace-hooks; do
	if "$bin" -c "$cfg" --json scan --check $c >"$work/scan.json"; then
		pass "$c: clean"
	else
		bad "$c: $(cat "$work/scan.json")"
	fi
done

sleep 1
"$bin" -c "$cfg" status | tee "$work/status"
assert "status reaches the daemon" grep -q '^daemon: up' "$work/status"
assert "every probe attached" grep -Eq ' ([0-9]+)/\1 probes' "$work/status"
rss=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$daemon/status")
anon=$(sed -n 's/^RssAnon:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$daemon/status")
echo "daemon memory: VmRSS ${rss} KiB, RssAnon ${anon} KiB"
if [ -n "${MAX_RSS_KB:-}" ] && [ "$anon" -gt "$MAX_RSS_KB" ]; then
	bad "daemon anonymous memory ${anon} KiB > ${MAX_RSS_KB} KiB"
fi

kill -TERM $daemon
if wait $daemon; then pass "daemon stopped cleanly"; else bad "daemon exited with $?"; fi

log=$work/state/findings.jsonl
expect() {
	if grep -q "\"check\":\"$1\"" "$log" 2>/dev/null; then
		pass "$1"
	else
		bad "$1 not reported"
	fi
}
expect exec-writable
expect exec-memfd
expect exec-deleted
expect exec-unowned
expect exec-service-shell
expect devmem-open
expect ptrace-attach
expect bpf-load
[ $had_preload = 0 ] && assert "write-sensitive" grep -q '"subject":"/etc/ld.so.preload"' "$log"
assert "write-sensitive (new program)" grep -q '"subject":"/usr/bin/minsec-e2e-unowned"' "$log"
command -v setpriv >/dev/null && expect priv-escalation
[ -n "$nr" ] && expect kexec-load
assert "dirty.list records the /usr write" grep -qx /usr/share/minsec-e2e/file "$work/state/dirty.list"
# Our own BPF (the daemon's probes, the scan's iterator) is not reported.
if grep -q '"check":"bpf-load".*msid_' "$log"; then bad "minsec-id's own BPF reported"; else pass "own BPF not reported"; fi

rm -rf /usr/share/minsec-e2e
if [ $fail != 0 ]; then
	echo "--- daemon log"
	cat "$work/daemon.log"
	echo "--- findings"
	cat "$log"
fi
rm -rf "$work"
exit $fail
