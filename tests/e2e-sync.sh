#!/usr/bin/env bash
# End-to-end test of minsec-id-sync against a real minsec.io backend: three
# hosts report the same modified package file, the third is told the crowd
# shares its content, and the scanner annotates its finding with that.
# Finding counts reach the backend's tables.
#
# Rootless: the modified file is a changed copy of a packaged program laid
# over /usr/bin with an overlay mount in a user namespace, so nothing on the
# host changes. Needs podman (a throwaway Postgres), unprivileged user
# namespaces, jq, and minsecd built from a minsec.io checkout
# (`go build -o minsecd ./cmd/minsecd`).
#
#   tests/e2e-sync.sh path/to/minsecd [path/to/minsec-id] [path/to/minsec-id-sync]
set -uo pipefail

minsecd=$(realpath "${1:?usage: $0 path/to/minsecd [minsec-id] [minsec-id-sync]}")
bin=$(realpath "${2:-target/release/minsec-id}")
sync=$(realpath "${3:-target/release/minsec-id-sync}")
work=$(mktemp -d /tmp/minsec-id-e2e-sync.XXXXXX)
pg=minsec-id-e2e-pg-$$
port=$((20000 + RANDOM % 20000))
server=http://127.0.0.1:$port

fail=0
pass() { echo "ok   $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}
# shellcheck disable=SC2329 # invoked by the trap
cleanup() {
	[ -n "${srv:-}" ] && kill "$srv" 2>/dev/null
	podman stop -t 1 "$pg" >/dev/null 2>&1
	rm -rf "$work"
}
trap cleanup EXIT
sql() { podman exec "$pg" psql -U postgres -tAc "$1"; }

# A packaged program, changed by one byte, laid over /usr/bin.
target=
for p in zcat gzip true; do
	if rpm -qf "/usr/bin/$p" >/dev/null 2>&1 || dpkg -S "/usr/bin/$p" >/dev/null 2>&1; then
		target=$p
		break
	fi
done
[ -n "$target" ] || {
	echo "FAIL no packaged program to modify"
	exit 1
}
mkdir -p "$work/upper" "$work/ovl" "$work/etc"
cp "/usr/bin/$target" "$work/upper/$target"
printf x >>"$work/upper/$target"
cat >"$work/etc/minsec-id.toml" <<EOF
[output]
journal = false
[paths]
socket = "$work/sock"
state_dir = "$work/host3"
EOF
scan() {
	unshare -rm sh -c "mount -t overlay overlay -o lowerdir=/usr/bin,upperdir=$work/upper,workdir=$work/ovl /usr/bin &&
		exec '$bin' -c '$work/etc' --json scan --full --check pkg-verify" >"$work/scan.json"
}

podman run -d --rm --name "$pg" -e POSTGRES_PASSWORD=e2e -p 127.0.0.1::5432 \
	docker.io/library/postgres:16-alpine >/dev/null || exit 1
until podman exec "$pg" pg_isready -q -U postgres 2>/dev/null; do sleep 0.5; done
pgport=$(podman port "$pg" 5432 | sed 's/.*://')
MINSEC_DATABASE_URL=postgres://postgres:e2e@127.0.0.1:$pgport/postgres \
	MINSEC_LISTEN_ADDR=127.0.0.1:$port MINSEC_METRICS_ADDR='' \
	MINSEC_ENROLL_SECRET=e2e-secret-e2e-secret MINSEC_POW_DIFFICULTY=8 \
	MINSEC_TRUST_PROXY=false MINSEC_ENROLL_PER_IP_HOUR=100 \
	MINSEC_HASHCHECK_MIN_REPORTERS=2 MINSEC_PROBATION_PERIOD=0s MINSEC_LOG_LEVEL=warn \
	"$minsecd" serve 2>"$work/minsecd.log" &
srv=$!
for _ in $(seq 100); do
	curl -fs "$server/readyz" >/dev/null && break
	sleep 0.2
done
curl -fs "$server/readyz" >/dev/null || {
	echo "FAIL minsecd did not start"
	cat "$work/minsecd.log"
	exit 1
}

if "$sync" -c "$work/none.toml" run; then pass "unconfigured: run exits quietly"; else bad "unconfigured run failed"; fi

scan
if grep -q "\"check\":\"pkg-modified\",\"severity\":\"high\",\"subject\":\"/usr/bin/$target\"" "$work/scan.json"; then
	pass "the modified /usr/bin/$target is a pkg-modified finding"
else
	bad "pkg-modified /usr/bin/$target not reported"
	cat "$work/scan.json"
	exit 1
fi

# The host may have modified files of its own: look only at this one.
fp=$(jq -r --arg s "/usr/bin/$target" '.findings[] | select(.check == "pkg-modified" and .subject == $s) | .fingerprint' "$work/scan.json")
check() {
	local what=$1
	shift
	if "$@"; then pass "$what"; else bad "$what"; fi
}

# Three hosts with the same finding, enrolled from three networks.
n=0
for h in host1 host2 host3; do
	n=$((n + 1))
	mkdir -p "$work/$h"
	[ "$h" = host3 ] || cp "$work/host3/state.json" "$work/$h/"
	printf 'server = "%s"\nstate_dir = "%s"\n' "$server" "$work/$h" >"$work/$h/sync.toml"
	"$sync" -c "$work/$h/sync.toml" enroll >/dev/null || bad "$h: enroll"
	id=$("$sync" -c "$work/$h/sync.toml" status | sed -n 's/^host_id: *//p')
	sql "update agents set enroll_ip = '198.51.$n.1' where host_id = '$id'" >/dev/null
done
check "enrolled as minsec-id" [ "$(sql "select count(*) from agents where product = 'minsec-id'")" = 3 ]

answer() { jq -r --arg fp "$fp" ".answers[\$fp] | \"\(.verdict) \(.same)\"" "$work/$1/sync/crowd.json"; }
"$sync" -c "$work/host1/sync.toml" check >/dev/null || bad "host1: check"
"$sync" -c "$work/host2/sync.toml" check >/dev/null || bad "host2: check"
check "below quorum: rare, 1 other host" [ "$(answer host2)" = "rare 1" ]
"$sync" -c "$work/host3/sync.toml" run || bad "host3: run"
check "at quorum: shared, 2 other hosts" [ "$(answer host3)" = "shared 2" ]

check "finding counts reached the backend" \
	[ "$(sql "select sum(open) > 0 from finding_counts where check_id = 'pkg-modified' and severity = 'high'")" = t ]
check "one vote per host" [ "$(sql "select count(*) from hash_votes where path = '/usr/bin/$target'")" = 3 ]
check "no content sent: digests only" \
	[ "$(sql "select octet_length(actual) from hash_votes where path = '/usr/bin/$target' limit 1")" -le 64 ]

scan
f=$(jq -c --arg fp "$fp" '.findings[] | select(.fingerprint == $fp)' "$work/scan.json")
if [[ $f == *'(crowd: the same content is reported by 2 other hosts)'* ]] &&
	[ "$(jq -r .detail.crowd.verdict <<<"$f")" = shared ] && [ "$(jq -r .severity <<<"$f")" = high ]; then
	pass "the scanner annotates the finding, severity unchanged"
else
	bad "no crowd annotation: $f"
fi

if [ $fail != 0 ]; then
	echo "--- minsecd"
	cat "$work/minsecd.log"
fi
exit $fail
