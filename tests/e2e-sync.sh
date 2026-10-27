#!/usr/bin/env bash
# End-to-end test of minsec-id-sync against a real minsec.io backend: three
# hosts report the same modified package file, the third is told the crowd
# shares its content, and the scanner annotates its finding with that.
# Finding counts reach the backend's tables. Then fleet management: hosts
# enroll into an organization with an install token, an anonymous host joins
# it, the organization counts once toward the crowd's quorum, and a host
# that goes quiet gets a missed-heartbeat alert.
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
export MINSEC_DATABASE_URL=postgres://postgres:e2e@127.0.0.1:$pgport/postgres
MINSEC_LISTEN_ADDR=127.0.0.1:$port MINSEC_METRICS_ADDR='' \
	MINSEC_ENROLL_SECRET=e2e-secret-e2e-secret MINSEC_POW_DIFFICULTY=8 \
	MINSEC_TRUST_PROXY=false MINSEC_ENROLL_PER_IP_HOUR=100 \
	MINSEC_HASHCHECK_MIN_REPORTERS=2 MINSEC_PROBATION_PERIOD=0s MINSEC_ALERT_INTERVAL=1s \
	MINSEC_LOG_LEVEL=warn \
	"$minsecd" serve >"$work/minsecd.log" 2>&1 &
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

# Fleet: an organization and an install token, from the operator CLI.
"$minsecd" admin org create Acme >/dev/null || bad "org create"
token=$("$minsecd" admin org token -note e2e Acme 2>/dev/null)
check "install token minted" [ "${token#minsec_}" != "$token" ]

# host4 and host5 enroll into it from two more networks, with labels.
for n in 4 5; do
	h=host$n
	mkdir -p "$work/$h"
	cp "$work/host3/state.json" "$work/$h/"
	printf 'server = "%s"\nstate_dir = "%s"\ninstall_token = "%s"\nlabel = "web%s"\n' \
		"$server" "$work/$h" "$token" "$n" >"$work/$h/sync.toml"
	"$sync" -c "$work/$h/sync.toml" enroll >/dev/null || bad "$h: enroll with token"
	id=$("$sync" -c "$work/$h/sync.toml" status | sed -n 's/^host_id: *//p')
	sql "update agents set enroll_ip = '198.51.$n.1' where host_id = '$id'" >/dev/null
done
check "enrolled into the organization" [ "$("$sync" -c "$work/host4/sync.toml" status | sed -n 's/^org: *//p')" = Acme ]
check "labels stored" [ "$(sql "select string_agg(label, ',' order by label) from agents where org_id is not null")" = web4,web5 ]

# Two hosts of one organization are one vote: host3 sees host1, host2 and
# the organization, not four hosts.
"$sync" -c "$work/host4/sync.toml" check >/dev/null || bad "host4: check"
"$sync" -c "$work/host5/sync.toml" check >/dev/null || bad "host5: check"
rm "$work/host3/sync/crowd.json" # answered earlier; ask again now
"$sync" -c "$work/host3/sync.toml" check >/dev/null || bad "host3: check"
check "an organization counts once" [ "$(answer host3)" = "shared 3" ]

# A mistyped token is refused before the host gives up its enrollment.
cp "$work/host2/sync.toml" "$work/host2/bad.toml"
printf 'install_token = "minsec_mistyped"\n' >>"$work/host2/bad.toml"
before=$("$sync" -c "$work/host2/sync.toml" status | sed -n 's/^host_id: *//p')
if "$sync" -c "$work/host2/bad.toml" run 2>/dev/null; then bad "a bad token was accepted"; fi
check "a bad token keeps the anonymous enrollment" \
	[ "$("$sync" -c "$work/host2/sync.toml" status | sed -n 's/^host_id: *//p')" = "$before" ]
"$sync" -c "$work/host2/sync.toml" report >/dev/null || bad "host2: report after a bad token"

# host1, enrolled anonymously, joins with the token on its next run.
old=$("$sync" -c "$work/host1/sync.toml" status | sed -n 's/^host_id: *//p')
printf 'install_token = "%s"\nlabel = "db1"\n' "$token" >>"$work/host1/sync.toml"
"$sync" -c "$work/host1/sync.toml" run 2>/dev/null || bad "host1: run with token"
new=$("$sync" -c "$work/host1/sync.toml" status | sed -n 's/^host_id: *//p')
check "an anonymous host joins on its next run" [ "$new" != "$old" ]
check "under its label" [ "$(sql "select label from agents where host_id = '$new'")" = db1 ]
check "the join happens once" [ "$("$sync" -c "$work/host1/sync.toml" run 2>&1 | grep -c re-enrolling)" = 0 ]

# web5 goes quiet: the alert job opens a missed-heartbeat alert.
id5=$("$sync" -c "$work/host5/sync.toml" status | sed -n 's/^host_id: *//p')
sql "update agents set last_seen_at = now() - interval '4 hours' where host_id = '$id5'" >/dev/null
for _ in $(seq 30); do
	[ "$(sql "select count(*) from alerts where host_id = '$id5' and resolved_at is null")" = 1 ] && break
	sleep 0.2
done
check "a quiet host is missing" [ "$(sql "select count(*) from alerts where host_id = '$id5' and resolved_at is null")" = 1 ]
"$sync" -c "$work/host5/sync.toml" report >/dev/null || bad "host5: report"
for _ in $(seq 30); do
	[ "$(sql "select resolution from alerts where host_id = '$id5'")" = recovered ] && break
	sleep 0.2
done
check "its next report resolves the alert" [ "$(sql "select resolution from alerts where host_id = '$id5'")" = recovered ]

if [ $fail != 0 ]; then
	echo "--- minsecd"
	cat "$work/minsecd.log"
fi
exit $fail
