#!/usr/bin/env bash
# Exercise the Bash completion against a real binary and a fixture scan, and
# syntax-check the Zsh and Fish completions where those shells are installed.
# Usage: tests/completions.sh [path/to/minsec-id]
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
bin=${1:-$repo/target/debug/minsec-id}
[[ -x $bin ]] || { echo "build first: cargo build" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/conf/conf.d"
ln -s "$bin" "$work/bin/minsec-id"
export PATH="$work/bin:$PATH"
printf '[output]\njournal = false\n[paths]\nstate_dir = "%s/state"\n' "$work" > "$work/conf/minsec-id.toml"
minsec-id -c "$work/conf" --root "$repo/tests/fixtures/debian" scan --quiet || true
minsec-id -c "$work/conf" disable ftrace-hooks >/dev/null

# shellcheck source=/dev/null
source "$repo/completions/bash/minsec-id"
fail=0
expect() { # expect <description> <word> <words...>
    local want=$1 desc=$2
    shift 2
    COMP_WORDS=("$@")
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    COMPREPLY=()
    _minsec_id minsec-id "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
    if [[ " ${COMPREPLY[*]} " == *" $want "* ]]; then
        echo "ok   $desc"
    else
        echo "FAIL $desc: wanted $want, got: ${COMPREPLY[*]}"
        fail=1
    fi
}
reject() { # reject <unwanted> <description> <words...>
    local bad=$1 desc=$2
    shift 2
    COMP_WORDS=("$@")
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    COMPREPLY=()
    _minsec_id minsec-id "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
    if [[ " ${COMPREPLY[*]} " == *" $bad "* ]]; then
        echo "FAIL $desc: did not want $bad"
        fail=1
    else
        echo "ok   $desc"
    fi
}
expect scan 'subcommands' minsec-id sc
expect --full 'scan options' minsec-id scan --f
expect kernel-tainted 'check ids for --check' minsec-id scan --check kern
expect ftrace-hooks 'enable offers disabled checks' minsec-id -c "$work/conf" enable ''
reject kernel-tainted 'enable skips enabled checks' minsec-id -c "$work/conf" enable ''
expect critical 'severity values' minsec-id findings --severity cr
expect account-uid0:toor 'accept offers open findings' minsec-id -c "$work/conf" accept acc

if command -v zsh >/dev/null; then zsh -n "$repo/completions/zsh/_minsec-id" && echo "ok   zsh syntax"; fi
if command -v fish >/dev/null; then fish -n "$repo/completions/fish/minsec-id.fish" && echo "ok   fish syntax"; fi
exit $fail
