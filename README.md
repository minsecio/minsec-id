# minsec-id

Minimalist intrusion detection for modern Linux.

`minsec-id` checks a host for signs of intrusion using what the system already
knows, instead of keeping its own copy:

* **No file-hash database.** The package manager already holds signed digests
  of every packaged file; the kernel already tracks taint, module signatures,
  lockdown, and what changed since install. `minsec-id` asks them.
* **Nothing resident by default.** Scans run from systemd timers (quick every
  30 minutes, full daily, at idle I/O priority). An optional eBPF daemon adds
  real-time detection (exec from `/tmp` or memfd, module and BPF loads,
  privilege escalation) on hosts that want it.
* **Same UX as [minsec](https://github.com/minsecio/minsec).** One TOML file
  plus drop-ins, `minsec-id enable|disable|accept`, `--json` on every command,
  a JSONL findings log, and journald fields you can filter on.

It is a sibling of `minsec` and will share the minsec.io backend for fleet
management and crowd-verified package hashes. See [docs/PLAN.md](docs/PLAN.md)
for the design and roadmap.

## Status

Phase 0: the skeleton works end to end with one check, `kernel-tainted`. The
package-integrity, persistence, process, and eBPF checks are next.

## What it does not claim

A kernel rootkit loaded before `minsec-id` can blind it. `minsec-id` can see
the act of loading one (with the daemon running), sloppy hiding (cross-view
checks), and, with minsec.io, an agent that stops reporting. It does not claim
to detect targeted, APT-grade intrusions.

## Requirements

Linux 5.14 or newer with glibc 2.34 or newer: EL9/10, Debian 12+, Ubuntu
22.04+, Fedora. `minsec-id inspect` reports what this host supports.

## Quick start

```sh
cargo build --release
sudo install -m 0755 target/release/minsec-id /usr/bin/minsec-id
sudo install -d /etc/minsec-id && sudo install -m 0644 packaging/minsec-id.toml /etc/minsec-id/
sudo install -m 0644 packaging/minsec-id-scan*.{service,timer} /etc/systemd/system/
sudo install -m 0644 packaging/minsec-id.tmpfiles.conf /usr/lib/tmpfiles.d/minsec-id.conf
sudo systemd-tmpfiles --create minsec-id.conf
sudo minsec-id scan
sudo systemctl enable --now minsec-id-scan.timer minsec-id-scan-full.timer
```

## Findings

Every check has a stable id (`minsec-id checks`). A finding is reported once —
to `/var/lib/minsec-id/findings.jsonl`, to journald, and to an optional
`exec` hook — and stays open until a later scan no longer sees it, which logs
it as resolved.

```sh
sudo minsec-id scan              # exit 0 clean, 2 open findings, 1 error
sudo minsec-id findings
sudo minsec-id show kernel-tainted:P
sudo minsec-id accept kernel-tainted:P --reason "NVIDIA driver"
journalctl SYSLOG_IDENTIFIER=minsec-id MINSEC_SEVERITY=high
```

`accept` writes `conf.d/accept.toml`, so accepted findings are configuration
you can review and distribute, not hidden state.

## CLI

| Command | |
|---|---|
| `minsec-id scan [--quick\|--full] [--check ID…]` | run checks |
| `minsec-id status` | last scan and open findings |
| `minsec-id findings [--all] [--severity S]` / `show <finding>` | list or inspect findings |
| `minsec-id accept <finding> [--reason]` / `unaccept <key>` | accept rules |
| `minsec-id checks` / `enable` / `disable <check>` | the check catalog |
| `minsec-id inspect` | host capabilities and configuration sources |
| `minsec-id check` | validate configuration |
| `minsec-id events` | the findings log |

## License

GPL-3.0-or-later.
