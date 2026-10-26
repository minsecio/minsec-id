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

Phase 2: the scanner and the optional eBPF daemon are complete. Image-based
systems (ostree, bootc), flatpak, and snap are next; see
[docs/PLAN.md](docs/PLAN.md).

## Checks

| Check | Finds | Scan |
|---|---|---|
| `kernel-tainted` | kernel taint flags, and the modules responsible | quick |
| `kmod-unowned`, `kmod-hidden` | modules no package installed; modules hidden from one of the kernel's module lists | quick |
| `bpf-prog-unknown` | loaded eBPF tracing, kprobe, and LSM programs | quick |
| `ftrace-hooks` | kernel functions hooked through ftrace, by owner | quick |
| `boot-posture` | lockdown, Secure Boot, LSM modes, hardening sysctls getting weaker; dangerous kernel command-line parameters | quick |
| `boot-kernel` | kernel images in `/boot` that differ from the packaged copy | full |
| `pkg-signatures` | rpm database edits (header signatures fail), unsigned packages | quick |
| `pkg-verify` | packaged files modified, missing, or with changed modes or link targets | full |
| `exe-unowned` | executables, libraries, setuid and capability binaries in system paths that no package owns | quick |
| `repo-key-changed`, `repo-changed` | signing keys and repositories added or changed; repositories that skip signature checks | quick |
| `proc-exe` | processes running from deleted files, memfds, or writable or hidden locations | quick |
| `proc-hidden` | processes the kernel runs that `/proc` does not list (read with a BPF task iterator) | quick |
| `proc-preload` | `ld.so.preload`, `LD_PRELOAD`, code mapped from writable or deleted files | quick |
| `proc-service-shell` | shells run by service accounts with a network socket on stdio | quick |
| `net-listener` | listeners hidden from `/proc/net`, or served by unowned binaries | quick |
| `net-raw-socket` | packet and raw sockets held by unexpected processes | quick |
| `persistence` | new or changed units, cron jobs, shell startup files, udev/modprobe rules, PAM, sudoers, sshd and loader configuration, hooks | quick |
| `accounts` | extra uid-0 accounts, empty passwords, new login accounts, new `NOPASSWD` rules | quick |
| `ssh-key-new` | SSH keys authorized for any account | quick |
| `anti-forensics` | history files linked to `/dev/null`, login and auth logs truncated in place | quick |

Checks that compare with a baseline record it on their first run and report
changes after that. When a reported change is one you want to keep, reset
that check's baseline: `minsec-id baseline --reset --check ssh-key-new`.

A full scan does not re-hash the disk. It hashes a packaged file only when
its ctime is newer than its package's install time, when its size or mtime
differ from the package database, or when it falls in the day's slice of a
rolling sample that covers every packaged file once a week. On a
3,400-package Fedora workstation, a full scan takes about ten seconds.

## The eBPF daemon

`minsec-id daemon` (`minsec-id.service`, installed but not enabled) watches
as things happen, where a scan sees only what is left afterwards. Its BPF
programs filter in the kernel and send compact records through one ring
buffer; the rules that judge them run in userspace, with the package
database and `/proc` to hand.

| Rule | Reports |
|---|---|
| `exec` | programs run from memfds (`exec-memfd`), deleted files (`exec-deleted`), writable or hidden locations and tmpfs (`exec-writable`), unowned files in system paths (`exec-unowned`); shells started by service accounts with a network socket on stdio (`exec-service-shell`) |
| `write-sensitive` | writes, outside package transactions, to `authorized_keys`, `ld.so.preload`, PAM, sudoers, sshd and loader configuration, `/boot`, the account files, persistence locations, and system programs modified in place |
| `module-load` | modules loaded from outside `modules.dep`, not from a package, or unsigned |
| `kexec-load` | a kernel loaded to boot into without the bootloader |
| `bpf-load` | tracing, kprobe, and LSM BPF programs loaded |
| `priv-escalation` | a process becoming root without running a setuid program (the outcome of most kernel exploits) |
| `ptrace-attach` | attaching to, or writing the memory of, another user's process |
| `devmem-open` | `/dev/mem`, `/dev/port`, or `/proc/kcore` opened |

Other writes under `/usr`, `/boot`, and `/etc` go to
`/var/lib/minsec-id/dirty.list`, and the next full scan hashes those files
whatever their ctime says. Daemon findings go to the findings log, the
journal, and the hook as they happen; the same finding is not reported again
within an hour (`daemon.repeat`). `minsec-id findings` lists them after the
scan's open findings, marked `[daemon: …]`, for a week (`daemon.recent`):
they record something that happened, so no later scan resolves them. Accept
the ones that are expected. `minsec-id status` shows the daemon's probes and
how many kernel records it examined (execs and writes; not findings). It uses about 2 MB of anonymous
memory and about 1 MB of BPF maps (half of it the ring buffer).

```sh
sudo systemctl enable --now minsec-id
sudo minsec-id status
sudo minsec-id events
```

The daemon needs a kernel with BTF (`/sys/kernel/btf/vmlinux`) and
CAP_BPF and CAP_PERFMON. It cannot run under `lockdown=confidentiality`,
which forbids BPF programs from reading kernel memory.

## What it does not claim

A kernel rootkit loaded before `minsec-id` can blind it. `minsec-id` can see
the act of loading one (with the daemon running), sloppy hiding (cross-view
checks), and, with minsec.io, an agent that stops reporting. It does not claim
to detect targeted, APT-grade intrusions.

## Requirements

Linux 5.14 or newer with glibc 2.34 or newer: EL9/10, Debian 12+, Ubuntu
22.04+, Fedora. `minsec-id inspect` reports what this host supports.

## Quick start

Building needs Rust 1.87 or newer and clang (for the BPF programs).

```sh
cargo build --release
sudo install -m 0755 target/release/minsec-id /usr/bin/minsec-id
sudo install -d /etc/minsec-id && sudo install -m 0644 packaging/minsec-id.toml /etc/minsec-id/
sudo install -m 0644 packaging/minsec-id*.{service,timer} /etc/systemd/system/
sudo install -m 0644 packaging/minsec-id.tmpfiles.conf /usr/lib/tmpfiles.d/minsec-id.conf
sudo install -m 0644 docs/man/minsec-id.1 /usr/share/man/man1/
sudo install -m 0644 docs/man/minsec-id.toml.5 /usr/share/man/man5/
scripts/install-completions.sh --user
sudo systemd-tmpfiles --create minsec-id.conf
sudo minsec-id scan
sudo systemctl enable --now minsec-id-scan.timer minsec-id-scan-full.timer
```

## Findings

Every check and daemon rule has a stable id (`minsec-id checks`). A scan
finding is reported once —
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
| `minsec-id verify <path\|package>` | hash files now and compare with the package database |
| `minsec-id baseline [--reset] [--check ID…]` | show or reset baselines |
| `minsec-id checks` / `enable` / `disable <id>` | checks and daemon rules |
| `minsec-id inspect` | host capabilities and configuration sources |
| `minsec-id check` | validate configuration |
| `minsec-id daemon` | the eBPF monitor, in the foreground |
| `minsec-id events` | the findings log |

Complete references: `minsec-id(1)` and `minsec-id.toml(5)`.

## License

GPL-3.0-or-later.
