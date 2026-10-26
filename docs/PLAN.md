# minsec-id — plan and recommendations

## Context

`minsec` replaced fail2ban with a ~2.5 MB Rust daemon. It works by letting the kernel do the
real work: nft sets with timeouts are the ban list, and journald does the matching. Host IDS tools
(AIDE, Tripwire, OSSEC/Wazuh, Samhain, rkhunter) are heavy in the same way fail2ban was. They keep
their own hash databases of the whole filesystem, rescan the disk on a schedule, and ship large
signature sets. A modern Linux host already holds most of that information:

- **What files should look like:** the package manager. rpmdb headers carry signed SHA-256 file
  digests; dpkg has md5sums. ostree, composefs and fs-verity cover image-based systems.
- **What changed:** the kernel. eBPF sees exec, module loads, BPF loads, credential changes and
  writes as they happen. Inode ctime, IMA measurements and fs-verity also record change.
- **Whether the system is in a trustworthy state:** taint flags, lockdown, Secure Boot,
  LSM/SELinux mode, the loaded BPF programs, and ftrace hooks.

`minsec-id` is the IDS sibling of `minsec`. It asks the OS and the kernel instead of keeping
parallel state, follows the same CLI, config, packaging and privacy conventions, and will later
report to minsec.io for crowd hash verification and fleet management.

**Decisions:**
- **Runtime shape:** one binary with two modes.
  - `minsec-id scan` is timer-driven and keeps no resident memory.
  - `minsec-id daemon` is an optional resident eBPF monitor.
- **Response:** detect and alert only for the MVP. Opt-in BPF-LSM enforcement comes in a later
  phase.
- **Platforms:** kernel ≥ 5.14 only. That means EL9/10, Debian 12+, Ubuntu 22.04+, Fedora and
  recent openSUSE. BTF, CO-RE, ring buffer, fentry and the bpf task iterators are therefore always
  present, so there is no legacy BPF fallback.
- **Crowd data:** crowd-verified package file hashes, sent only when a file mismatches, plus
  finding counts per check id. File content, users and hostnames are never sent.

**Honest scope statement** (goes in the README; minsec.io's PLAN.md takes the same stance):
- A kernel rootkit loaded *before* minsec-id can blind it. What we can detect:
  - the *act* of loading one, while the daemon is running;
  - sloppy hiding, via cross-view checks;
  - silencing of the agent, via a missed heartbeat (minsec.io phase).
- We do not claim APT-grade detection.

---

## 1. Key recommendations

| Decision | Recommendation | Why |
|---|---|---|
| Language/toolchain | Rust, edition 2021, MSRV 1.85. Same release profile as minsec (`opt-level="s"`, fat LTO, `codegen-units=1`, `panic=abort`, strip) | One family, one toolchain |
| Runtime | `scan`: plain synchronous code, no tokio. `daemon`: tokio `current_thread` with minsec's feature set | A scan is a straight-line batch job. The daemon needs ring buffer, socket and timers in one loop |
| eBPF | BPF programs in **C (CO-RE, checked-in `vmlinux.h`)**, built with clang in `build.rs` and embedded with `include_bytes!`. Loaded by **aya** (pure Rust, no libbpf `.so`) | C is the mature, well-documented BPF dialect, and userspace stays on stable Rust. CI fails the build if clang is missing; there is no BPF cargo feature |
| Hook choice | Tracepoints and raw tracepoints first, fentry on `security_*` functions second, LSM hooks only for Phase 5 enforcement | fentry on LSM functions works without `lsm=bpf` on the kernel command line, which EL9 does not set by default |
| Package DB access | Stream the package manager's own query output: `rpm -qa --qf '[…]'` and `/var/lib/dpkg/info/*.md5sums` + `status`. Do the comparison in Rust | No librpm or sqlite linkage. We control the I/O pacing, unlike `rpm -Va` |
| Hashing strategy | Hash a file only when there is evidence it changed (§3.2); otherwise a rolling 1/N sample. Never a full rescan per run | This is how we avoid AIDE-style whole-disk churn |
| State | Under `/var/lib/minsec-id/`, kept small: `state.json` (keys, fingerprints, sysctls, cmdline, accepted items), `findings.jsonl` (rotated), and `dirty.list` from the daemon. No file-hash database | The package DB *is* the baseline |
| Output | Findings go to a JSONL log, to journald via the native protocol (one datagram to `/run/systemd/journal/socket` with `MINSEC_CHECK=`, `PRIORITY=` and `MESSAGE_ID=` fields; no libsystemd), to the control socket, and to an `exec` notify hook | `journalctl MINSEC_CHECK=pkg-modified` works out of the box |
| Config | `/etc/minsec-id/minsec-id.toml` + `conf.d/*.toml`, loaded the same way as minsec (`Config::load_dir` with recursive `merge()`, `deny_unknown_fields`) | Same UX |
| Control | `/run/minsec-id/minsec-id.sock`, newline-delimited JSON with minsec's request/response shape | Virtualmin can drive both tools the same way |
| Network | Only in a separate `minsec-id-sync` binary (later phase). Neither the scanner nor the daemon has a TLS or HTTP stack | Same split as minsec/minsec-sync |
| Code sharing | Phase 0: copy minsec's generic modules, marking where each came from. Before Phase 4, extract them into a shared `minsec-common` crate. Use `minsec-proto` (signing, PoW) as a git dependency pinned to a tag | Avoids coupling release cycles too early, while making the wire code identical |
| Budgets | Binary ≤ 5 MB. Daemon anon RSS ≤ 5 MB, plus ≤ 2 MB of BPF maps. Quick scan < 1 s CPU. Full scan run at I/O-idle priority | Enforced as CI gates, as in minsec |

---

## 2. Architecture

```
            ┌──────────────── minsec-id scan (timer, oneshot, root, read-only sandbox) ───────────┐
 rpm/dpkg ──┤ pkgdb ─┐                                                                         │
 /proc,/sys ┤ probes ├─► checks (stable ids) ─► findings ─► dedup vs state/accept ─► sinks ────┼─► findings.jsonl
 bpf iters ─┤ fs walk┘                                                     (new/changed only)  │   journald fields
            └──────────────────────────────────────────────────────────────────────────────────┘   exec notify
            ┌──────────────── minsec-id daemon (optional, CAP_BPF/PERFMON) ────────────────────┐   control socket
 kernel ────┤ BPF progs ─► ringbuf ─► rules (exec/module/bpf/creds/write) ─► findings ─► sinks │
            │                          └─► dirty.list (paths written under /usr,/boot,/etc) ──► next scan hashes these
            └──────────────────────────────────────────────────────────────────────────────────┘
 minsec-id-sync (later, timer) ──► minsec.io: hash-check queries, finding counts, heartbeat
```

### 2.1 Workspace (this repo)

```
crates/
  minsec-id-core/   lib: config, pkgdb (rpm, dpkg; later flatpak, snap, ostree), probes (/proc, /sys,
                    sock_diag netlink, bpf syscall enumeration), checks/, findings, state, sinks
  minsec-id/        bin: CLI + `scan` + `daemon` (one binary, as in minsec)
  minsec-id-bpf/    C BPF sources, vmlinux.h, build.rs → embedded objects, plus the aya loader glue
  minsec-id-sync/   bin (Phase 4)
packaging/          units, tmpfiles, default toml, deb/rpm scripts (sysusers with the daemon, Phase 2)
docs/               PLAN.md, man/ (hand-written roff, as in minsec)
completions/        bash/zsh/fish
tests/              fixture rootfs + e2e scripts
```

Files to copy from minsec (each gets a provenance comment) and later extract into `minsec-common`:
- `crates/minsec-core/src/config.rs`: `merge()` and the `load_dir` pattern
- `crates/minsec-core/src/duration.rs`
- `crates/minsec-core/src/control.rs`: client with a 5 s timeout; make it generic over request/response
- The socket accept loop in `crates/minsec/src/daemon.rs` (~L48–84)
- `crates/minsec-core/src/events.rs`: JSONL append and 8 MB rotation; make the event type generic
- `crates/minsec-core/src/inspection.rs`: the `schema_version` JSON pattern
- Packaging and CI: unit hardening block, `scripts/check-glibc.sh`, the size gate,
  `scripts/release.sh`, cargo-deb / cargo-generate-rpm metadata, `release.yml` (cargo-zigbuild,
  pinned actions)

### 2.2 The finding model

Every check has a **stable kebab-case id**, for example `pkg-modified`, `proc-exe-deleted` or
`kmod-hidden`. This matches how minsec's filter names act as signature ids in the minsec.io
registry.

A finding has these fields:
- `check`
- `severity` (info / low / medium / high / critical)
- `subject`: a path, pid+exe, module name, or key fingerprint
- `fingerprint`: hash of check + subject + salient detail
- `detail`: a small object
- `first_seen` / `last_seen`

A finding is emitted to the sinks only when it is new or has changed, so repeated scans don't spam.
`minsec-id accept <fingerprint|check:subject>` writes an allow rule to
`conf.d/accept.toml`. The rules live in config, not state, so they can be audited and pushed by
config management, the same way `minsec enable` writes to `conf.d`.

**Baseline semantics:** the first scan records the current trust anchors in `state.json` and
reports anything that is unconditionally bad. Anchors are: repo keys, repos, authorized_keys
fingerprints, users, sysctls, cmdline, persistence entries and BPF programs. Later scans report
*changes* to those anchors. `minsec-id baseline --reset` re-records them.

---

## 3. Check catalog (MVP = Phases 1–2)

Each check declares its cost (`quick`: stat, /proc or /sys only; `full`: reads file contents) and
its requirements, which `inspect` reports as available or unavailable.

### 3.1 Kernel and boot (quick)
- `kernel-tainted`: decode the `/proc/sys/kernel/tainted` bits (P, O, E, F, …); report a change
  from the baseline.
- `kmod-unowned` / `kmod-unsigned`: a module whose `.ko` is not package-owned, or whose
  `/sys/module/*/taint` shows it unsigned.
- `kmod-hidden`: cross-view of `/proc/modules`, `/sys/module`, `kallsyms` module symbols, and a BPF
  iterator view.
- `bpf-prog-unknown`: enumerate programs with `BPF_PROG_GET_NEXT_ID` / `BPF_OBJ_GET_INFO_BY_FD`.
  Flag kprobe, tracing or LSM programs not loaded by systemd or by an allow-listed loader.
  ebpfkit- and TripleCross-style rootkits show up here. Also check pinned objects in `/sys/fs/bpf`.
- `ftrace-hooks`: non-empty `/sys/kernel/tracing/enabled_functions` or a kprobes list that is not
  explained by known BPF programs. Used by ftrace-hooking rootkits.
- `boot-posture`: report regressions from the baseline in:
  - lockdown, Secure Boot (efivars), `module.sig_enforce`
  - SELinux enforce / AppArmor mode
  - `/proc/cmdline` (`init=`, `selinux=0`, `lsm=`)
  - `kexec_loaded`
  - hardening sysctls (`kptr_restrict`, `ptrace_scope`, `unprivileged_bpf_disabled`,
    `modules_disabled`)
- `boot-files`: kernels, UKIs and bootloader files in `/boot` and the ESP verified against the
  package DB. Initramfs is locally generated, so for it we check only for a rebuild without a
  matching kernel install event.

### 3.2 Package integrity (full, but incremental)

Steps:
1. Stream (path, digest, size, mode, flags, package, install time) from rpm or dpkg.
2. Choose what to hash. A file is hashed if any of these apply:
   - **ctime > install time of the package that owns it.** This needs no stored state, and an
     attacker cannot set ctime without clock games or raw block-device edits.
   - The path is in the daemon's `dirty.list`.
   - The size or mode differs from the DB.
   - It falls in the rolling sample (default: the whole system once every 7 days, by hashing
     path-bucket `day % 7`).
3. Run under `IOSchedulingClass=idle`, `CPUWeight=idle`, with read-ahead hints.

Checks:
- `pkg-modified`: digest mismatch on a non-config file. Severity is high for files in `bin`, `sbin`,
  `lib*` and `/boot`.
- `pkg-config-modified`: a `%config` / conffile changed. Info by default; high for a security-
  relevant list (PAM, sshd_config, sudoers, `ld.so.*`, nsswitch).
- `pkg-missing`, `pkg-mode-changed` (includes newly added setuid/setgid bits).
- `pkg-db-tampered`: on rpm, verify the stored header signatures (`RSAHEADER`/`DSAHEADER`) against
  the imported keys, so an attacker who rewrites rpmdb digests to match a trojan is caught.
  dpkg md5sums cannot be authenticated locally. Crowd verification covers that gap in Phase 4.
- `exe-unowned`: executables, setuid files, and files carrying a `security.capability` xattr under
  `/usr/{bin,sbin,lib*,libexec}` and `/boot` that no package owns. This is a walk with stat only.
- `pkg-unsigned`: installed rpm without a signature, or from a key no longer in the keyring.
- A `minsec-id verify <path|package>` subcommand runs the same logic ad hoc.

### 3.3 Supply-chain anchors (quick)
- `repo-key-changed`: rpm `gpg-pubkey` packages / `rpmkeys --list`; apt `trusted.gpg(.d)`,
  `/usr/share/keyrings`, `/etc/apt/keyrings`; flatpak remote keys. Baseline is the fingerprints.
- `repo-changed`: `/etc/yum.repos.d`, `sources.list(.d)` and flatpak remotes added or changed.
  `gpgcheck=0`, `trusted=yes` or `[allow-insecure]` raises the severity.

### 3.4 Processes and network (quick, from /proc and netlink)
- `proc-exe-deleted`, `proc-exe-memfd`, `proc-exe-writable-path`: the process's exe is in `/tmp`,
  `/var/tmp`, `/dev/shm`, `/run/user`, or a dot-directory.
- `proc-hidden`: pids from a bpf task iterator compared with `readdir(/proc)`. A getdents-hooking
  rootkit shows up as a difference.
- `proc-preload`: `/etc/ld.so.preload` exists, or a daemon's environ has `LD_PRELOAD`, or `maps`
  contains libraries from writable or unowned paths.
- `proc-service-shell`: a shell or interpreter whose parent runs as a service user (apache,
  www-data, nginx, mysql, …) and whose stdio is a socket (webshell / reverse shell).
- `net-listener-unowned`: listening socket (via sock_diag netlink) whose owning process's exe is
  not package-owned.
- `net-hidden`: sock_diag compared with `/proc/net/*`.
- `net-raw-socket`: AF_PACKET/raw sockets with attached classic BPF filters, held by processes
  outside an allow list. BPFDoor fits this pattern.

### 3.5 Persistence and accounts (quick)

**Persistence:** new or changed entries that no package owns, compared against the baseline:
- systemd units, drop-ins, generators and timers, in `/etc`, `/run` and user dirs
- cron, at, rc.local, XDG autostart, update-motd.d, NM dispatcher
- udev rules, `modprobe.d` `install` lines, `modules-load.d`
- `/etc/profile.d` and shell rc files, initramfs hooks
- PAM: `pam_*.so` files not owned by a package → **critical**; `pam.d` changes

**Accounts:**
- uid 0 accounts other than root
- new users with a login shell
- empty password hashes
- new `NOPASSWD` sudoers rules
- `authorized_keys` changes for any user (fingerprints only), plus
  `AuthorizedKeysCommand`/`AuthorizedKeysFile` changes

**Anti-forensics:** history files symlinked to `/dev/null`; wtmp/lastlog that is truncated or has
gone backwards; `journalctl --verify` failures when FSS sealing is enabled.

### 3.6 Daemon real-time rules (Phase 2)

Program set (ring buffer 256 KB). Userspace dedupes and rate-limits per rule:
- **exec** (`sched_process_exec`): exec from tmpfs, memfd, a deleted file or a writable path;
  exec of a binary not package-owned, checked by dev+inode against an in-memory set of owned
  executables (~5–10k × 16 B); a service user spawning a shell or interpreter.
- **Module loads:** `module_load` tracepoint, `finit_module`.
- **kexec_load.**
- **BPF loads:** `bpf(BPF_PROG_LOAD)` of kprobe, tracing or LSM types by an unexpected process.
- **Privilege escalation:** fentry `commit_creds` where uid goes from non-zero to 0 without a
  setuid/fcaps exec in progress. This is the classic kernel-exploit tell.
- **Tracing others:** `ptrace` attach / `process_vm_writev` against other users' processes.
- **Writes to protected paths:** fentry `security_file_open` with write mode, filtered in-kernel to
  the root filesystem and resolved with `bpf_d_path`.
  - Immediate finding for high-value paths: `ld.so.preload`, PAM, `authorized_keys`, `/boot`,
    sudoers.
  - Anything else under `/usr` or `/etc` is appended to `dirty.list` for the next scan.
- Opens of `/dev/mem` and `/proc/kcore`.

Privileges: user `minsec-id` with `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
CAP_DAC_READ_SEARCH`, using the same hardening block as `minsec.service` (adjusting
`SystemCallFilter` for `bpf`). The scanner runs as root, but `ProtectSystem=strict`, all paths
read-only except `/var/lib/minsec-id`, and a capability bounding set limited to the read and
ptrace caps it needs. It does not use `PrivateNetwork` (the notify hook inherits the sandbox and
may need the network; the binary itself has no network code), nor `PrivateTmp`,
`PrivateDevices`, `ProtectKernelModules` or `ProtectHome=yes`: each hides something the scanner
inspects.

---

## 4. CLI (mirrors minsec: clap derive, `-c/--config-dir`, `--json` with `schema_version`)

| Command | |
|---|---|
| `minsec-id scan [--quick\|--full] [--check ID…]` | run checks; exits **0 clean, 1 error, 2 findings** (usable as a monitoring plugin). This is the one deliberate deviation from minsec's 0/1 |
| `minsec-id status` | last scan times and counts, daemon state, open findings by severity |
| `minsec-id findings [--all] [--severity S]` / `show <fp>` | list or inspect findings |
| `minsec-id accept <fp\|check:subject> [--reason]` / `unaccept` | writes `conf.d/accept.toml` |
| `minsec-id baseline [--reset]` | record or show trust anchors |
| `minsec-id checks` / `enable` / `disable <check>` | list checks with cost and availability; toggle |
| `minsec-id verify <path\|package>` | ad hoc integrity check |
| `minsec-id inspect` | capability report: kernel, BTF, BPF LSM, IMA, lockdown, Secure Boot, package managers, image-based or not |
| `minsec-id check` | validate config |
| `minsec-id events [--follow]` | finding stream (JSONL) |
| `minsec-id daemon` | the eBPF monitor |

Units:
- `minsec-id-scan.timer` runs a quick scan every 30 min and a full (incremental) scan daily, with
  `RandomizedDelaySec`.
- `minsec-id.service` runs the daemon and is optional: the package ships it disabled.
- Phase 4 adds `minsec-id-sync.timer`.

---

## 5. Phases

**Phase 0 (skeleton):**
- workspace and CI: fmt, clippy `-D warnings`, tests, size and glibc gates (clang and the
  `minsec-id-bpf` crate arrive with the daemon in Phase 2)
- copied common modules, config, finding model, sinks (JSONL, journald native, exec hook)
- `inspect`, `checks`, `check`
- packaging stubs (scan units and timers, tmpfiles, cargo-deb / generate-rpm)
- one end-to-end check: `kernel-tainted`

**Phase 1 (scanner MVP):** §3.1, §3.3, §3.4 (minus `proc-hidden`), §3.5, and §3.2 for rpm and dpkg
with ctime-incremental hashing and rolling sampling. Also accept/baseline, `verify`, man pages,
completions.

Phase 1 as built, where it differs from the plan above:
- **Configuration edits are watched by `persistence` only.** It runs in quick
  scans and covers PAM, sudoers, sshd, the loader, shell startup files, and
  more. `pkg-verify` skips configuration files, so one edit gives one
  finding. `pkg-config-modified` is emitted only by `minsec-id verify`.
- **No ownership cache.** Each scan streams the package database again:
  about 0.7 s of CPU and 55 MB of memory on a 3,400-package workstation, and
  a fraction of that on a server. A cache would be state an attacker could
  edit.
- **rpm `%verify` flags are honoured** (`FILEVERIFYFLAGS`), so `pkg-verify`
  agrees with `rpm -V` about files the package expects to change.
- **`pkg-db-tampered` relies on rpm's verification of header signatures as it
  reads the database.** It has not yet been tested against a deliberately
  edited rpmdb; that test belongs in the VM e2e suite.
- **`proc-service-shell` ignores root.** A root shell with a socket on stdio
  is not distinguished from legitimate ones yet.
- **`net-raw-socket` judges the process holding the socket**, not the socket
  filter attached to it. Reading the filter needs `packet_diag` and
  `CAP_NET_ADMIN`; a BPFDoor-style process already stands out by running a
  deleted or unowned binary.
- **The scanner keeps `CAP_SYS_ADMIN`.** The kernel requires it to list BPF
  programs.
- **`boot-kernel`** compares `/boot/vmlinuz-*` with
  `/usr/lib/modules/*/vmlinuz` (EL and Fedora). Debian packages the image
  itself, so `pkg-verify` covers it there. Initramfs images are not checked.
- **Deferred:** `journalctl --verify` for sealed journals.

**Phase 2 (eBPF daemon):** §3.6, the control socket, `dirty.list` handoff to the scanner,
`proc-hidden` / `kmod-hidden` via bpf iterators, RSS and BPF map budget gates.

**Phase 3 (more package formats and image-based systems):**
- flatpak: `ostree fsck` on its repo, remote keys
- snap: `snap known` assertions compared with the `.snap` sha3-384, hashed only on change
- ostree/bootc/composefs:
  - booted commit/image digest and its signature from `bootc status --json` / `rpm-ostree status`
  - composefs fs-verity enforced (`prepare-root.conf`)
  - `/usr` unlocked or overlaid
  - `ostree admin config-diff` for `/etc`
  - layered packages
- systemd-sysext images and dm-verity status
- IMA measurement list as a free source of hashes for executed files, where a policy is active

**Phase 4 (minsec.io integration):**
- `minsec-id-sync` with the same enrollment flow (PoW + Ed25519, `minsec-proto`)
- Data sent:
  - hash-check queries (distro, version, arch, package NEVRA, path, sha256), sent only for
    mismatching package-owned non-config files
  - repo-key fingerprint prevalence
  - finding counts per check id
  - heartbeat
- Backend work in `/home/joe/src/minsec.io`:
  - a `product` field on enroll and on `agents`
  - `POST /v1/findings` and `POST /v1/hashcheck`, with a new signing prefix
    (`minsec-id-findings-v1`) to prevent cross-product replay
  - new partitioned tables with retention entries in `internal/agg/retention.go`
  - a PRIVACY.md section
  - `install_token` → org binding for paid fleet management (missed-heartbeat alerts, findings
    aggregated per org)
  - Extract `minsec-common` first.

**Phase 5 (response):** opt-in BPF-LSM enforcement policies (deny exec from tmpfs or memfd, deny
module loads after boot, deny unexpected BPF loads), correlation with minsec (SSH source IP of the
session that spawned a flagged process), and IMA/TPM attestation via minsec.io.

---

## 6. Verification

- **Unit:**
  - fixture rootfs and fake `/proc` and `/sys` trees under `tests/fixtures/`
  - recorded `rpm --qf` and dpkg info outputs as pkgdb input
  - taint bit decoding, ctime-vs-install-time selection, rolling-sample coverage (every file is
    covered within N runs), finding dedup and accept matching, config merge
- **CLI:** `crates/minsec-id/tests/cli.rs` runs the binary via `CARGO_BIN_EXE_minsec-id` against a
  temporary config dir and a fixture root (`--root` hidden flag), as minsec's `tests/cli.rs` does.
- **Tamper e2e (`tests/e2e-tamper.sh`):** podman containers of EL9, Debian 12 and Ubuntu 24.04
  for scanner checks, plus a VM for kernel and BPF checks. The script:
  1. modifies `/usr/bin/ls`
  2. adds `/etc/ld.so.preload`
  3. adds an authorized key
  4. adds an apt/yum repo with `gpgcheck=0`
  5. runs a binary from `/tmp` and via memfd
  6. drops an unowned `pam_x.so`
  7. `insmod`s a test module (VM)
  8. attaches a kprobe with bpftrace (VM)
  9. asserts the expected check ids in `scan --json` / `events`
  10. asserts that a clean host exits 0
- **Performance gates in CI:** binary size; daemon anon RSS from `smaps_rollup`; quick-scan CPU
  time; full-scan bytes read from `/proc/self/io`, which must show the incremental path reads far
  less than a full hash on the second run.
- **Manual:** run alongside AIDE or `rpm -Va` / `debsums` on a real Virtualmin host for a week and
  diff the results.
