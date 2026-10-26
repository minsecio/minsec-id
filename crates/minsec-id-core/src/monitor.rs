//! The daemon's rules: ring buffer events from the BPF monitor in, findings
//! out. The kernel side only filters; every judgement is made here, where
//! it can use the package database, `/proc`, and the accounts, and where it
//! can be tested with synthetic events.
//!
//! A rule's findings are events, not state: they go to the findings log,
//! the journal, and the hook as they happen (a repeat within
//! `daemon.repeat` is suppressed), and are not tracked as open findings the
//! way scan findings are.

use crate::check::kmod::modules_dep;
use crate::check::persistence::{self, PAM_MODULES};
use crate::check::proc_exe::{benign_memfd, suspicious_location};
use crate::check::service_shell::is_shell;
use crate::check::{bpf_progs, path_is_code};
use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::pkgdb::PkgDb;
use crate::{procfs, users};
use minsec_id_bpf::{flags, Event, Kind, Probe};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    /// Finding ids besides the rule's own.
    pub emits: &'static [&'static str],
    pub probes: &'static [Probe],
}

static RULES: &[Rule] = &[
    Rule {
        id: "exec",
        description:
            "programs run from memory, deleted files, writable or unowned system paths, or as a service's network shell",
        emits: &[
            "exec-memfd",
            "exec-deleted",
            "exec-writable",
            "exec-unowned",
            "exec-service-shell",
        ],
        probes: &[Probe::Exec],
    },
    Rule {
        id: "write-sensitive",
        description: "writes to login, loader, boot, and persistence files outside package transactions",
        emits: &[],
        probes: &[Probe::Write],
    },
    Rule {
        id: "module-load",
        description: "kernel modules loaded from outside the packaged module tree, or unsigned",
        emits: &[],
        probes: &[Probe::Module],
    },
    Rule {
        id: "kexec-load",
        description: "a kernel loaded to be booted into by kexec",
        emits: &[],
        probes: &[Probe::Kexec],
    },
    Rule {
        id: "bpf-load",
        description: "eBPF tracing, kprobe, and LSM programs loaded",
        emits: &[],
        probes: &[Probe::Bpf],
    },
    Rule {
        id: "priv-escalation",
        description: "a process gaining root other than by running a setuid program",
        emits: &[],
        probes: &[Probe::Creds],
    },
    Rule {
        id: "ptrace-attach",
        description: "a process attaching to, or writing the memory of, another user's process",
        emits: &[],
        probes: &[Probe::Ptrace],
    },
    Rule {
        id: "devmem-open",
        description: "/dev/mem, /dev/port, or /proc/kcore opened",
        emits: &[],
        probes: &[Probe::DevMem],
    },
];

pub fn rules() -> &'static [Rule] {
    RULES
}

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// The rule that emits findings under `finding_id`.
pub fn rule_for(finding_id: &str) -> Option<&'static Rule> {
    RULES
        .iter()
        .find(|r| r.id == finding_id || r.emits.contains(&finding_id))
}

fn rule_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Exec => "exec",
        Kind::Write => "write-sensitive",
        Kind::Module => "module-load",
        Kind::Kexec => "kexec-load",
        Kind::Bpf => "bpf-load",
        Kind::Creds => "priv-escalation",
        Kind::Ptrace => "ptrace-attach",
        Kind::DevMem => "devmem-open",
    }
}

/// Where everything executable should come from a package. (`/usr/local`
/// and `/opt` are the administrator's.)
fn system_path(p: &str) -> bool {
    (p.starts_with("/usr/") && !p.starts_with("/usr/local/"))
        || ["/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/"]
            .iter()
            .any(|d| p.starts_with(d))
}

fn is_module(p: &str) -> bool {
    p.contains("/lib/modules/") && [".ko", ".ko.xz", ".ko.zst", ".ko.gz"].iter().any(|s| p.ends_with(s))
}

/// Package-owned executables and kernel modules under the system paths, as
/// hashes of their paths keyed per process (so a colliding name cannot be
/// chosen in advance). A few hundred KB where the package database itself
/// is tens of MB.
pub struct Owned {
    hashes: Vec<u64>,
    key: std::collections::hash_map::RandomState,
    stamp: u64,
}

/// Changes whenever a package database does.
fn db_stamp(host: &Host) -> u64 {
    [
        "/usr/lib/sysimage/rpm/rpmdb.sqlite",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/rpm/Packages",
        "/var/lib/dpkg/status",
    ]
    .iter()
    .filter_map(|p| std::fs::metadata(host.path(p)).ok())
    .map(|m| (m.mtime() as u64) << 20 ^ m.mtime_nsec() as u64 ^ m.ino())
    .fold(0, |a, b| a ^ b)
}

impl Owned {
    pub fn build(host: &Host) -> anyhow::Result<Self> {
        let stamp = db_stamp(host);
        let db = PkgDb::load(host)?;
        Ok(Self::from_db(host, &db, stamp))
    }

    fn from_db(host: &Host, db: &PkgDb, stamp: u64) -> Self {
        let key = std::collections::hash_map::RandomState::new();
        let mut hashes: Vec<u64> = db
            .files()
            .filter(|f| f.installed && f.is_regular())
            .filter_map(|f| {
                let p = f.path();
                if !system_path(&p) {
                    return None;
                }
                // dpkg records no modes: ask the file.
                let exec = match f.mode {
                    Some(m) => m & 0o111 != 0,
                    None => std::fs::metadata(host.path(&p)).is_ok_and(|m| m.permissions().mode() & 0o111 != 0),
                };
                (exec || is_module(&p)).then(|| key.hash_one(p.as_str()))
            })
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        Self { hashes, key, stamp }
    }

    pub fn contains(&self, path: &str) -> bool {
        self.hashes.binary_search(&self.key.hash_one(path)).is_ok()
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    fn stale(&self, host: &Host) -> bool {
        db_stamp(host) != self.stamp
    }
}

/// Programs that write system files as their job; writes by them or their
/// descendants (scriptlets, triggers) are the package database's to explain.
const PACKAGE_TOOLS: &[&str] = &[
    "/usr/bin/rpm",
    "/usr/bin/rpmkeys",
    "/usr/bin/dnf",
    "/usr/bin/dnf5",
    "/usr/bin/dnf-3",
    "/usr/bin/yum",
    "/usr/bin/microdnf",
    "/usr/libexec/packagekitd",
    "/usr/bin/rpm-ostree",
    "/usr/bin/bootc",
    "/usr/bin/zypper",
    "/usr/bin/dpkg",
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/aptitude",
    "/usr/bin/unattended-upgrade",
    "/usr/lib/snapd/snapd",
];

/// Account tools: their writes to the account files are their job.
const ACCOUNT_TOOLS: &[&str] = &[
    "passwd",
    "chpasswd",
    "chage",
    "chsh",
    "chfn",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "gpasswd",
    "newusers",
    "vipw",
    "vigr",
    "pwconv",
    "grpconv",
    "systemd-sysusers",
    "lusermod",
    "luseradd",
    "lchage",
    "lpasswd",
    "adduser",
    "deluser",
    "addgroup",
    "delgroup",
];

const ACCOUNT_FILES: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"];

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// How much a write to `path` matters by itself, and why.
fn sensitive(path: &str, created: bool) -> Option<(Severity, &'static str)> {
    let name = base(path);
    if name.starts_with("authorized_keys") {
        return Some((Severity::High, "SSH authorized keys"));
    }
    if path == "/etc/ld.so.preload" {
        return Some((Severity::High, "the dynamic loader's preload list"));
    }
    if PAM_MODULES
        .iter()
        .any(|d| path.strip_prefix(d).is_some_and(|r| r.starts_with('/')))
    {
        return Some((Severity::High, "a PAM module"));
    }
    if path.starts_with("/boot/") {
        // Rewritten by the bootloader's tools at every boot.
        if name == "grubenv" || name == "random-seed" {
            return None;
        }
        return Some((Severity::High, "a boot file"));
    }
    if ACCOUNT_FILES.contains(&path) {
        return Some((Severity::Medium, "an account database"));
    }
    if let Some(sev) = persistence::location(path) {
        return Some((sev, "a persistence or authentication location"));
    }
    if path_is_code(path) && !path.starts_with("/usr/local/") && !path.starts_with("/usr/lib/sysimage/") {
        if !created && !name.ends_with(".pyc") {
            return Some((Severity::High, "a system program or library, modified in place"));
        }
        if ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"]
            .iter()
            .any(|d| path.starts_with(d))
        {
            return Some((Severity::Medium, "a new program in a system directory"));
        }
    }
    None
}

/// Whether the next full scan should hash this path.
fn dirty_candidate(path: &str) -> bool {
    (system_path(path) || path.starts_with("/etc/"))
        && !path.starts_with("/usr/lib/sysimage/")
        && !path.ends_with(".pyc")
}

/// A daemon finding as `minsec-id findings` shows it: every report of one
/// fingerprint within `daemon.recent`, from the findings log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Recent {
    #[serde(flatten)]
    pub finding: Finding,
    pub first_seen: u64,
    pub last_seen: u64,
    /// How many times it was reported (repeats within `daemon.repeat` are
    /// not reported, so this undercounts occurrences).
    pub count: u64,
    /// The accept rule covering it now, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<String>,
}

/// Daemon findings reported since `now - daemon.recent`, most recent first.
pub fn recent(cfg: &Config, now: u64) -> Vec<Recent> {
    let since = now.saturating_sub(cfg.daemon.recent.secs());
    let mut by_fp: HashMap<String, Recent> = HashMap::new();
    for ev in crate::events::EventLog::read_all(&cfg.events_file()) {
        let crate::events::Event::Finding { ts, finding } = ev else {
            continue;
        };
        if ts < since || rule_for(&finding.check).is_none() {
            continue;
        }
        by_fp
            .entry(finding.fingerprint.clone())
            .and_modify(|r| {
                r.last_seen = ts;
                r.count += 1;
                r.finding = finding.clone();
            })
            .or_insert_with(|| Recent {
                accepted: None,
                finding,
                first_seen: ts,
                last_seen: ts,
                count: 1,
            });
    }
    let mut v: Vec<Recent> = by_fp
        .into_values()
        .map(|mut r| {
            r.accepted = cfg.accepted(&r.finding).map(|(k, _)| k.to_string());
            r
        })
        .collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.last_seen));
    v
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    /// Kernel records examined, by kind: execs not already known to be
    /// unremarkable, and writes to watched paths. Not findings.
    pub events: BTreeMap<String, u64>,
    /// Findings reported, by severity.
    pub findings: BTreeMap<Severity, u64>,
    /// Repeats within `daemon.repeat`, not reported again.
    pub suppressed: u64,
    pub accepted: u64,
    /// Writes explained by a package transaction.
    pub package_writes: u64,
    /// Paths recorded for the next full scan.
    pub dirty: u64,
}

pub struct Outcome {
    pub findings: Vec<Finding>,
    /// The exec was unremarkable: the kernel need not send this file's execs again.
    pub exec_ok: bool,
}

pub struct Engine {
    cfg: Config,
    host: Host,
    owned: Option<Owned>,
    modules: Option<(std::time::SystemTime, BTreeMap<String, String>)>,
    accounts: (u64, HashMap<u32, users::User>),
    /// Fingerprint → when last reported.
    recent: HashMap<String, u64>,
    /// (pid, path) → ms: overlayfs opens a file twice per open.
    writes: HashMap<(u32, String), u64>,
    /// pid → (package transaction?, when looked up).
    pkg: HashMap<u32, (bool, u64)>,
    dirty: BTreeSet<String>,
    self_exe: Option<String>,
    pub stats: Stats,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Engine {
    pub fn new(cfg: Config, host: Host) -> Self {
        let self_exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string());
        Self {
            cfg,
            host,
            owned: None,
            modules: None,
            accounts: (0, HashMap::new()),
            recent: HashMap::new(),
            writes: HashMap::new(),
            pkg: HashMap::new(),
            dirty: BTreeSet::new(),
            self_exe,
            stats: Stats::default(),
        }
    }

    pub fn cfg(&self) -> &Config {
        &self.cfg
    }

    pub fn reload(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    pub fn enabled(&self, rule: &str) -> bool {
        self.cfg.check_enabled(rule, true)
    }

    /// The probes the enabled rules need.
    pub fn probes(&self) -> Vec<Probe> {
        let mut v: Vec<Probe> = RULES
            .iter()
            .filter(|r| self.enabled(r.id))
            .flat_map(|r| r.probes.iter().copied())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Build the ownership set (exec-unowned, module-load). Without a
    /// package database those findings are not made.
    pub fn load_ownership(&mut self) {
        match Owned::build(&self.host) {
            Ok(o) => {
                tracing::info!("{} package-owned executables and modules", o.len());
                self.owned = Some(o);
            }
            Err(e) => tracing::warn!("package database: {e:#}; unowned programs are not reported"),
        }
        // SAFETY: returns free heap pages to the kernel; the database was large.
        unsafe { libc::malloc_trim(0) };
    }

    pub fn owned_count(&self) -> usize {
        self.owned.as_ref().map_or(0, Owned::len)
    }

    /// Whether a package owns `path`, rebuilding the set first if the
    /// package database changed since it was built.
    fn owns(&mut self, path: &str) -> Option<bool> {
        let o = self.owned.as_ref()?;
        if o.contains(path) {
            return Some(true);
        }
        if o.stale(&self.host) {
            self.load_ownership();
            return self.owned.as_ref().map(|o| o.contains(path));
        }
        Some(false)
    }

    /// Whether `path` is a file a merged system extension provides: the
    /// `sysext` check reports extensions, not each file they bring.
    fn is_extension_file(&self, path: &str) -> bool {
        if !path.starts_with("/usr/") {
            return false;
        }
        let mounts = crate::procfs::mounts(&self.host);
        crate::sysext::Layers::usr(&self.host, &mounts)
            .is_some_and(|l| std::fs::metadata(self.host.path(path)).is_ok_and(|m| l.is_extension_file(path, &m)))
    }

    pub fn handle(&mut self, ev: &Event, now: u64) -> Outcome {
        *self.stats.events.entry(ev.kind.as_str().into()).or_default() += 1;
        tracing::debug!(
            "{} pid={} uid={} comm={} flags={:#x} path={} name={} arg0={:#x} arg1={:#x}",
            ev.kind.as_str(),
            ev.pid,
            ev.uid,
            ev.comm,
            ev.flags,
            ev.path,
            ev.name,
            ev.arg0,
            ev.arg1
        );
        let rule = rule_of(ev.kind);
        if !self.enabled(rule) {
            return Outcome {
                findings: Vec::new(),
                exec_ok: false,
            };
        }
        let (found, exec_ok) = match ev.kind {
            Kind::Exec => self.exec(ev),
            Kind::Write => (self.write(ev), false),
            Kind::Module => (self.module(ev), false),
            Kind::Kexec => (self.kexec(ev), false),
            Kind::Bpf => (self.bpf(ev), false),
            Kind::Creds => (self.creds(ev), false),
            Kind::Ptrace => (self.ptrace(ev), false),
            Kind::DevMem => (self.devmem(ev), false),
        };
        let findings = self.report(rule, found, now);
        Outcome { findings, exec_ok }
    }

    /// Apply severity overrides, accept rules, and repeat suppression.
    fn report(&mut self, rule: &str, found: Vec<Finding>, now: u64) -> Vec<Finding> {
        let repeat = self.cfg.daemon.repeat.secs();
        let mut out = Vec::new();
        for mut f in found {
            if let Some(s) = self.cfg.severity_override(rule) {
                f.severity = s;
            }
            if self.cfg.accepted(&f).is_some() {
                self.stats.accepted += 1;
                continue;
            }
            match self.recent.get(&f.fingerprint) {
                Some(t) if now.saturating_sub(*t) < repeat => {
                    self.stats.suppressed += 1;
                    continue;
                }
                _ => {}
            }
            self.recent.insert(f.fingerprint.clone(), now);
            *self.stats.findings.entry(f.severity).or_default() += 1;
            out.push(f);
        }
        out
    }

    /// Forget what no longer matters: called every few seconds.
    pub fn prune(&mut self, now: u64) {
        let repeat = self.cfg.daemon.repeat.secs();
        self.recent.retain(|_, t| now.saturating_sub(*t) < repeat);
        let ms = now_ms();
        self.writes.retain(|_, t| ms.saturating_sub(*t) < 2_000);
        self.pkg.retain(|_, (_, t)| ms.saturating_sub(*t) < 10_000);
    }

    /// Paths recorded for the next full scan since the last call.
    pub fn take_dirty(&mut self) -> Vec<String> {
        std::mem::take(&mut self.dirty).into_iter().collect()
    }

    fn detail(&self, ev: &Event) -> serde_json::Value {
        serde_json::json!({
            "pid": ev.pid,
            "ppid": ev.ppid,
            "uid": ev.uid,
            "euid": ev.euid,
            "comm": ev.comm,
            "parent": ev.pcomm,
            "exe": self.exe_of(ev.pid),
            "cmdline": procfs::cmdline(&self.host, ev.pid),
            "container": !ev.has(flags::HOST_ROOT),
        })
    }

    fn exe_of(&self, pid: u32) -> Option<String> {
        self.host
            .read_link(format!("/proc/{pid}/exe"))
            .map(|e| e.trim_end_matches(" (deleted)").to_string())
    }

    fn is_self(&self, pid: u32) -> bool {
        self.self_exe.is_some() && self.exe_of(pid) == self.self_exe
    }

    /// Whether `pid` (or, if it has exited, `ppid`) is a package manager or
    /// runs under one.
    fn in_transaction(&mut self, pid: u32, ppid: u32) -> bool {
        if let Some((v, _)) = self.pkg.get(&pid) {
            return *v;
        }
        let start = if self.host.exists(format!("/proc/{pid}")) {
            pid
        } else {
            ppid
        };
        let mut cur = start;
        let mut found = false;
        for _ in 0..16 {
            if cur <= 1 {
                break;
            }
            if self.is_package_tool(cur) {
                found = true;
                break;
            }
            match procfs::read(&self.host, cur, None) {
                Some(p) => cur = p.ppid,
                None => break,
            }
        }
        self.pkg.insert(pid, (found, now_ms()));
        found
    }

    fn is_package_tool(&self, pid: u32) -> bool {
        let Some(exe) = self.exe_of(pid) else { return false };
        if PACKAGE_TOOLS.contains(&exe.as_str()) {
            return true;
        }
        // dnf 4, unattended-upgrades: Python scripts.
        if base(&exe).starts_with("python") {
            let raw = self.host.read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if let Some(script) = raw.split(|b| *b == 0).nth(1) {
                let script = String::from_utf8_lossy(script);
                return PACKAGE_TOOLS.iter().any(|t| *t == script || base(t) == script);
            }
        }
        false
    }

    fn account(&mut self, uid: u32) -> Option<users::User> {
        let now = now_ms();
        if now.saturating_sub(self.accounts.0) > 300_000 {
            self.accounts = (now, users::passwd(&self.host).into_iter().map(|u| (u.uid, u)).collect());
        }
        self.accounts.1.get(&uid).cloned()
    }

    fn exec(&mut self, ev: &Event) -> (Vec<Finding>, bool) {
        let host = ev.has(flags::HOST_ROOT);
        let deleted = ev.has(flags::DELETED) || ev.path.ends_with(" (deleted)");
        let path = ev.path.trim_end_matches(" (deleted)").to_string();
        let mut verdict: Option<(&str, Severity, String)> = None;
        if let Some(name) = path.strip_prefix("/memfd:") {
            if !benign_memfd(name) {
                verdict = Some((
                    "exec-memfd",
                    Severity::High,
                    format!(
                        "{} (pid {}) is running from an anonymous memory file: {path}",
                        ev.comm, ev.pid
                    ),
                ));
            }
        } else if suspicious_location(&path, host) || (host && ev.has(flags::TMPFS)) {
            verdict = Some((
                "exec-writable",
                Severity::High,
                format!(
                    "{path} was run (pid {}, parent {}) from a writable or hidden location",
                    ev.pid, ev.pcomm
                ),
            ));
        } else if deleted {
            verdict = Some((
                "exec-deleted",
                if host { Severity::High } else { Severity::Medium },
                format!("{path} was run (pid {}) after being deleted", ev.pid),
            ));
        } else if host
            && !ev.has(flags::PATH_RAW)
            && system_path(&path)
            && self.owns(&path) == Some(false)
            && !self.in_transaction(ev.pid, ev.ppid)
            && !self.is_extension_file(&path)
        {
            verdict = Some((
                "exec-unowned",
                Severity::High,
                format!("{path} was run (pid {}) but no package installed it", ev.pid),
            ));
        }
        let mut out: Vec<Finding> = verdict
            .map(|(id, sev, msg)| Finding::new(id, sev, &path, "").message(msg).detail(self.detail(ev)))
            .into_iter()
            .collect();
        let stdio = ev.has(flags::STDIN_INET) || ev.has(flags::STDOUT_INET);
        if host && stdio && ev.uid != 0 && is_shell(&path) {
            let acct = self.account(ev.uid);
            let service = match &acct {
                Some(u) => u.uid < 1000 || !u.can_login(),
                None => ev.uid < 1000,
            };
            if service {
                let user = acct.map(|u| u.name).unwrap_or_else(|| ev.uid.to_string());
                out.push(
                    Finding::new("exec-service-shell", Severity::High, format!("{user}:{path}"), "")
                        .message(format!(
                            "{path} started as service account {user} (pid {}, parent {}) with a network socket on stdio",
                            ev.pid, ev.pcomm
                        ))
                        .detail(self.detail(ev)),
                );
            }
        }
        let quiet = flags::DELETED | flags::TMPFS | flags::STDIN_INET | flags::STDOUT_INET | flags::PATH_RAW;
        let ok = out.is_empty() && host && ev.flags & quiet == 0;
        (out, ok)
    }

    fn write(&mut self, ev: &Event) -> Vec<Finding> {
        let ms = now_ms();
        let key = (ev.pid, ev.path.clone());
        if self.writes.get(&key).is_some_and(|t| ms.saturating_sub(*t) < 2_000) {
            return Vec::new();
        }
        self.writes.insert(key, ms);
        if self.in_transaction(ev.pid, ev.ppid) {
            self.stats.package_writes += 1;
            return Vec::new();
        }
        let path = ev.path.as_str();
        let created = ev.has(flags::CREATED);
        if let Some((sev, what)) = sensitive(path, created) {
            let exe = self.exe_of(ev.pid);
            let writer = exe.clone().unwrap_or_else(|| ev.comm.clone());
            if ACCOUNT_FILES.contains(&path) && ACCOUNT_TOOLS.contains(&base(&writer)) {
                return Vec::new();
            }
            let mut d = self.detail(ev);
            d["created"] = created.into();
            return vec![Finding::new("write-sensitive", sev, path, &writer)
                .message(format!(
                    "{path} ({what}) {} by {} (pid {}, uid {})",
                    if created { "created" } else { "opened for writing" },
                    writer,
                    ev.pid,
                    ev.uid
                ))
                .detail(d)];
        }
        if dirty_candidate(path) && self.dirty.len() < 100_000 && self.dirty.insert(path.to_string()) {
            self.stats.dirty += 1;
        }
        Vec::new()
    }

    fn module(&mut self, ev: &Event) -> Vec<Finding> {
        let name = ev.name.replace('-', "_");
        let dep_mtime = self
            .host
            .read_opt("/proc/sys/kernel/osrelease")
            .and_then(|r| {
                ["/usr/lib/modules", "/lib/modules"]
                    .iter()
                    .find_map(|b| std::fs::metadata(self.host.path(format!("{b}/{r}/modules.dep"))).ok())
            })
            .and_then(|m| m.modified().ok());
        if self.modules.as_ref().map(|(t, _)| Some(*t)) != Some(dep_mtime) {
            let map = modules_dep(&self.host).map(|(_, m)| m).unwrap_or_default();
            self.modules = dep_mtime.map(|t| (t, map));
        }
        let path = self.modules.as_ref().and_then(|(_, m)| m.get(&name).cloned());
        let unsigned = ev.arg0 == 0;
        let (sev, why) = match &path {
            None => (
                Severity::High,
                "is not in modules.dep: loaded from an arbitrary file".to_string(),
            ),
            Some(p) => match self.owns(&crate::host::normalize(p)) {
                Some(false) if p.contains("/updates/dkms/") || p.contains("/extra/") => {
                    (Severity::Low, format!("({p}) was built locally (DKMS)"))
                }
                Some(false) => (Severity::Medium, format!("({p}) is not from a package")),
                _ if unsigned => (Severity::Medium, format!("({p}) is not signed")),
                _ => return Vec::new(),
            },
        };
        let sev = if unsigned { sev.max(Severity::Medium) } else { sev };
        let mut d = self.detail(ev);
        d["module"] = ev.name.clone().into();
        d["path"] = path.clone().into();
        d["signed"] = match ev.arg0 {
            1 => true.into(),
            0 => false.into(),
            _ => serde_json::Value::Null,
        };
        d["taints"] = ev.arg1.into();
        vec![
            Finding::new("module-load", sev, &ev.name, path.as_deref().unwrap_or(""))
                .message(format!(
                    "module {} loaded by {} (pid {}) {why}{}",
                    ev.name,
                    ev.comm,
                    ev.pid,
                    if unsigned { ", unsigned" } else { "" }
                ))
                .detail(d),
        ]
    }

    fn kexec(&mut self, ev: &Event) -> Vec<Finding> {
        // kexec_load: KEXEC_ON_CRASH = 1. kexec_file_load: KEXEC_FILE_UNLOAD = 1, KEXEC_FILE_ON_CRASH = 2.
        let (crash, unload) = match ev.arg0 {
            0 => (ev.arg1 & 1 != 0, false),
            _ => (ev.arg1 & 2 != 0, ev.arg1 & 1 != 0),
        };
        if unload {
            return Vec::new();
        }
        let (sev, what) = if crash {
            (Severity::Low, "a crash kernel (kdump)")
        } else {
            (Severity::High, "a kernel to boot into, bypassing the bootloader")
        };
        vec![Finding::new("kexec-load", sev, &ev.comm, &format!("{crash}"))
            .message(format!("{} (pid {}) loaded {what}", ev.comm, ev.pid))
            .detail(self.detail(ev))]
    }

    fn bpf(&mut self, ev: &Event) -> Vec<Finding> {
        // A scan's task iterator, and the loader's feature probes before
        // it, are ours.
        if ev.pid == 1 || self.is_self(ev.pid) {
            return Vec::new();
        }
        let exe = self.exe_of(ev.pid).unwrap_or_else(|| ev.comm.clone());
        // systemd (the system and user managers, and its helpers) loads its
        // own: RestrictFileSystems=, and feature probes such as det_arg_ctx.
        // Only the packaged binaries count: the kernel resolves the exe, and
        // replacing one is itself reported.
        if exe.starts_with("/usr/lib/systemd/") && self.owns(&exe) == Some(true) {
            return Vec::new();
        }
        let kind = bpf_progs::TRACING_TYPES
            .iter()
            .find(|(t, _)| *t as u64 == ev.arg0)
            .map(|(_, k)| *k)
            .unwrap_or("tracing");
        let name = if ev.name.is_empty() { "(unnamed)" } else { &ev.name };
        vec![
            Finding::new("bpf-load", Severity::Medium, format!("{exe}:{kind}/{name}"), "")
                .message(format!("{exe} (pid {}) loaded a {kind} BPF program {name}", ev.pid))
                .detail(self.detail(ev)),
        ]
    }

    fn creds(&mut self, ev: &Event) -> Vec<Finding> {
        let exe = self.exe_of(ev.pid).unwrap_or_else(|| ev.comm.clone());
        vec![
            Finding::new("priv-escalation", Severity::Critical, &exe, &ev.pid.to_string())
                .message(format!(
                    "{exe} (pid {}, uid {}) became root without running a setuid program",
                    ev.pid, ev.uid
                ))
                .detail(self.detail(ev)),
        ]
    }

    fn ptrace(&mut self, ev: &Event) -> Vec<Finding> {
        let target = ev.arg1 as u32;
        let Some(t) = procfs::read(&self.host, target, None) else {
            return Vec::new();
        };
        if t.uid == ev.euid || t.pid == ev.pid {
            return Vec::new();
        }
        let tracer = self.exe_of(ev.pid).unwrap_or_else(|| ev.comm.clone());
        let what = if ev.arg0 == 0xffff_ffff {
            "wrote the memory of"
        } else {
            "attached to"
        };
        let sev = if t.uid == 0 && ev.euid != 0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut d = self.detail(ev);
        d["target"] = serde_json::json!({ "pid": t.pid, "uid": t.uid, "comm": t.comm, "exe": t.exe });
        vec![Finding::new("ptrace-attach", sev, format!("{tracer}->{}", t.comm), "")
            .message(format!(
                "{tracer} (pid {}, uid {}) {what} {} (pid {}, uid {})",
                ev.pid, ev.euid, t.comm, t.pid, t.uid
            ))
            .detail(d)]
    }

    fn devmem(&mut self, ev: &Event) -> Vec<Finding> {
        let write = ev.arg1 & 2 != 0;
        let exe = self.exe_of(ev.pid).unwrap_or_else(|| ev.comm.clone());
        vec![Finding::new(
            "devmem-open",
            if write { Severity::High } else { Severity::Medium },
            &ev.path,
            &exe,
        )
        .message(format!(
            "{} opened for {} by {exe} (pid {})",
            ev.path,
            if write { "writing" } else { "reading" },
            ev.pid
        ))
        .detail(self.detail(ev))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkgdb::tests::sample;

    fn engine() -> Engine {
        let mut e = Engine::new(Config::default(), Host::default());
        let db = sample(&Host::default(), &[("/usr/bin/owned", "00")]);
        let mut o = Owned::from_db(&Host::default(), &db, 0);
        // The sample has no modes; mark its one file as owned directly.
        o.hashes = vec![o.key.hash_one("/usr/bin/owned")];
        o.stamp = db_stamp(&Host::default());
        e.owned = Some(o);
        e
    }

    fn exec(path: &str, flags: u32) -> Event {
        let mut ev = Event::new(Kind::Exec);
        ev.pid = u32::MAX - 1; // no such process: nothing is read from /proc
        ev.ppid = u32::MAX - 2;
        ev.flags = flags | flags::HOST_ROOT;
        ev.path = path.into();
        ev.comm = "x".into();
        ev
    }

    fn ids(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.check.as_str()).collect()
    }

    #[test]
    fn rule_ids_are_unique_and_distinct_from_checks() {
        let mut seen = BTreeSet::new();
        for r in rules() {
            for id in std::iter::once(r.id).chain(r.emits.iter().copied()) {
                assert!(seen.insert(id), "duplicate rule id {id}");
                assert!(crate::check::producer(id).is_none(), "{id} is also a check id");
            }
        }
        assert_eq!(rule_for("exec-memfd").unwrap().id, "exec");
        for k in [
            Kind::Exec,
            Kind::Write,
            Kind::Module,
            Kind::Kexec,
            Kind::Bpf,
            Kind::Creds,
            Kind::Ptrace,
            Kind::DevMem,
        ] {
            assert!(rule(rule_of(k)).is_some());
        }
    }

    #[test]
    fn exec_rules() {
        let mut e = engine();
        assert_eq!(ids(&e.handle(&exec("/tmp/x", 0), 1)), ["exec-writable"]);
        assert_eq!(
            ids(&e.handle(&exec("/memfd:pwn (deleted)", flags::DELETED), 1)),
            ["exec-memfd"]
        );
        assert!(e
            .handle(&exec("/memfd:runc_cloned:/proc/self/exe", 0), 1)
            .findings
            .is_empty());
        assert_eq!(
            ids(&e.handle(&exec("/opt/x/y (deleted)", flags::DELETED), 1)),
            ["exec-deleted"]
        );
        assert_eq!(ids(&e.handle(&exec("/usr/bin/evil", 0), 1)), ["exec-unowned"]);
        assert_eq!(
            ids(&e.handle(&exec("/srv/app/run", flags::TMPFS), 1)),
            ["exec-writable"]
        );
        let ok = e.handle(&exec("/usr/bin/owned", 0), 1);
        assert!(
            ok.findings.is_empty() && ok.exec_ok,
            "an owned program is cached as fine"
        );
        let raw = e.handle(&exec("/usr/bin/owned", flags::PATH_RAW), 1);
        assert!(raw.findings.is_empty() && !raw.exec_ok);
        // Containers have their own /usr and their own /tmp conventions.
        let mut c = exec("/usr/bin/evil", 0);
        c.flags &= !flags::HOST_ROOT;
        assert!(e.handle(&c, 1).findings.is_empty());
        // /usr/local is the administrator's.
        assert!(e.handle(&exec("/usr/local/bin/tool", 0), 1).findings.is_empty());
    }

    #[test]
    fn service_shell() {
        let mut e = engine();
        e.accounts = (
            now_ms(),
            HashMap::from([(
                48,
                users::User {
                    name: "apache".into(),
                    passwd: "x".into(),
                    uid: 48,
                    gid: 48,
                    home: "/usr/share/httpd".into(),
                    shell: "/sbin/nologin".into(),
                },
            )]),
        );
        let mut ev = exec("/usr/bin/owned", flags::STDIN_INET);
        ev.path = "/usr/bin/bash".into();
        ev.uid = 48;
        // /usr/bin/bash is not in this engine's ownership set, so add it.
        let o = e.owned.as_mut().unwrap();
        let h = o.key.hash_one("/usr/bin/bash");
        o.hashes.push(h);
        o.hashes.sort_unstable();
        let o = e.handle(&ev, 1);
        assert_eq!(ids(&o), ["exec-service-shell"]);
        assert_eq!(o.findings[0].subject, "apache:/usr/bin/bash");
        assert!(!o.exec_ok);
    }

    #[test]
    fn repeats_are_suppressed_and_accept_applies() {
        let mut e = engine();
        assert_eq!(e.handle(&exec("/tmp/x", 0), 100).findings.len(), 1);
        assert!(e.handle(&exec("/tmp/x", 0), 200).findings.is_empty());
        assert_eq!(e.stats.suppressed, 1);
        assert_eq!(e.handle(&exec("/tmp/x", 0), 100 + 3600).findings.len(), 1);
        e.reload(Config::parse("[accept.\"exec-writable:/tmp/*\"]\n").unwrap());
        assert!(e.handle(&exec("/tmp/y", 0), 1).findings.is_empty());
        assert_eq!(e.stats.accepted, 1);
        e.reload(Config::parse("[checks.exec]\nenabled = false\n").unwrap());
        assert!(e.handle(&exec("/tmp/z", 0), 1).findings.is_empty());
        assert!(!e.probes().contains(&Probe::Exec));
    }

    #[test]
    fn writes() {
        let mut e = engine();
        let w = |path: &str, flags: u32| {
            let mut ev = Event::new(Kind::Write);
            ev.pid = u32::MAX - 1;
            ev.ppid = u32::MAX - 2;
            ev.flags = flags | flags::HOST_ROOT;
            ev.path = path.into();
            ev.comm = "sh".into();
            ev
        };
        let o = e.handle(&w("/etc/ld.so.preload", flags::CREATED), 1);
        assert_eq!(o.findings[0].severity, Severity::High);
        // overlayfs's second open of the same file is the same write
        assert!(e.handle(&w("/etc/ld.so.preload", 0), 1).findings.is_empty());
        assert_eq!(
            e.handle(&w("/root/.ssh/authorized_keys", 0), 1).findings[0].severity,
            Severity::High
        );
        assert_eq!(e.handle(&w("/etc/sudoers.d/x", flags::CREATED), 1).findings.len(), 1);
        assert_eq!(
            e.handle(&w("/etc/cron.d/job", flags::CREATED), 1).findings[0].severity,
            Severity::Medium
        );
        assert_eq!(e.handle(&w("/usr/bin/ls", 0), 1).findings[0].severity, Severity::High);
        assert_eq!(
            e.handle(&w("/usr/bin/newtool", flags::CREATED), 1).findings[0].severity,
            Severity::Medium
        );
        assert!(e.handle(&w("/boot/grub2/grubenv", 0), 1).findings.is_empty());
        assert!(e
            .handle(&w("/usr/lib/python3.12/__pycache__/x.pyc", flags::CREATED), 1)
            .findings
            .is_empty());
        assert!(e
            .handle(&w("/usr/share/doc/x/README", flags::CREATED), 1)
            .findings
            .is_empty());
        assert!(e.handle(&w("/etc/hostname", 0), 1).findings.is_empty());
        let dirty = e.take_dirty();
        assert!(dirty.contains(&"/usr/share/doc/x/README".to_string()));
        assert!(dirty.contains(&"/etc/hostname".to_string()));
        assert!(!dirty.iter().any(|p| p.ends_with(".pyc")));
        assert!(e.take_dirty().is_empty());
    }

    #[test]
    fn sensitivity() {
        assert!(sensitive("/usr/lib64/security/pam_evil.so", true).is_some());
        assert_eq!(sensitive("/etc/shadow", false).unwrap().0, Severity::Medium);
        assert!(sensitive("/var/spool/at/.SEQ", false).is_none());
        assert!(sensitive("/usr/lib/sysimage/rpm/rpmdb.sqlite-shm", false).is_none());
        assert!(persistence::location("/etc/systemd/system/x.service").is_some());
        assert!(persistence::location("/etc/systemd/systemx").is_none());
    }

    #[test]
    fn kexec_and_bpf() {
        let mut e = engine();
        let mut k = Event::new(Kind::Kexec);
        k.pid = u32::MAX - 1;
        k.comm = "kexec".into();
        k.arg0 = 1;
        k.arg1 = 2; // KEXEC_FILE_ON_CRASH
        assert_eq!(e.handle(&k, 1).findings[0].severity, Severity::Low);
        k.arg1 = 0;
        assert_eq!(e.handle(&k, 1).findings[0].severity, Severity::High);
        k.arg1 = 1; // unload
        assert!(e.handle(&k, 1).findings.is_empty());
        let mut b = Event::new(Kind::Bpf);
        b.pid = u32::MAX - 1;
        b.comm = "loader".into();
        b.name = "hook".into();
        b.arg0 = 2;
        assert_eq!(e.handle(&b, 1).findings[0].subject, "loader:kprobe/hook");
        b.pid = 1;
        assert!(e.handle(&b, 1).findings.is_empty(), "systemd's own");
    }
}
