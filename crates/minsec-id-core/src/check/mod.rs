//! The check registry. Each check has a stable kebab-case id: it is what
//! operators enable and disable, and what the minsec.io registry will map to
//! categories (as minsec's filter names are). A check may emit findings under
//! further ids (`pkg-verify` emits `pkg-modified`, `pkg-missing`, …); those
//! are what operators accept.

use crate::config::Config;
use crate::finding::Finding;
use crate::host::Host;
use crate::pkgdb::PkgDb;
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

mod accounts;
mod antiforensics;
mod boot;
pub(crate) mod bpf_progs;
mod checkout;
mod exe_unowned;
mod flatpak;
mod ftrace;
mod ima;
mod kernel_tainted;
pub(crate) mod kmod;
mod net;
pub(crate) mod ostree_host;
pub(crate) mod persistence;
pub(crate) mod pkg_verify;
pub(crate) mod proc_exe;
mod proc_hidden;
mod proc_preload;
pub(crate) mod repos;
pub(crate) mod service_shell;
mod snap;
mod ssh_keys;
mod sysext;

pub use pkg_verify::{verify, VerifyReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cost {
    /// stat, /proc, /sys, small files: run every quick scan.
    Quick,
    /// Reads file contents at scale: full scans only.
    Full,
    /// A daemon rule: runs as events happen, not in scans.
    Daemon,
}

pub struct Ctx<'a> {
    pub host: &'a Host,
    pub cfg: &'a Config,
    pub now: u64,
    pub state_dir: PathBuf,
    pkgdb: OnceCell<Result<PkgDb, String>>,
}

impl<'a> Ctx<'a> {
    pub fn new(host: &'a Host, cfg: &'a Config, now: u64) -> Self {
        Self {
            host,
            cfg,
            now,
            state_dir: cfg.paths.state_dir.clone(),
            pkgdb: OnceCell::new(),
        }
    }

    /// The package database, loaded on first use and shared by every check
    /// in the scan.
    pub fn pkgdb(&self) -> anyhow::Result<&PkgDb> {
        match self.pkgdb.get_or_init(|| {
            let r = PkgDb::load(self.host).map_err(|e| format!("package database: {e:#}"));
            if let (Ok(db), true) = (&r, tracing::enabled!(tracing::Level::DEBUG)) {
                let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                let mem: Vec<&str> = st
                    .lines()
                    .filter(|l| l.starts_with("VmHWM") || l.starts_with("VmRSS"))
                    .collect();
                tracing::debug!(
                    "package database: {} files, {} packages; {}",
                    db.file_count(),
                    db.packages.len(),
                    mem.join(" ")
                );
            }
            r
        }) {
            Ok(db) => Ok(db),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }

    /// The package database, or an error if the host has none: for checks
    /// whose findings mean nothing without ownership.
    pub fn owned(&self) -> anyhow::Result<&PkgDb> {
        let db = self.pkgdb()?;
        if db.is_empty() {
            return Err(Unavailable("no package database (rpm or dpkg) on this host".into()).into());
        }
        Ok(db)
    }
}

/// Returned by a check that finds at run time that it cannot run here (a
/// filesystem not mounted, a feature absent). Reported as `unavailable`,
/// not as an error.
#[derive(Debug)]
pub struct Unavailable(pub String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unavailable {}

/// A check's baseline: values recorded the first time it ran, against which
/// later runs report changes. `fresh` is true on that first run (or after
/// `minsec-id baseline --reset`), when a check records without reporting.
#[derive(Debug, Default)]
pub struct Anchors {
    pub map: BTreeMap<String, String>,
    pub fresh: bool,
}

impl Anchors {
    /// Compare `value` with the recorded one for `key`: `None` when it
    /// matches, `Some(Some(old))` when it changed, `Some(None)` when the key
    /// is new. Only a fresh baseline records; afterwards a change stays
    /// reported until it is reverted or the baseline is reset after review.
    pub fn observe(&mut self, key: &str, value: &str) -> Option<Option<String>> {
        match self.map.get(key) {
            Some(v) if v == value => None,
            Some(v) => Some(Some(v.clone())),
            None if self.fresh => {
                self.map.insert(key.to_string(), value.to_string());
                None
            }
            None => Some(None),
        }
    }

    /// Record `value` unconditionally (a change for the better, or a value
    /// that is not itself a finding).
    pub fn set(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), value.to_string());
    }
}

pub trait Check: Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn cost(&self) -> Cost;
    fn default_enabled(&self) -> bool {
        true
    }
    /// Finding ids this check emits besides its own.
    fn emits(&self) -> &'static [&'static str] {
        &[]
    }
    /// Why this check cannot run on this host, if it cannot.
    fn unavailable(&self, host: &Host) -> Option<String>;
    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>>;
}

static ALL: &[&dyn Check] = &[
    &kernel_tainted::KernelTainted,
    &kmod::KmodUnowned,
    &kmod::KmodHidden,
    &bpf_progs::BpfProgs,
    &ftrace::Ftrace,
    &boot::BootPosture,
    &boot::BootKernel,
    &pkg_verify::PkgSignatures,
    &pkg_verify::PkgVerify,
    &ima::ImaVerify,
    &flatpak::FlatpakSignatures,
    &flatpak::FlatpakVerify,
    &snap::SnapMounts,
    &snap::SnapVerify,
    &ostree_host::OstreeDeployment,
    &ostree_host::OstreeVerify,
    &sysext::Sysext,
    &exe_unowned::ExeUnowned,
    &repos::RepoKeys,
    &repos::Repos,
    &proc_exe::ProcExe,
    &proc_hidden::ProcHidden,
    &proc_preload::ProcPreload,
    &service_shell::ServiceShell,
    &net::NetListeners,
    &net::NetRaw,
    &persistence::Persistence,
    &accounts::Accounts,
    &ssh_keys::SshKeys,
    &antiforensics::AntiForensics,
];

pub fn all() -> &'static [&'static dyn Check] {
    ALL
}

pub fn get(id: &str) -> Option<&'static dyn Check> {
    ALL.iter().copied().find(|c| c.id() == id)
}

/// The check that emits findings under `finding_id`.
pub fn producer(finding_id: &str) -> Option<&'static dyn Check> {
    ALL.iter()
        .copied()
        .find(|c| c.id() == finding_id || c.emits().contains(&finding_id))
}

/// Severity for a finding about a path: where it lives says how much it
/// matters.
pub(crate) fn path_is_code(p: &str) -> bool {
    const CODE: &[&str] = &[
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/usr/local/lib/",
        "/boot/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
    ];
    CODE.iter().any(|d| p.starts_with(d))
}

/// Paths that anyone (or any service) can write, where nothing should run from.
pub(crate) fn path_is_writable_area(p: &str) -> bool {
    const AREAS: &[&str] = &[
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/shm/",
        "/run/user/",
        "/dev/mqueue/",
    ];
    AREAS.iter().any(|d| p.starts_with(d)) || p.split('/').any(|c| c.starts_with('.') && c != "." && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_kebab_case() {
        let mut seen = std::collections::BTreeSet::new();
        for c in all() {
            for id in std::iter::once(c.id()).chain(c.emits().iter().copied()) {
                assert!(seen.insert(id), "duplicate check id {id}");
                assert!(
                    !id.is_empty()
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "check id {id} is not kebab-case"
                );
            }
        }
        assert_eq!(producer("kernel-tainted").unwrap().id(), "kernel-tainted");
    }

    #[test]
    fn anchors_record_then_compare() {
        let mut a = Anchors {
            fresh: true,
            ..Default::default()
        };
        assert_eq!(a.observe("k", "1"), None);
        a.fresh = false;
        assert_eq!(a.observe("k", "1"), None);
        assert_eq!(a.observe("k", "2"), Some(Some("1".into())));
        assert_eq!(a.map["k"], "1", "a change is reported, not absorbed");
        assert_eq!(a.observe("new", "x"), Some(None));
        assert_eq!(a.observe("new", "x"), Some(None), "a new key stays reported");
    }

    #[test]
    fn path_classes() {
        assert!(path_is_code("/usr/lib64/libc.so.6"));
        assert!(!path_is_code("/usr/share/doc/x"));
        assert!(path_is_writable_area("/tmp/x"));
        assert!(path_is_writable_area("/var/www/.cache/x"));
        assert!(!path_is_writable_area("/usr/bin/ls"));
    }
}
