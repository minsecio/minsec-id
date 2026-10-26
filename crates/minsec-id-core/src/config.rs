//! Configuration: `/etc/minsec-id/minsec-id.toml` plus `conf.d/*.toml` drop-ins.
//! Loading and merging follow minsec (crates/minsec-core/src/config.rs); the
//! generic part is to move to minsec-common.

use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/minsec-id";
pub const DEFAULT_SOCKET: &str = "/run/minsec-id/minsec-id.sock";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/minsec-id";
pub const MAIN_FILE: &str = "minsec-id.toml";
pub const ACCEPT_FILE: &str = "accept.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// Send findings to journald with `MINSEC_*` fields.
    #[serde(default = "d_true")]
    pub journal: bool,
    /// Command run (via `sh -c`) once per new finding; the finding is JSON on
    /// stdin and `MINSEC_CHECK`, `MINSEC_SEVERITY`, `MINSEC_SUBJECT`,
    /// `MINSEC_FINGERPRINT` are in the environment.
    #[serde(default)]
    pub exec: Option<String>,
    /// Only notify (journal and exec) at or above this severity. Everything is
    /// still recorded in the findings log.
    #[serde(default = "d_min_severity")]
    pub min_severity: Severity,
}

fn d_true() -> bool {
    true
}
fn d_min_severity() -> Severity {
    Severity::Low
}

impl Default for Output {
    fn default() -> Self {
        toml::from_str("").expect("defaults deserialize from empty table")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    #[serde(default = "d_socket")]
    pub socket: PathBuf,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
}

fn d_socket() -> PathBuf {
    DEFAULT_SOCKET.into()
}
fn d_state_dir() -> PathBuf {
    DEFAULT_STATE_DIR.into()
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            socket: d_socket(),
            state_dir: d_state_dir(),
        }
    }
}

/// Per-check overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckConfig {
    /// Unset means the check's built-in default.
    pub enabled: Option<bool>,
    /// Replace the severity of every finding from this check.
    pub severity: Option<Severity>,
}

/// An accepted finding. Keyed `check:subject`; a subject ending in `*`
/// matches by prefix (`kmod-unowned:nvidia*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub output: Output,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default)]
    pub checks: BTreeMap<String, CheckConfig>,
    #[serde(default)]
    pub accept: BTreeMap<String, Accept>,
    #[serde(skip)]
    pub config_dir: PathBuf,
}

impl Config {
    /// Load `<dir>/minsec-id.toml` and merge `<dir>/conf.d/*.toml` over it.
    /// A missing main file yields defaults.
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let main = dir.join(MAIN_FILE);
        let mut merged: toml::Table = match std::fs::read_to_string(&main) {
            Ok(s) => toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", main.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
            Err(e) => anyhow::bail!("{}: {e}", main.display()),
        };
        for p in dropins(dir) {
            let s = std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
            let t: toml::Table = toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
            merge(&mut merged, t);
        }
        let mut cfg: Config = toml::Value::Table(merged)
            .try_into()
            .map_err(|e| anyhow::anyhow!("config: {e}"))?;
        cfg.config_dir = dir.to_path_buf();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = toml::from_str(s)?;
        cfg.config_dir = DEFAULT_CONFIG_DIR.into();
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        for id in self.checks.keys() {
            if crate::check::get(id).is_none() {
                anyhow::bail!("checks.{id}: unknown check (see `minsec-id checks`)");
            }
        }
        for key in self.accept.keys() {
            let Some((check, subject)) = key.split_once(':') else {
                anyhow::bail!("accept.\"{key}\": expected \"<check>:<subject>\"");
            };
            if crate::check::get(check).is_none() {
                anyhow::bail!("accept.\"{key}\": unknown check `{check}`");
            }
            if subject.is_empty() {
                anyhow::bail!("accept.\"{key}\": empty subject (use `*` to accept the whole check)");
            }
        }
        Ok(())
    }

    pub fn check_enabled(&self, id: &str, default: bool) -> bool {
        self.checks.get(id).and_then(|c| c.enabled).unwrap_or(default)
    }

    pub fn severity_override(&self, id: &str) -> Option<Severity> {
        self.checks.get(id).and_then(|c| c.severity)
    }

    /// The accept rule that covers this finding, if any.
    pub fn accepted(&self, f: &Finding) -> Option<(&str, &Accept)> {
        let key = f.key();
        if let Some((k, a)) = self.accept.get_key_value(&key) {
            return Some((k.as_str(), a));
        }
        self.accept.iter().find_map(|(k, a)| {
            let (check, subject) = k.split_once(':')?;
            let prefix = subject.strip_suffix('*')?;
            (check == f.check && f.subject.starts_with(prefix)).then_some((k.as_str(), a))
        })
    }

    pub fn events_file(&self) -> PathBuf {
        self.paths.state_dir.join("findings.jsonl")
    }

    pub fn state_file(&self) -> PathBuf {
        self.paths.state_dir.join("state.json")
    }
}

/// `<dir>/conf.d/*.toml`, in the order they are applied.
pub fn dropins(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir.join("conf.d"))
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries
}

/// Deep-merge TOML tables: `over` wins; nested tables merge recursively.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// Edit one drop-in file as a TOML table: read it (absent is empty), let
/// `f` change it, write it back. Used by `enable`, `disable`, and `accept`.
pub fn edit_dropin(
    dir: &Path,
    file: &str,
    f: impl FnOnce(&mut toml::Table) -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let confd = dir.join("conf.d");
    std::fs::create_dir_all(&confd)?;
    let path = confd.join(file);
    let mut table: toml::Table = match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => anyhow::bail!("{}: {e}", path.display()),
    };
    f(&mut table)?;
    std::fs::write(&path, toml::to_string(&table)?)?;
    Ok(path)
}

/// `table[name]` as a mutable sub-table, created if absent.
pub fn subtable<'a>(table: &'a mut toml::Table, name: &str) -> anyhow::Result<&'a mut toml::Table> {
    table
        .entry(name)
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`{name}` is not a table"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let cfg = Config::parse(
            r#"
[output]
exec = "logger"
[checks.kernel-tainted]
severity = "critical"
"#,
        )
        .unwrap();
        assert!(cfg.output.journal);
        assert_eq!(cfg.output.min_severity, Severity::Low);
        assert_eq!(cfg.severity_override("kernel-tainted"), Some(Severity::Critical));
        assert!(cfg.check_enabled("kernel-tainted", true));
        assert_eq!(cfg.paths.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
    }

    #[test]
    fn rejects_bad() {
        assert!(Config::parse("[nope]\nx = 1").is_err());
        assert!(Config::parse("[checks.no-such-check]\nenabled = true").is_err());
        assert!(Config::parse("[accept.\"kernel-tainted\"]").is_err());
        assert!(Config::parse("[accept.\"kernel-tainted:\"]").is_err());
        assert!(Config::parse("[output]\nmin_severity = \"loud\"").is_err());
    }

    #[test]
    fn accept_exact_and_prefix() {
        let cfg = Config::parse("[accept.\"kernel-tainted:P\"]\nreason = \"nvidia\"\n[accept.\"kernel-tainted:O*\"]\n")
            .unwrap();
        let f = |s: &str| Finding::new("kernel-tainted", Severity::Low, s, "");
        assert_eq!(cfg.accepted(&f("P")).unwrap().1.reason.as_deref(), Some("nvidia"));
        assert_eq!(cfg.accepted(&f("O")).unwrap().0, "kernel-tainted:O*");
        assert!(cfg.accepted(&f("E")).is_none());
    }

    #[test]
    fn merge_tables() {
        let mut a: toml::Table = toml::from_str("[output]\njournal=false\nexec='a'").unwrap();
        let b: toml::Table = toml::from_str("[output]\nexec='b'\n[checks.kernel-tainted]\nenabled=false").unwrap();
        merge(&mut a, b);
        let c: Config = toml::Value::Table(a).try_into().unwrap();
        assert!(!c.output.journal);
        assert_eq!(c.output.exec.as_deref(), Some("b"));
        assert!(!c.check_enabled("kernel-tainted", true));
    }
}
