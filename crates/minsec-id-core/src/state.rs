//! `state.json`: the open findings and the last scan. Small by design — the
//! package database, not this file, is the baseline for file contents.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub version: u32,
    #[serde(default)]
    pub last_scan: Option<LastScan>,
    /// Open findings by fingerprint, including accepted ones.
    #[serde(default)]
    pub open: BTreeMap<String, OpenFinding>,
    /// Per-check baselines (see `check::Anchors`).
    #[serde(default)]
    pub anchors: BTreeMap<String, BTreeMap<String, String>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            last_scan: None,
            open: BTreeMap::new(),
            anchors: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenFinding {
    #[serde(flatten)]
    pub finding: Finding,
    pub first_seen: u64,
    pub last_seen: u64,
    /// The accept rule covering it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastScan {
    pub ts: u64,
    pub mode: String,
    pub duration_ms: u64,
    pub checks: Vec<String>,
    /// Checks that failed to run, with the error.
    #[serde(default)]
    pub errors: BTreeMap<String, String>,
}

impl State {
    /// Load, treating a missing file as empty. A corrupt file is an error:
    /// silently starting over would re-report everything.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(b) => {
                let s: State = serde_json::from_slice(&b).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                if s.version != STATE_VERSION {
                    anyhow::bail!("{}: unsupported state version {}", path.display(), s.version);
                }
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => anyhow::bail!("{}: {e}", path.display()),
        }
    }

    /// Write atomically (temp file + rename), readable by root only.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
        f.write_all(&serde_json::to_vec_pretty(self)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Open findings that are not accepted.
    pub fn unaccepted(&self) -> impl Iterator<Item = &OpenFinding> {
        self.open.values().filter(|o| o.accepted.is_none())
    }
}

/// An exclusive lock on the state directory, held for a scan so a quick scan
/// and a full scan never interleave their state updates.
pub struct Lock(#[allow(dead_code)] std::fs::File);

impl Lock {
    pub fn acquire(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
        let p = dir.join("lock");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&p)
            .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
        // SAFETY: flock on a valid, owned descriptor.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            anyhow::bail!("{}: {}", p.display(), std::io::Error::last_os_error());
        }
        Ok(Self(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("minsec-id-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state.json");
        assert_eq!(State::load(&p).unwrap(), State::default());
        let mut s = State::default();
        let f = Finding::new("kernel-tainted", Severity::Low, "P", "");
        s.open.insert(
            f.fingerprint.clone(),
            OpenFinding {
                finding: f,
                first_seen: 1,
                last_seen: 2,
                accepted: Some("kernel-tainted:P".into()),
            },
        );
        s.save(&p).unwrap();
        assert_eq!(State::load(&p).unwrap(), s);
        assert_eq!(s.unaccepted().count(), 0);
        std::fs::write(&p, "{").unwrap();
        assert!(State::load(&p).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
