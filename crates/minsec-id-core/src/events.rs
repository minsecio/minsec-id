//! Append-only JSONL findings log, consumed by `minsec-id events` and, later,
//! by `minsec-id-sync`. The writer is minsec's (crates/minsec-core/src/events.rs)
//! with this tool's event type; it is to move to minsec-common.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const ROTATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
    /// A finding seen for the first time (or changed: new fingerprint).
    Finding {
        ts: u64,
        #[serde(flatten)]
        finding: Finding,
    },
    /// A finding that a later run of its check no longer reports.
    Resolved {
        ts: u64,
        check: String,
        subject: String,
        fingerprint: String,
    },
    /// One per completed scan.
    Scan {
        ts: u64,
        mode: String,
        checks: usize,
        open: usize,
        new: usize,
        resolved: usize,
        errors: usize,
        duration_ms: u64,
    },
}

pub struct EventLog {
    path: PathBuf,
    file: Option<File>,
    written: u64,
}

impl EventLog {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            written,
        })
    }

    /// An event log that discards everything.
    pub fn sink() -> Self {
        Self {
            path: PathBuf::new(),
            file: None,
            written: 0,
        }
    }

    pub fn append(&mut self, ev: &Event) {
        self.reopen_if_rotated();
        let Some(f) = self.file.as_mut() else { return };
        let mut line = match serde_json::to_string(ev) {
            Ok(s) => s,
            Err(_) => return,
        };
        line.push('\n');
        if let Err(e) = f.write_all(line.as_bytes()) {
            tracing::warn!(path = %self.path.display(), "cannot write event: {e}");
            return;
        }
        self.written += line.len() as u64;
        if self.written >= ROTATE_BYTES {
            self.rotate();
        }
    }

    /// The scanner and the daemon both append; when one rotates the log,
    /// the other's descriptor still points at the rotated file.
    fn reopen_if_rotated(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let Some(f) = self.file.as_ref() else { return };
        let held = f.metadata().map(|m| (m.dev(), m.ino())).ok();
        let now = std::fs::metadata(&self.path).map(|m| (m.dev(), m.ino())).ok();
        if held != now {
            if let Ok(f) = OpenOptions::new().create(true).append(true).open(&self.path) {
                self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
                self.file = Some(f);
            }
        }
    }

    fn rotate(&mut self) {
        let old = self.path.with_extension("jsonl.1");
        if std::fs::rename(&self.path, &old).is_ok() {
            if let Ok(f) = OpenOptions::new().create(true).append(true).open(&self.path) {
                self.file = Some(f);
                self.written = 0;
            }
        }
    }

    /// Read all events (rotated file first), skipping malformed lines.
    pub fn read_all(path: &Path) -> Vec<Event> {
        let mut out = Vec::new();
        for p in [path.with_extension("jsonl.1"), path.to_path_buf()] {
            if let Ok(f) = File::open(&p) {
                for l in BufReader::new(f).lines().map_while(Result::ok) {
                    if let Ok(ev) = serde_json::from_str::<Event>(&l) {
                        out.push(ev);
                    }
                }
            }
        }
        out
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn finding_event_is_flat_json() {
        let f = Finding::new("kernel-tainted", Severity::High, "E", "b").message("m");
        let ev = Event::Finding { ts: 1, finding: f };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.starts_with(r#"{"kind":"finding","ts":1,"check":"kernel-tainted""#),
            "{s}"
        );
        assert_eq!(serde_json::from_str::<Event>(&s).unwrap(), ev);
    }
}
