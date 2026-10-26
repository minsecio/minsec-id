//! What the crowd says about this host's modified package files.
//! `minsec-id-sync` asks minsec.io whether other hosts report the same
//! content for the same package and path, and writes the answers to
//! `<state_dir>/sync/crowd.json`, keyed by finding fingerprint. The scanner,
//! which has no network stack, reads that file and annotates the findings:
//! content many independent hosts share was most likely changed by the
//! package's own scripts or a common local practice; content no other host
//! reports is this host's alone. Severity is left as the check set it — the
//! crowd informs triage, and a crowd that could lower severities would be
//! worth poisoning.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const VERSION: u32 = 1;

/// The checks whose findings are sent for a crowd hash check.
pub const CHECKS: &[&str] = &["pkg-modified"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    /// `shared` (a quorum of other hosts report the same content) or `rare`.
    pub verdict: String,
    pub same: u32,
    pub different: u32,
    pub expected_disputed: u32,
    /// When minsec.io answered (unix seconds).
    pub checked: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crowd {
    pub version: u32,
    /// By finding fingerprint.
    #[serde(default)]
    pub answers: BTreeMap<String, Answer>,
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join("sync").join("crowd.json")
}

impl Crowd {
    /// The answers on file; none when sync is not set up or the file is
    /// unreadable (the scan goes on without them).
    pub fn load(state_dir: &Path) -> Self {
        std::fs::read(path(state_dir))
            .ok()
            .and_then(|b| serde_json::from_slice::<Crowd>(&b).ok())
            .filter(|c| c.version == VERSION)
            .unwrap_or_default()
    }

    /// Add the crowd's answer, if there is one, to a finding's message and
    /// detail.
    pub fn annotate(&self, f: &mut Finding) {
        if !CHECKS.contains(&f.check.as_str()) {
            return;
        }
        let Some(a) = self
            .answers
            .get(&f.fingerprint)
            .filter(|a| matches!(a.verdict.as_str(), "shared" | "rare"))
        else {
            return;
        };
        let hosts = |n: u32| {
            if n == 1 {
                "1 other host".to_string()
            } else {
                format!("{n} other hosts")
            }
        };
        let mut says = match (a.verdict.as_str(), a.same) {
            ("shared", n) => format!("the same content is reported by {}", hosts(n)),
            (_, 0) => "no other host reports this content".to_string(),
            (_, n) => format!("the same content is reported by only {}", hosts(n)),
        };
        match a.expected_disputed {
            0 => {}
            1 => says.push_str("; 1 other host records a different package digest for it"),
            n => says.push_str(&format!("; {n} other hosts record a different package digest for it")),
        }
        f.message = format!("{} (crowd: {says})", f.message);
        if let Some(o) = f.detail.as_object_mut() {
            o.insert("crowd".into(), serde_json::to_value(a).unwrap_or_default());
        }
    }

    /// Write the file atomically (tmp + rename).
    pub fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        let p = path(state_dir);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        std::fs::rename(&tmp, &p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn finding() -> Finding {
        Finding::new("pkg-modified", Severity::High, "/usr/bin/ls", "beef")
            .message("/usr/bin/ls differs from coreutils-9.5-1.fc44.x86_64")
            .detail(serde_json::json!({ "kind": "content" }))
    }

    #[test]
    fn annotates_without_changing_severity_or_fingerprint() {
        let mut f = finding();
        let mut c = Crowd {
            version: VERSION,
            ..Default::default()
        };
        c.answers.insert(
            f.fingerprint.clone(),
            Answer {
                verdict: "shared".into(),
                same: 12,
                expected_disputed: 1,
                checked: 5,
                ..Default::default()
            },
        );
        let fp = f.fingerprint.clone();
        c.annotate(&mut f);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.fingerprint, fp);
        assert!(
            f.message.ends_with(
                "(crowd: the same content is reported by 12 other hosts; 1 other host records a different package digest for it)"
            ),
            "{}",
            f.message
        );
        assert_eq!(f.detail["crowd"]["same"], 12);

        let mut g = finding();
        c.answers.get_mut(&fp).unwrap().verdict = "rare".into();
        c.answers.get_mut(&fp).unwrap().same = 0;
        c.answers.get_mut(&fp).unwrap().expected_disputed = 0;
        c.annotate(&mut g);
        assert!(g.message.ends_with("(crowd: no other host reports this content)"));

        let mut other = Finding::new("exe-unowned", Severity::High, "/usr/bin/x", "");
        other.fingerprint = fp;
        c.annotate(&mut other);
        assert!(other.message.is_empty(), "only the hash-checked checks are annotated");
    }

    #[test]
    fn missing_or_foreign_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("minsec-id-crowd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(Crowd::load(&dir).answers.is_empty());
        std::fs::create_dir_all(dir.join("sync")).unwrap();
        std::fs::write(path(&dir), r#"{"version":99,"answers":{"x":{"verdict":"shared","same":1,"different":0,"expected_disputed":0,"checked":1}}}"#).unwrap();
        assert!(Crowd::load(&dir).answers.is_empty());
        let mut c = Crowd {
            version: VERSION,
            ..Default::default()
        };
        c.answers.insert("x".into(), Answer::default());
        c.save(&dir).unwrap();
        assert_eq!(Crowd::load(&dir), c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
