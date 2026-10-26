//! Findings: what a check reports. A finding is identified by a stable
//! fingerprint so repeated scans report it once, and by `check:subject` so an
//! operator can accept it durably.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// syslog priority for journald's `PRIORITY=` field.
    pub fn syslog_priority(&self) -> u8 {
        match self {
            Severity::Info => 6,
            Severity::Low => 5,
            Severity::Medium => 4,
            Severity::High => 3,
            Severity::Critical => 2,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return Err(format!("unknown severity `{s}` (info|low|medium|high|critical)")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable check id, e.g. `kernel-tainted`.
    pub check: String,
    pub severity: Severity,
    /// What the finding is about: a path, module name, taint flag, …
    pub subject: String,
    /// One-line human description.
    pub message: String,
    /// Check-specific structured detail.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
    /// Hash of check, subject, and the check's salient detail.
    pub fingerprint: String,
}

impl Finding {
    /// `salient` is whatever, besides check and subject, makes this a
    /// different finding when it changes (a boot id, a digest, …).
    pub fn new(check: &str, severity: Severity, subject: impl Into<String>, salient: &str) -> Self {
        let subject = subject.into();
        let fingerprint = fingerprint(&[check, &subject, salient]);
        Self {
            check: check.to_string(),
            severity,
            subject,
            message: String::new(),
            detail: serde_json::Value::Null,
            fingerprint,
        }
    }

    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.message = m.into();
        self
    }

    pub fn detail(mut self, d: serde_json::Value) -> Self {
        self.detail = d;
        self
    }

    /// The durable accept key.
    pub fn key(&self) -> String {
        format!("{}:{}", self.check, self.subject)
    }
}

/// FNV-1a 64 over NUL-separated parts, as 16 hex digits. Stable across
/// builds and versions (unlike `DefaultHasher`); dedup, not security.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            // A NUL separator byte: the xor with 0 vanishes, the multiply stays.
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in p.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_separated() {
        assert_eq!(fingerprint(&["a"]), "af63dc4c8601ec8c");
        assert_ne!(fingerprint(&["ab", "c"]), fingerprint(&["a", "bc"]));
        let f = Finding::new("kernel-tainted", Severity::High, "E", "boot1");
        assert_eq!(f.key(), "kernel-tainted:E");
        assert_ne!(
            f.fingerprint,
            Finding::new("kernel-tainted", Severity::High, "E", "boot2").fingerprint
        );
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::Info);
        assert_eq!("high".parse::<Severity>().unwrap(), Severity::High);
        assert!("nope".parse::<Severity>().is_err());
    }
}
