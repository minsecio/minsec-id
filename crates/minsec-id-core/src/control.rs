//! The daemon's control socket: newline-delimited JSON, one request and one
//! response per line. The shape and the client are minsec's
//! (crates/minsec-core/src/control.rs), with this daemon's requests; they
//! are to move to minsec-common.

use crate::monitor::Stats;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    Status,
    /// Re-read the configuration (accept rules, severities, enabled rules).
    Reload,
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeStatus {
    pub probe: String,
    pub attached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    pub uptime: u64,
    pub probes: Vec<ProbeStatus>,
    #[serde(flatten)]
    pub stats: Stats,
    /// Ring buffer records lost because userspace fell behind.
    pub dropped: u64,
    /// Package-owned executables and modules known.
    pub owned: usize,
    /// Resident memory, from /proc/self/status.
    pub rss_kb: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl Response {
    pub fn message(m: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: Some(m.into()),
            ..Default::default()
        }
    }

    pub fn err(e: impl ToString) -> Self {
        Self {
            ok: false,
            error: Some(e.to_string()),
            ..Default::default()
        }
    }
}

/// How long the CLI waits for the daemon before giving up.
pub const TIMEOUT: Duration = Duration::from_secs(5);

pub fn call(socket: &Path, req: &Request) -> anyhow::Result<Response> {
    call_with_timeout(socket, req, TIMEOUT)
}

pub fn call_with_timeout(socket: &Path, req: &Request, timeout: Duration) -> anyhow::Result<Response> {
    use std::io::{BufRead, BufReader, Write};
    let mut s = std::os::unix::net::UnixStream::connect(socket)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    s.write_all(line.as_bytes())?;
    let mut r = BufReader::new(s);
    let mut resp = String::new();
    r.read_line(&mut resp)?;
    if resp.is_empty() {
        anyhow::bail!("empty response from daemon");
    }
    Ok(serde_json::from_str(&resp)?)
}

/// Resident set size of this process, in KiB.
pub fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r: Request = serde_json::from_str(r#"{"cmd":"reload"}"#).unwrap();
        assert_eq!(r, Request::Reload);
        assert_eq!(serde_json::to_string(&Request::Status).unwrap(), r#"{"cmd":"status"}"#);
        let s = serde_json::to_string(&Response::err("nope")).unwrap();
        assert_eq!(s, r#"{"ok":false,"error":"nope"}"#);
        assert!(rss_kb() > 0);
    }

    #[test]
    fn call_times_out_on_silent_daemon() {
        let dir = std::env::temp_dir().join(format!("minsec-id-control-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let silent = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
        let err = call_with_timeout(&path, &Request::Ping, Duration::from_millis(100)).unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert!(
            matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            "{io}"
        );
        drop(silent.join().unwrap().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }
}
