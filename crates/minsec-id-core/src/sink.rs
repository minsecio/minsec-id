//! Where new findings go besides the findings log: journald (native protocol,
//! no libsystemd) and an optional `exec` hook.

use crate::finding::Finding;
use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
/// `MESSAGE_ID` of finding entries: `journalctl MESSAGE_ID=…` lists them all.
pub const MSGID_FINDING: &str = "4f5e0b3a9c7d4e21b8a6d2c1f0e9b7a5";
pub const MSGID_RESOLVED: &str = "4f5e0b3a9c7d4e21b8a6d2c1f0e9b7a6";
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Encode fields in the journal's native datagram format. Values containing
/// a newline use the length-prefixed binary form.
pub fn journal_encode(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (k, v) in fields {
        buf.extend_from_slice(k.as_bytes());
        if v.contains('\n') {
            buf.push(b'\n');
            buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        } else {
            buf.push(b'=');
        }
        buf.extend_from_slice(v.as_bytes());
        buf.push(b'\n');
    }
    buf
}

pub fn journal_send(socket: &Path, fields: &[(&str, &str)]) -> std::io::Result<()> {
    let sock = UnixDatagram::unbound()?;
    sock.send_to(&journal_encode(fields), socket)?;
    Ok(())
}

fn finding_fields<'a>(f: &'a Finding, msg: &'a str, prio: &'a str, msgid: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("MESSAGE", msg),
        ("PRIORITY", prio),
        ("SYSLOG_IDENTIFIER", "minsec-id"),
        ("MESSAGE_ID", msgid),
        ("MINSEC_CHECK", &f.check),
        ("MINSEC_SEVERITY", f.severity.as_str()),
        ("MINSEC_SUBJECT", &f.subject),
        ("MINSEC_FINGERPRINT", &f.fingerprint),
    ]
}

pub fn journal_finding(socket: &Path, f: &Finding) {
    let msg = format!("[{}] {}: {}", f.severity, f.check, f.message);
    let prio = f.severity.syslog_priority().to_string();
    if let Err(e) = journal_send(socket, &finding_fields(f, &msg, &prio, MSGID_FINDING)) {
        tracing::debug!("journal: {e}");
    }
}

pub fn journal_resolved(socket: &Path, f: &Finding) {
    let msg = format!("resolved: {}: {}", f.check, f.subject);
    if let Err(e) = journal_send(socket, &finding_fields(f, &msg, "6", MSGID_RESOLVED)) {
        tracing::debug!("journal: {e}");
    }
}

/// Run the notify hook for one finding: JSON on stdin, key fields in the
/// environment. Killed after 30 s so a stuck hook cannot stall the scan.
pub fn exec_hook(cmd: &str, f: &Finding) -> anyhow::Result<()> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env("MINSEC_CHECK", &f.check)
        .env("MINSEC_SEVERITY", f.severity.as_str())
        .env("MINSEC_SUBJECT", &f.subject)
        .env("MINSEC_FINGERPRINT", &f.fingerprint)
        .env("MINSEC_MESSAGE", &f.message)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        // A hook that ignores stdin closes the pipe early; that is fine.
        let _ = stdin.write_all(&serde_json::to_vec(f)?);
    }
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                anyhow::bail!("notify hook exited with {status}");
            }
            return Ok(());
        }
        if start.elapsed() > HOOK_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("notify hook timed out after {}s", HOOK_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn encodes_plain_and_binary_fields() {
        let b = journal_encode(&[("A", "x"), ("B", "1\n2")]);
        let mut want = b"A=x\nB\n".to_vec();
        want.extend_from_slice(&3u64.to_le_bytes());
        want.extend_from_slice(b"1\n2\n");
        assert_eq!(b, want);
    }

    #[test]
    fn sends_to_a_datagram_socket() {
        let dir = std::env::temp_dir().join(format!("minsec-id-journal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("socket");
        let _ = std::fs::remove_file(&p);
        let server = UnixDatagram::bind(&p).unwrap();
        let f = Finding::new("kernel-tainted", Severity::High, "E", "").message("unsigned");
        journal_finding(&p, &f);
        let mut buf = [0u8; 1024];
        let n = server.recv(&mut buf).unwrap();
        let s = String::from_utf8_lossy(&buf[..n]);
        assert!(s.contains("MINSEC_CHECK=kernel-tainted\n"), "{s}");
        assert!(s.contains("PRIORITY=3\n"), "{s}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hook_gets_env_and_stdin() {
        let dir = std::env::temp_dir().join(format!("minsec-id-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out");
        let f = Finding::new("kernel-tainted", Severity::High, "E", "");
        exec_hook(&format!("{{ echo $MINSEC_CHECK; cat; }} > {}", out.display()), &f).unwrap();
        let got = std::fs::read_to_string(&out).unwrap();
        assert!(got.starts_with("kernel-tainted\n{"), "{got}");
        assert!(exec_hook("exit 3", &f).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
