//! Reading processes from `/proc`. Everything here tolerates processes that
//! exit mid-read: a vanished pid is skipped, never an error.

use crate::host::Host;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    /// `readlink /proc/<pid>/exe`, including a ` (deleted)` suffix or a
    /// `/memfd:` name. `None` for kernel threads and unreadable processes.
    pub exe: Option<String>,
    /// Whether the process shares the host's mount namespace. Paths of a
    /// process in a container are relative to its own root.
    pub host_mnt_ns: bool,
}

impl Proc {
    pub fn is_kernel_thread(&self) -> bool {
        (self.exe.is_none() && self.ppid == 2) || self.pid == 2
    }

    /// The exe path without a ` (deleted)` suffix, and whether it was there.
    pub fn exe_path(&self) -> Option<(&str, bool)> {
        let e = self.exe.as_deref()?;
        Some(match e.strip_suffix(" (deleted)") {
            Some(p) => (p, true),
            None => (e, false),
        })
    }
}

pub fn pids(host: &Host) -> Vec<u32> {
    host.list_dir("/proc").iter().filter_map(|n| n.parse().ok()).collect()
}

pub fn read(host: &Host, pid: u32, init_mnt: Option<&str>) -> Option<Proc> {
    let status = std::fs::read_to_string(host.path(format!("/proc/{pid}/status"))).ok()?;
    let mut p = Proc {
        pid,
        ..Default::default()
    };
    for l in status.lines() {
        if let Some(v) = l.strip_prefix("Name:") {
            p.comm = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("PPid:") {
            p.ppid = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Uid:") {
            // Real, effective, saved, fs: report the effective uid.
            p.uid = v.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }
    p.exe = host.read_link(format!("/proc/{pid}/exe"));
    let ns = host.read_link(format!("/proc/{pid}/ns/mnt"));
    p.host_mnt_ns = match (ns.as_deref(), init_mnt) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    Some(p)
}

/// The mount namespace of pid 1, to tell host processes from containers.
pub fn init_mnt_ns(host: &Host) -> Option<String> {
    host.read_link("/proc/1/ns/mnt")
}

pub fn all(host: &Host) -> Vec<Proc> {
    let init = init_mnt_ns(host);
    pids(host)
        .into_iter()
        .filter_map(|pid| read(host, pid, init.as_deref()))
        .collect()
}

/// `cmdline` with NULs as spaces, truncated: for display only.
pub fn cmdline(host: &Host, pid: u32) -> String {
    let raw = host.read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let mut s: String = String::from_utf8_lossy(&raw).replace('\0', " ").trim().to_string();
    if s.len() > 256 {
        let mut cut = 256;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

/// Targets of a process's fd symlinks: `socket:[123]`, `/dev/pts/0`, …
pub fn fds(host: &Host, pid: u32) -> Vec<(u32, String)> {
    host.list_dir(format!("/proc/{pid}/fd"))
        .into_iter()
        .filter_map(|fd| {
            let n: u32 = fd.parse().ok()?;
            Some((n, host.read_link(format!("/proc/{pid}/fd/{fd}"))?))
        })
        .collect()
}

/// Socket inode → owning pids, across every process.
pub fn socket_owners(host: &Host, procs: &[Proc]) -> HashMap<u64, Vec<u32>> {
    let mut m: HashMap<u64, Vec<u32>> = HashMap::new();
    for p in procs {
        for (_, t) in fds(host, p.pid) {
            if let Some(ino) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Ok(ino) = ino.parse() {
                    m.entry(ino).or_default().push(p.pid);
                }
            }
        }
    }
    m
}

/// One executable mapping from `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub path: String,
    pub deleted: bool,
}

/// File-backed executable mappings, deduplicated.
pub fn exec_mappings(host: &Host, pid: u32) -> Vec<Mapping> {
    let s = std::fs::read_to_string(host.path(format!("/proc/{pid}/maps"))).unwrap_or_default();
    let mut out: Vec<Mapping> = Vec::new();
    for l in s.lines() {
        let mut f = l.splitn(6, ' ');
        let (_, perms) = (f.next(), f.next().unwrap_or(""));
        if !perms.contains('x') {
            continue;
        }
        let path = f.nth(3).unwrap_or("").trim_start();
        if !(path.starts_with('/')) {
            continue;
        }
        let (path, deleted) = match path.strip_suffix(" (deleted)") {
            Some(p) => (p, true),
            None => (path, false),
        };
        let m = Mapping {
            path: path.to_string(),
            deleted,
        };
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

/// One variable from a process's environment.
pub fn environ_var(host: &Host, pid: u32, name: &str) -> Option<String> {
    let raw = host.read(format!("/proc/{pid}/environ")).ok()?;
    let prefix = format!("{name}=");
    raw.split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_bytes()))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_self() {
        let host = Host::default();
        let me = std::process::id();
        let p = read(&host, me, init_mnt_ns(&host).as_deref()).unwrap();
        assert_eq!(p.pid, me);
        assert!(p.exe.is_some());
        assert!(!exec_mappings(&host, me).is_empty());
        assert!(fds(&host, me).iter().any(|(n, _)| *n == 0 || *n == 1 || *n == 2));
    }
}
