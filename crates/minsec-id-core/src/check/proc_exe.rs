//! `proc-exe`: processes running from where nothing legitimate runs.
//!
//! - `proc-exe-deleted`: the executable was deleted and nothing replaced it
//!   (an upgraded binary, replaced in place by its package, is not
//!   reported: that is a pending restart, not an intrusion).
//! - `proc-exe-memfd`: running from an anonymous memory file (fileless).
//! - `proc-exe-writable`: running from `/tmp`, `/dev/shm`, and similar, or
//!   from a hidden directory inside a system path.

use super::{path_is_writable_area, Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::procfs::{self, Proc};
use std::collections::BTreeMap;

pub struct ProcExe;

/// A writable area, or a hidden directory outside home directories (where
/// tools legitimately live in `~/.local`, `~/.vscode-server`, …).
pub(crate) fn suspicious_location(path: &str, host_ns: bool) -> bool {
    const STRICT: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/"];
    if STRICT.iter().any(|d| path.starts_with(d)) {
        return true;
    }
    if !host_ns {
        return false;
    }
    let homes = path.starts_with("/home/") || path.starts_with("/root/") || path.starts_with("/run/user/");
    !homes && path_is_writable_area(path)
}

/// Container runtimes re-exec themselves from a memfd (CVE-2019-5736).
pub(crate) fn benign_memfd(name: &str) -> bool {
    name.starts_with("runc_cloned") || name.starts_with("crun") || name.starts_with("youki")
}

#[derive(Default)]
struct Group {
    pids: Vec<u32>,
    first: Option<Proc>,
}

impl Check for ProcExe {
    fn id(&self) -> &'static str {
        "proc-exe"
    }

    fn description(&self) -> &'static str {
        "processes running from deleted files, memfds, or writable locations"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["proc-exe-deleted", "proc-exe-memfd", "proc-exe-writable"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/self")).then(|| "/proc is not mounted".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let me = std::process::id();
        let db = ctx.pkgdb()?;
        let mut groups: BTreeMap<(&'static str, String), Group> = BTreeMap::new();
        for p in procfs::all(host) {
            if p.pid == me || p.is_kernel_thread() {
                continue;
            }
            let Some((path, deleted)) = p.exe_path() else { continue };
            let id = if let Some(name) = path.strip_prefix("/memfd:") {
                if benign_memfd(name) {
                    continue;
                }
                "proc-exe-memfd"
            } else if suspicious_location(path, p.host_mnt_ns) {
                "proc-exe-writable"
            } else if deleted {
                // Replaced by a package upgrade: the path exists (in the
                // process's own root) and, on the host, is packaged.
                let replaced = host.exists(format!("/proc/{}/root{path}", p.pid))
                    && (!p.host_mnt_ns || db.is_empty() || db.owns(path));
                if replaced {
                    continue;
                }
                "proc-exe-deleted"
            } else {
                continue;
            };
            let g = groups.entry((id, p.exe.clone().unwrap_or_default())).or_default();
            g.pids.push(p.pid);
            g.first.get_or_insert(p);
        }
        Ok(groups
            .into_iter()
            .map(|((id, exe), g)| {
                let p = g.first.expect("a group has a process");
                let what = match id {
                    "proc-exe-memfd" => "from an anonymous memory file",
                    "proc-exe-writable" => "from a writable or hidden location",
                    _ => "from a deleted executable",
                };
                let severity = if id == "proc-exe-deleted" && !p.host_mnt_ns {
                    Severity::Medium
                } else {
                    Severity::High
                };
                Finding::new(id, severity, &exe, "")
                    .message(format!("{} (pid {}) is running {what}: {exe}", p.comm, p.pid))
                    .detail(serde_json::json!({
                        "pids": g.pids,
                        "comm": p.comm,
                        "uid": p.uid,
                        "ppid": p.ppid,
                        "cmdline": procfs::cmdline(host, p.pid),
                        "container": !p.host_mnt_ns,
                    }))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        assert!(suspicious_location("/tmp/x", true));
        assert!(suspicious_location("/dev/shm/.x/y", false));
        assert!(suspicious_location("/usr/lib/.hidden/x", true));
        assert!(
            !suspicious_location("/usr/lib/.hidden/x", false),
            "container paths are their own"
        );
        assert!(!suspicious_location("/home/u/.local/bin/x", true));
        assert!(!suspicious_location("/usr/bin/bash", true));
        assert!(benign_memfd("runc_cloned:/proc/self/exe"));
    }

    #[test]
    fn sees_no_problem_in_itself() {
        // The test binary runs from target/, which is neither suspicious nor deleted.
        let host = Host::default();
        let p = procfs::read(&host, std::process::id(), None).unwrap();
        let (path, deleted) = p.exe_path().unwrap();
        assert!(!deleted);
        assert!(!path.starts_with("/memfd:"));
    }
}
