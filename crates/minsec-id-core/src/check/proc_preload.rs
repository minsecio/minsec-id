//! `proc-preload`: code injected into processes through the loader.
//!
//! - `/etc/ld.so.preload` exists with entries: every dynamically linked
//!   program loads them (the classic userland rootkit).
//! - A process has `LD_PRELOAD` in its environment.
//! - A process maps executable code from a writable location, a memfd, or a
//!   deleted file that nothing replaced.

use super::proc_exe::suspicious_location;
use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::procfs;
use std::collections::BTreeMap;

pub struct ProcPreload;

/// Preloads applications set for themselves (Firefox's sandbox).
const BENIGN_PRELOADS: &[&str] = &["libmozsandbox.so"];
const MAX_LISTED: usize = 20;

/// (pid, comm) of the processes a finding is about.
type Procs = Vec<(u32, String)>;

impl Check for ProcPreload {
    fn id(&self) -> &'static str {
        "proc-preload"
    }

    fn description(&self) -> &'static str {
        "ld.so.preload, LD_PRELOAD, and executable mappings from writable or deleted files"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/self")).then(|| "/proc is not mounted".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.pkgdb()?;
        let mut out = Vec::new();

        if let Some(s) = host.read_opt("/etc/ld.so.preload") {
            let libs: Vec<&str> = s.split_whitespace().filter(|l| !l.starts_with('#')).collect();
            if !libs.is_empty() {
                out.push(
                    Finding::new(self.id(), Severity::High, "/etc/ld.so.preload", &libs.join(" "))
                        .message(format!(
                            "/etc/ld.so.preload loads {} into every program",
                            libs.join(", ")
                        ))
                        .detail(serde_json::json!({ "libraries": libs })),
                );
            }
        }

        let me = std::process::id();
        let mut env: BTreeMap<String, Procs> = BTreeMap::new();
        let mut maps: BTreeMap<String, (Procs, &'static str)> = BTreeMap::new();
        for p in procfs::all(host) {
            if p.pid == me || p.is_kernel_thread() {
                continue;
            }
            if p.host_mnt_ns {
                if let Some(v) = procfs::environ_var(host, p.pid, "LD_PRELOAD")
                    .filter(|v| !v.trim().is_empty() && !BENIGN_PRELOADS.contains(&v.trim()))
                {
                    env.entry(v).or_default().push((p.pid, p.comm.clone()));
                }
            }
            for m in procfs::exec_mappings(host, p.pid) {
                let why = if m.path.starts_with("/memfd:") {
                    "an anonymous memory file"
                } else if suspicious_location(&m.path, p.host_mnt_ns) {
                    "a writable or hidden location"
                } else if m.deleted {
                    let replaced = host.exists(format!("/proc/{}/root{}", p.pid, m.path))
                        && (!p.host_mnt_ns || db.is_empty() || db.owns(&m.path));
                    if replaced {
                        continue;
                    }
                    "a deleted file"
                } else {
                    continue;
                };
                maps.entry(m.path)
                    .or_insert((Vec::new(), why))
                    .0
                    .push((p.pid, p.comm.clone()));
            }
        }
        for (v, procs) in env {
            out.push(
                Finding::new(self.id(), Severity::Medium, format!("LD_PRELOAD={v}"), "")
                    .message(format!(
                        "{} process(es) run with LD_PRELOAD={v} (e.g. {})",
                        procs.len(),
                        procs[0].1
                    ))
                    .detail(
                        serde_json::json!({ "count": procs.len(), "processes": &procs[..procs.len().min(MAX_LISTED)] }),
                    ),
            );
        }
        for (path, (procs, why)) in maps {
            out.push(
                Finding::new(self.id(), Severity::High, &path, "")
                    .message(format!(
                        "{} process(es) execute code mapped from {why}: {path} (e.g. {})",
                        procs.len(),
                        procs[0].1
                    ))
                    .detail(
                        serde_json::json!({ "count": procs.len(), "processes": &procs[..procs.len().min(MAX_LISTED)] }),
                    ),
            );
        }
        Ok(out)
    }
}
