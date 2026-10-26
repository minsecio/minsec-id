//! `proc-hidden`: processes the kernel has that `/proc` does not list. The
//! kernel's task list is read with a BPF task iterator, which a rootkit
//! filtering `getdents` on `/proc` does not reach.

use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::procfs;
use std::collections::{HashMap, HashSet};

pub struct ProcHidden;

/// pid → comm of processes in the kernel's list but not in `/proc`.
fn unlisted(host: &Host) -> anyhow::Result<HashMap<u32, String>> {
    let tasks = minsec_id_bpf::tasks()?;
    let listed: HashSet<u32> = procfs::pids(host).into_iter().collect();
    Ok(tasks
        .into_iter()
        .filter(|t| !listed.contains(&t.pid))
        .map(|t| (t.pid, t.comm))
        .collect())
}

impl Check for ProcHidden {
    fn id(&self) -> &'static str {
        "proc-hidden"
    }

    fn description(&self) -> &'static str {
        "processes the kernel runs but /proc does not list"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (host.root() != std::path::Path::new("/")).then(|| "only the running kernel can be asked".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        if let Some(why) = minsec_id_bpf::unavailable() {
            return Err(Unavailable(why).into());
        }
        let first = unlisted(ctx.host)?;
        if first.is_empty() {
            return Ok(Vec::new());
        }
        // A process starting or exiting between the two reads is in one
        // list only: what persists is hidden.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let second = unlisted(ctx.host)?;
        Ok(first
            .into_iter()
            .filter(|(pid, _)| second.contains_key(pid))
            .map(|(pid, comm)| {
                let visible = ctx.host.exists(format!("/proc/{pid}/status"));
                Finding::new(self.id(), Severity::Critical, &comm, &pid.to_string())
                    .message(format!(
                        "process {comm} (pid {pid}) is running but hidden from the /proc listing{}",
                        if visible { " (its /proc entry still opens)" } else { "" }
                    ))
                    .detail(serde_json::json!({
                        "pid": pid,
                        "opens": visible,
                        "cmdline": procfs::cmdline(ctx.host, pid),
                    }))
            })
            .collect())
    }
}
