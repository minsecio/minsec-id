//! `proc-service-shell`: a shell or interpreter running as a service account
//! with a TCP or UDP socket for stdin or stdout: the shape of a reverse
//! shell or a webshell's interactive session. Login shells have a terminal,
//! CGI scripts have pipes, and service scripts log to journald over a unix
//! socket; none has an internet socket on stdio.

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::{procfs, users};
use std::collections::HashMap;

pub struct ServiceShell;

const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox", "perl", "php", "ruby", "lua", "node",
    "nc", "ncat", "netcat", "socat", "telnet", "openssl",
];

pub(crate) fn is_shell(exe: &str) -> bool {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    SHELLS.contains(&base) || base.starts_with("python") || base.starts_with("php") || base.starts_with("perl5")
}

impl Check for ServiceShell {
    fn id(&self) -> &'static str {
        "proc-service-shell"
    }

    fn description(&self) -> &'static str {
        "shells and interpreters run by service accounts with a socket on stdin/stdout"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/self")).then(|| "/proc is not mounted".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let accounts: HashMap<u32, users::User> = users::passwd(host).into_iter().map(|u| (u.uid, u)).collect();
        let procs = procfs::all(host);
        let inet = super::net::inet_inodes(host);
        let comm_of: HashMap<u32, String> = procs.iter().map(|p| (p.pid, p.comm.clone())).collect();
        let mut out = Vec::new();
        for p in &procs {
            if !p.host_mnt_ns || p.uid == 0 {
                continue;
            }
            let Some((exe, _)) = p.exe_path() else { continue };
            if !is_shell(exe) {
                continue;
            }
            // A service account: a system uid, or any account without a login shell.
            let service = match accounts.get(&p.uid) {
                Some(u) => u.uid < 1000 || !u.can_login(),
                None => p.uid < 1000,
            };
            if !service {
                continue;
            }
            let fds = procfs::fds(host, p.pid);
            let socket_stdio = fds.iter().any(|(n, t)| {
                *n <= 1
                    && t.strip_prefix("socket:[")
                        .and_then(|x| x.strip_suffix(']'))
                        .and_then(|x| x.parse::<u64>().ok())
                        .is_some_and(|ino| inet.contains(&ino))
            });
            if !socket_stdio {
                continue;
            }
            let user = accounts
                .get(&p.uid)
                .map(|u| u.name.clone())
                .unwrap_or_else(|| p.uid.to_string());
            let parent = comm_of.get(&p.ppid).cloned().unwrap_or_default();
            out.push(
                Finding::new(self.id(), Severity::High, format!("{user}:{exe}"), &p.pid.to_string())
                    .message(format!(
                        "{exe} runs as service account {user} (pid {}, parent {parent}) with a network socket on stdio",
                        p.pid
                    ))
                    .detail(serde_json::json!({
                        "pid": p.pid,
                        "ppid": p.ppid,
                        "parent": parent,
                        "uid": p.uid,
                        "cmdline": procfs::cmdline(host, p.pid),
                    })),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shells() {
        assert!(super::is_shell("/usr/bin/bash"));
        assert!(super::is_shell("/usr/bin/python3.12"));
        assert!(!super::is_shell("/usr/sbin/nginx"));
    }
}
