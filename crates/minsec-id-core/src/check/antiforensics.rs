//! `anti-forensics`: covering tracks.
//!
//! - `history-devnull`: a shell or tool history file symlinked to
//!   `/dev/null`.
//! - `log-truncated`: a login record or auth log that shrank without being
//!   rotated (same inode, smaller size).

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::users;
use std::os::unix::fs::MetadataExt;

pub struct AntiForensics;

const HISTORIES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".ash_history",
    ".history",
    ".mysql_history",
    ".psql_history",
    ".python_history",
    ".sqlite_history",
];

const LOGS: &[&str] = &[
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/lib/wtmpdb/wtmp.db",
    "/var/log/secure",
    "/var/log/auth.log",
    "/var/log/audit/audit.log",
];

impl Check for AntiForensics {
    fn id(&self) -> &'static str {
        "anti-forensics"
    }

    fn description(&self) -> &'static str {
        "history files sent to /dev/null and login or auth logs truncated in place"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["history-devnull", "log-truncated"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, _: &Host) -> Option<String> {
        None
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let mut out = Vec::new();
        for u in users::with_homes(host) {
            for h in HISTORIES {
                let p = format!("{}/{h}", u.home.trim_end_matches('/'));
                if host.read_link(&p).as_deref() == Some("/dev/null") {
                    out.push(
                        Finding::new("history-devnull", Severity::Medium, &p, "").message(format!(
                            "{p} is a symlink to /dev/null: {}'s history is discarded",
                            u.name
                        )),
                    );
                }
            }
        }
        for log in LOGS {
            let Ok(md) = std::fs::metadata(host.path(log)) else {
                continue;
            };
            let now = format!("{}:{}", md.ino(), md.size());
            if let Some((ino, size)) = anchors.map.get(*log).and_then(|v| {
                let (i, s) = v.split_once(':')?;
                Some((i.parse::<u64>().ok()?, s.parse::<u64>().ok()?))
            }) {
                if ino == md.ino() && md.size() < size {
                    out.push(
                        Finding::new("log-truncated", Severity::High, *log, &now)
                            .message(format!(
                                "{log} shrank from {size} to {} bytes without rotation",
                                md.size()
                            ))
                            .detail(serde_json::json!({ "was": size, "now": md.size(), "inode": ino })),
                    );
                }
            }
            // Logs grow and rotate: always track the latest size.
            anchors.set(log, &now);
        }
        Ok(out)
    }
}
