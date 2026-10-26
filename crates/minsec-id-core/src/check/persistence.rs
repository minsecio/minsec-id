//! `persistence`: the places code is started from without anyone asking —
//! systemd units and generators, cron and at, shell startup files, udev,
//! modprobe, PAM, sudoers, the dynamic loader's configuration, package
//! manager hooks, initramfs hooks, and per-user equivalents.
//!
//! Files a package installed and that are unmodified are left to
//! `pkg-verify`. Everything else (unowned files, and edited configuration)
//! is recorded by content on the first run; later runs report new files
//! (`persist-new`) and changed ones (`persist-changed`). An unowned PAM
//! module is reported even on the first run: nothing legitimate puts one
//! there by hand.

use super::{Anchors, Check, Cost, Ctx};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::{Canon, Host};
use crate::users;
use std::os::unix::fs::MetadataExt;

pub struct Persistence;

/// Files larger than this are tracked by size and mtime, not content.
const MAX_HASH: u64 = 1 << 20;

/// (path, depth: 0 = the file itself, 1 = directory entries, n = recursive, severity)
pub(crate) const SYSTEM: &[(&str, u32, Severity)] = &[
    ("/etc/systemd/system", 3, Severity::Medium),
    ("/etc/systemd/user", 3, Severity::Medium),
    ("/usr/lib/systemd/system", 2, Severity::Medium),
    ("/usr/lib/systemd/user", 2, Severity::Medium),
    ("/usr/local/lib/systemd/system", 2, Severity::Medium),
    ("/etc/systemd/system-generators", 1, Severity::High),
    ("/usr/lib/systemd/system-generators", 1, Severity::High),
    ("/usr/local/lib/systemd/system-generators", 1, Severity::High),
    ("/etc/systemd/user-generators", 1, Severity::High),
    ("/etc/crontab", 0, Severity::Medium),
    ("/etc/anacrontab", 0, Severity::Medium),
    ("/etc/cron.d", 1, Severity::Medium),
    ("/etc/cron.hourly", 1, Severity::Medium),
    ("/etc/cron.daily", 1, Severity::Medium),
    ("/etc/cron.weekly", 1, Severity::Medium),
    ("/etc/cron.monthly", 1, Severity::Medium),
    ("/var/spool/cron", 2, Severity::Medium),
    ("/var/spool/at", 1, Severity::Medium),
    ("/etc/rc.local", 0, Severity::Medium),
    ("/etc/rc.d/rc.local", 0, Severity::Medium),
    ("/etc/init.d", 1, Severity::Medium),
    ("/etc/xdg/autostart", 1, Severity::Medium),
    ("/etc/update-motd.d", 1, Severity::Medium),
    ("/etc/NetworkManager/dispatcher.d", 2, Severity::Medium),
    ("/etc/udev/rules.d", 1, Severity::Medium),
    ("/usr/lib/udev/rules.d", 1, Severity::Medium),
    ("/etc/modprobe.d", 1, Severity::Medium),
    ("/usr/lib/modprobe.d", 1, Severity::Medium),
    ("/etc/modules-load.d", 1, Severity::Low),
    ("/etc/modules", 0, Severity::Low),
    ("/etc/profile", 0, Severity::Medium),
    ("/etc/profile.d", 1, Severity::Medium),
    ("/etc/bashrc", 0, Severity::Medium),
    ("/etc/bash.bashrc", 0, Severity::Medium),
    ("/etc/environment", 0, Severity::Medium),
    ("/etc/zshenv", 0, Severity::Medium),
    ("/etc/zsh/zshenv", 0, Severity::Medium),
    ("/etc/ld.so.conf", 0, Severity::High),
    ("/etc/ld.so.conf.d", 1, Severity::High),
    ("/etc/pam.d", 1, Severity::High),
    ("/etc/security", 1, Severity::Medium),
    ("/etc/sudoers", 0, Severity::High),
    ("/etc/sudoers.d", 1, Severity::High),
    ("/etc/ssh/sshd_config", 0, Severity::High),
    ("/etc/nsswitch.conf", 0, Severity::High),
    ("/etc/login.defs", 0, Severity::Medium),
    ("/etc/ssh/sshd_config.d", 1, Severity::High),
    ("/etc/apt/apt.conf.d", 1, Severity::Medium),
    ("/etc/dnf/plugins", 1, Severity::Low),
    ("/etc/logrotate.d", 1, Severity::Low),
    ("/etc/dracut.conf.d", 1, Severity::Medium),
    ("/usr/lib/dracut/modules.d", 3, Severity::Medium),
    ("/etc/initramfs-tools/hooks", 1, Severity::Medium),
    ("/etc/initramfs-tools/scripts", 3, Severity::Medium),
];

/// PAM module directories: an unowned module here is critical.
pub(crate) const PAM_MODULES: &[&str] = &[
    "/usr/lib64/security",
    "/usr/lib/security",
    "/usr/lib/x86_64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security",
];

/// Relative to each home directory.
const PER_USER: &[(&str, u32)] = &[
    (".bashrc", 0),
    (".bash_profile", 0),
    (".bash_login", 0),
    (".profile", 0),
    (".zshrc", 0),
    (".zprofile", 0),
    (".config/systemd/user", 3),
    (".config/autostart", 1),
    (".ssh/rc", 0),
];

/// atd's own bookkeeping in its spool, rewritten as jobs come and go.
const SPOOL_NOISE: &[&str] = &["/var/spool/at/.SEQ", "/var/spool/at/.lockfile"];

/// The severity a change to `path` has, if it is a persistence location.
pub(crate) fn location(path: &str) -> Option<Severity> {
    if SPOOL_NOISE.contains(&path) {
        return None;
    }
    SYSTEM.iter().find_map(|(p, depth, sev)| {
        let hit = path == *p || (*depth > 0 && path.strip_prefix(p).is_some_and(|r| r.starts_with('/')));
        hit.then_some(*sev)
    })
}

fn collect(host: &Host, path: &str, depth: u32, out: &mut Vec<String>) {
    if SPOOL_NOISE.contains(&path) {
        return;
    }
    let Ok(md) = std::fs::symlink_metadata(host.path(path)) else {
        return;
    };
    if md.is_file() {
        out.push(path.to_string());
    } else if md.is_dir() && depth > 0 {
        for name in host.list_dir(path) {
            collect(host, &format!("{path}/{name}"), depth - 1, out);
        }
    }
}

impl Check for Persistence {
    fn id(&self) -> &'static str {
        "persistence"
    }

    fn description(&self) -> &'static str {
        "new or changed autostart, scheduler, shell, PAM, sudo, loader, and hook files"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["persist-new", "persist-changed"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, _: &Host) -> Option<String> {
        None
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.pkgdb()?;
        let mut canon = Canon::new(host);
        let mut targets: Vec<(String, Severity, bool)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut add = |paths: Vec<String>, sev: Severity, pam: bool, targets: &mut Vec<(String, Severity, bool)>| {
            for p in paths {
                let c = canon.path(&p);
                if seen.insert(c.clone()) {
                    targets.push((c, sev, pam));
                }
            }
        };
        for (p, depth, sev) in SYSTEM {
            let mut v = Vec::new();
            collect(host, p, *depth, &mut v);
            add(v, *sev, false, &mut targets);
        }
        for p in PAM_MODULES {
            let mut v = Vec::new();
            collect(host, p, 1, &mut v);
            add(v, Severity::Critical, true, &mut targets);
        }
        for u in users::with_homes(host) {
            for (rel, depth) in PER_USER {
                let mut v = Vec::new();
                collect(host, &format!("{}/{rel}", u.home.trim_end_matches('/')), *depth, &mut v);
                add(v, Severity::Low, false, &mut targets);
            }
        }

        let mut out = Vec::new();
        let mut present = std::collections::HashSet::new();
        for (path, sev, pam) in targets {
            let disk = host.path(&path);
            let owners: Vec<_> = db.lookup(&path).collect();
            let config = owners.iter().any(|f| f.config);
            if !owners.is_empty() && !config {
                continue; // a packaged file: pkg-verify's job
            }
            // Packaged configuration as shipped is not news either.
            if owners.iter().any(|f| {
                !f.digest.is_empty()
                    && f.pkg
                        .algo
                        .is_some_and(|a| digest::file(a, &disk).is_ok_and(|d| d == f.digest))
            }) {
                continue;
            }
            let Ok(md) = std::fs::symlink_metadata(&disk) else {
                continue;
            };
            // Present even if unreadable now: a transient error must not
            // drop the baseline and later report the file as new.
            present.insert(path.clone());
            let value = if md.size() > MAX_HASH {
                format!("size:{}:{}", md.size(), md.mtime())
            } else {
                match digest::file(Algo::Sha256, &disk) {
                    Ok(d) => digest::hex(&d),
                    Err(_) => continue,
                }
            };
            let unowned_pam = pam && owners.is_empty() && path.ends_with(".so");
            let change = anchors.observe(&path, &value);
            if unowned_pam && change.is_none() {
                out.push(
                    Finding::new("persist-new", Severity::Critical, &path, &value)
                        .message(format!("PAM module {path} is not owned by any package"))
                        .detail(serde_json::json!({ "sha256": value })),
                );
                continue;
            }
            let Some(old) = change else { continue };
            // Packaged configuration with no baseline was as shipped before.
            let (id, what) = if old.is_some() || config {
                ("persist-changed", "changed")
            } else {
                ("persist-new", "appeared")
            };
            let sev = if unowned_pam { Severity::Critical } else { sev };
            out.push(
                Finding::new(id, sev, &path, &value)
                    .message(format!(
                        "{path} {what} since the baseline{}",
                        if owners.is_empty() {
                            " (not from a package)"
                        } else {
                            " (edited package configuration)"
                        }
                    ))
                    .detail(serde_json::json!({
                        "sha256": value,
                        "baseline": old,
                        "uid": md.uid(),
                        "mode": format!("{:04o}", md.mode() & 0o7777),
                        "mtime": md.mtime(),
                        "ctime": md.ctime(),
                    })),
            );
        }
        // Forget files that are gone, so one that comes back is new again.
        anchors.map.retain(|k, _| present.contains(k));
        Ok(out)
    }
}
