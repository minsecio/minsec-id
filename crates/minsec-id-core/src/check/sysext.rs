//! `sysext`: extensions merged over `/usr`, `/opt`, or `/etc` by
//! systemd-sysext and systemd-confext. An extension adds files no package
//! and no image installed, so each is reported once when it appears, more
//! severely when nothing verifies its content (a directory, or an image
//! without dm-verity), and its content changing is `sysext-changed`. Files
//! it provides are left out of `exe-unowned`, which would otherwise report
//! each of them.

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::sysext::{self, Source};
use std::os::unix::fs::MetadataExt;

pub struct Sysext;

/// What identifies an extension's content without reading it all: an
/// image's size and times; for a directory, every file's path, size, and
/// times (a directory extension can be changed in place).
fn fingerprint(host: &Host, src: &Source) -> String {
    match src {
        Source::Image(p) => match std::fs::metadata(host.path(p)) {
            Ok(m) => format!("{}:{}:{}:{}", m.size(), m.mtime(), m.ctime(), m.ino()),
            Err(_) => String::new(),
        },
        Source::Directory(p) => {
            let mut entries = Vec::new();
            let mut stack = vec![host.path(p)];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let Ok(m) = e.metadata() else { continue };
                    if m.is_dir() {
                        stack.push(e.path());
                    }
                    entries.push(format!(
                        "{}:{}:{}:{}",
                        e.path().display(),
                        m.size(),
                        m.mtime(),
                        m.ctime()
                    ));
                }
            }
            entries.sort();
            crate::finding::fingerprint(&entries.iter().map(String::as_str).collect::<Vec<_>>())
        }
    }
}

impl Check for Sysext {
    fn id(&self) -> &'static str {
        "sysext"
    }

    fn description(&self) -> &'static str {
        "system and configuration extensions merged over /usr, /opt, and /etc"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["sysext-changed"]
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
        let mut live = std::collections::HashSet::new();
        for e in sysext::merged(&crate::procfs::mounts(host)) {
            let key = format!("{}:{}", e.class, e.name);
            live.insert(key.clone());
            let src = sysext::source(host, &e);
            let (kind, path, verified) = match &src {
                Some(Source::Image(p)) => ("image", p.clone(), sysext::verity(host, p)),
                Some(Source::Directory(p)) => ("directory", p.clone(), false),
                None => ("unknown", String::new(), false),
            };
            let fp = src.as_ref().map(|s| fingerprint(host, s)).unwrap_or_default();
            let value = format!("{kind} {path} {fp}");
            let detail = serde_json::json!({
                "class": e.class,
                "hierarchy": e.hierarchy,
                "kind": kind,
                "source": path,
                "verity": verified,
            });
            // Recorded when first seen; one that appeared after the baseline
            // stays reported as new until accepted or the baseline is reset,
            // and a change to its content is reported separately, so that
            // accepting an extension does not accept what it later becomes.
            let new_key = format!("{key}:new");
            match anchors.map.get(&key).cloned() {
                None => {
                    anchors.set(&key, &value);
                    if !anchors.fresh {
                        anchors.set(&new_key, "1");
                    }
                }
                Some(old) if old != value => out.push(
                    Finding::new("sysext-changed", Severity::High, &key, &value)
                        .message(format!(
                            "{} {} merged into {} has changed ({path})",
                            e.class, e.name, e.hierarchy
                        ))
                        .detail(detail.clone()),
                ),
                Some(_) => {}
            }
            if anchors.map.contains_key(&new_key) {
                let (sev, why) = match (kind, verified) {
                    ("image", true) => (Severity::Low, "an image verified by dm-verity"),
                    ("image", false) => (Severity::Medium, "an image without dm-verity"),
                    ("directory", _) => (Severity::Medium, "a directory: nothing verifies its content"),
                    _ => (Severity::Medium, "its source was not found"),
                };
                out.push(
                    Finding::new(self.id(), sev, &key, kind)
                        .message(format!(
                            "{} {} is merged into {}: {why}{}",
                            e.class,
                            e.name,
                            e.hierarchy,
                            if path.is_empty() {
                                String::new()
                            } else {
                                format!(" ({path})")
                            }
                        ))
                        .detail(detail),
                );
            }
        }
        // An extension no longer merged needs no record.
        anchors
            .map
            .retain(|k, _| live.contains(k.strip_suffix(":new").unwrap_or(k)));
        Ok(out)
    }
}
