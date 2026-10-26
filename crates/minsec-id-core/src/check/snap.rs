//! Snaps, verified from snapd's own records.
//!
//! A snap is one squashfs file (`/var/lib/snapd/snaps/NAME_REV.snap`),
//! mounted read-only at `/snap/NAME/REV`. The store signs a `snap-revision`
//! assertion for each revision, carrying the file's SHA3-384 and size, and a
//! `snap-declaration` binding the snap id to its name; snapd keeps both in
//! `/var/lib/snapd/assertions`. So:
//!
//! - `snap-verify` (full) checks each `.snap` against the assertions for its
//!   name and revision: the size always, the digest when the file's ctime
//!   moved since it last hashed clean (`snap-verified.bin`) or it falls in
//!   the day's slice of the rolling sample. Snaps installed from a file
//!   without assertions (`--dangerous`, revisions `xN`) are reported as
//!   `snap-unasserted`.
//! - `snap-mounts` (quick) checks that each `/snap/NAME/REV` is mounted from
//!   its own `.snap`, and that the file is still there (a loop device keeps
//!   a replaced or deleted file mounted).
//!
//! The assertions' signatures are not verified here: snapd verified them
//! when it acquired them, and the store's keys are its to manage.

use super::pkg_verify::{load_verified, path_hash, save_verified};
use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use base64::Engine as _;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

pub struct SnapVerify;
pub struct SnapMounts;

const SNAPS: &str = "/var/lib/snapd/snaps";
const ASSERTS: &str = "/var/lib/snapd/assertions/asserts-v0";
const VERIFIED: &str = "snap-verified.bin";

fn unavailable(host: &Host) -> Option<String> {
    (!host.exists(SNAPS)).then(|| "no snapd".into())
}

/// An assertion's headers (`key: value` lines up to the first blank line).
/// Multi-line values are not needed here and are skipped.
pub(crate) fn headers(s: &str) -> HashMap<&str, &str> {
    s.split("\n\n")
        .next()
        .unwrap_or("")
        .lines()
        .filter(|l| !l.starts_with(' '))
        .filter_map(|l| l.split_once(": "))
        .collect()
}

/// `NAME_REV.snap` (or `NAME_KEY_REV.snap` for a parallel instance) →
/// (instance name, snap name, revision).
fn parse_file_name(n: &str) -> Option<(&str, &str, &str)> {
    let stem = n.strip_suffix(".snap")?;
    let (inst, rev) = stem.rsplit_once('_')?;
    let name = inst.split_once('_').map_or(inst, |(n, _)| n);
    (!name.is_empty() && !rev.is_empty()).then_some((inst, name, rev))
}

struct Revision {
    digest: String,
    size: u64,
}

/// The assertions snapd holds: snap name → snap id, and (snap id,
/// revision) → the store's record of that file.
struct Store {
    ids: HashMap<String, String>,
    revisions: HashMap<(String, String), Revision>,
}

/// The current revision of an assertion: snapd names the file `active`
/// for revision 0 and `active.N` for revision N.
fn active(host: &Host, dir: &str) -> Option<String> {
    let newest = host
        .list_dir(dir)
        .into_iter()
        .filter_map(|n| {
            let rev = match n.strip_prefix("active")? {
                "" => 0,
                r => r.strip_prefix('.')?.parse::<u32>().ok()?,
            };
            Some((rev, n))
        })
        .max()?;
    host.read_opt(format!("{dir}/{}", newest.1))
}

fn store(host: &Host) -> Store {
    let mut ids = HashMap::new();
    let decl = format!("{ASSERTS}/snap-declaration");
    for series in host.list_dir(&decl) {
        for id in host.list_dir(format!("{decl}/{series}")) {
            if let Some(a) = active(host, &format!("{decl}/{series}/{id}")) {
                let h = headers(&a);
                if let (Some(n), Some(i)) = (h.get("snap-name"), h.get("snap-id")) {
                    ids.insert(n.to_string(), i.to_string());
                }
            }
        }
    }
    let mut revisions = HashMap::new();
    let revs = format!("{ASSERTS}/snap-revision");
    for d in host.list_dir(&revs) {
        if let Some(a) = active(host, &format!("{revs}/{d}")) {
            let h = headers(&a);
            if let (Some(id), Some(rev), Some(dg), Some(size)) = (
                h.get("snap-id"),
                h.get("snap-revision"),
                h.get("snap-sha3-384"),
                h.get("snap-size"),
            ) {
                revisions.insert(
                    (id.to_string(), rev.to_string()),
                    Revision {
                        digest: dg.to_string(),
                        size: size.parse().unwrap_or(u64::MAX),
                    },
                );
            }
        }
    }
    Store { ids, revisions }
}

/// snapd's digest of a file: SHA3-384, base64url without padding.
fn snap_digest(path: &std::path::Path) -> std::io::Result<String> {
    let d = digest::file(Algo::Sha3_384, path)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d))
}

impl Check for SnapVerify {
    fn id(&self) -> &'static str {
        "snap-verify"
    }

    fn description(&self) -> &'static str {
        "installed snaps against the store's signed digests, hashing only on change"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["snap-modified", "snap-unasserted"]
    }

    fn cost(&self) -> Cost {
        Cost::Full
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        if !host.exists(ASSERTS) {
            return Err(Unavailable("snapd has no assertion database".into()).into());
        }
        let store = store(host);
        let verified = load_verified(&ctx.state_dir, VERIFIED);
        let mut next = HashMap::new();
        let days = ctx.cfg.scan.sample_days.max(1) as u64;
        let today = ctx.now / 86_400;
        let mut out = Vec::new();
        let (mut hashed, mut bytes) = (0u64, 0u64);
        for n in host.list_dir(SNAPS) {
            let Some((inst, name, rev)) = parse_file_name(&n) else {
                continue;
            };
            let p = format!("{SNAPS}/{n}");
            let disk = host.path(&p);
            let Ok(md) = std::fs::symlink_metadata(&disk) else {
                continue;
            };
            if !md.file_type().is_file() {
                continue;
            }
            let modified = |sev: Severity, salient: &str, why: String| {
                Finding::new("snap-modified", sev, &p, salient)
                    .message(format!("snap {inst} revision {rev}: {why}"))
                    .detail(serde_json::json!({ "snap": inst, "revision": rev }))
            };
            if rev.starts_with('x') {
                out.push(
                    Finding::new("snap-unasserted", Severity::Low, &p, "")
                        .message(format!(
                            "snap {inst} revision {rev} was installed from a file, without store assertions"
                        ))
                        .detail(serde_json::json!({ "snap": inst, "revision": rev })),
                );
                continue;
            }
            let Some(id) = store.ids.get(name) else {
                out.push(modified(
                    Severity::High,
                    "no-declaration",
                    "the store has not declared a snap of this name".into(),
                ));
                continue;
            };
            let Some(want) = store.revisions.get(&(id.clone(), rev.to_string())) else {
                out.push(modified(
                    Severity::High,
                    "no-revision",
                    "no store assertion for this revision".into(),
                ));
                continue;
            };
            if md.len() != want.size {
                out.push(modified(
                    Severity::High,
                    &format!("size:{}", md.len()),
                    format!("{} bytes; the store's is {}", md.len(), want.size),
                ));
                continue;
            }
            let key = path_hash(&p);
            let ctime = md.ctime() * 1_000_000_000 + md.ctime_nsec();
            let sampled = key % days == today % days;
            if verified.get(&key) == Some(&ctime) && !sampled {
                next.insert(key, ctime);
                continue;
            }
            let got = match snap_digest(&disk) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!("{p}: {e}");
                    continue;
                }
            };
            hashed += 1;
            bytes += md.len();
            if got == want.digest {
                next.insert(key, ctime);
            } else {
                out.push(
                    modified(Severity::High, &got, "content differs from the store's digest".into()).detail(
                        serde_json::json!({ "snap": inst, "revision": rev, "expected": want.digest, "actual": got }),
                    ),
                );
            }
        }
        if let Err(e) = save_verified(&ctx.state_dir, VERIFIED, &next) {
            tracing::warn!("{VERIFIED}: {e}");
        }
        tracing::info!("snap-verify: {} snaps hashed ({} MiB)", hashed, bytes >> 20);
        Ok(out)
    }
}

/// The file a loop device is backed by, as the kernel reports it (with a
/// ` (deleted)` suffix when it was removed).
fn loop_backing(host: &Host, dev: &str) -> Option<String> {
    let name = dev.strip_prefix("/dev/")?;
    host.read_opt(format!("/sys/block/{name}/loop/backing_file"))
}

impl Check for SnapMounts {
    fn id(&self) -> &'static str {
        "snap-mounts"
    }

    fn description(&self) -> &'static str {
        "each mounted snap backed by its own .snap file"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let mut out = Vec::new();
        for m in crate::procfs::mounts(ctx.host) {
            let Some(rest) = m.target.strip_prefix("/snap/") else {
                continue;
            };
            let Some((inst, rev)) = rest.split_once('/') else {
                continue;
            };
            if rev.contains('/') || inst == "bin" {
                continue;
            }
            // `snap try` mounts a directory: it has no file to verify, and
            // snap-verify reports its revision as unasserted.
            if rev.starts_with('x') && m.fstype != "squashfs" {
                continue;
            }
            let want = format!("{SNAPS}/{inst}_{rev}.snap");
            let got = if m.source.starts_with("/dev/loop") {
                loop_backing(ctx.host, &m.source)
            } else {
                Some(format!("{} ({})", m.source, m.fstype))
            };
            let Some(got) = got else {
                continue;
            };
            if got == want {
                continue;
            }
            let why = if got == format!("{want} (deleted)") {
                "is mounted from a file that has since been replaced or deleted".to_string()
            } else {
                format!("is mounted from {got}, not {want}")
            };
            out.push(
                Finding::new("snap-mounts", Severity::High, &m.target, &got)
                    .message(format!("{} {why}", m.target))
                    .detail(serde_json::json!({ "expected": want, "actual": got, "source": m.source })),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        assert_eq!(parse_file_name("core22_1380.snap"), Some(("core22", "core22", "1380")));
        assert_eq!(parse_file_name("hello_x1.snap"), Some(("hello", "hello", "x1")));
        assert_eq!(
            parse_file_name("lxd_test_33110.snap"),
            Some(("lxd_test", "lxd", "33110"))
        );
        assert_eq!(parse_file_name("core22_1380.snap.partial"), None);
        assert_eq!(parse_file_name("nounderscore.snap"), None);
    }

    #[test]
    fn newest_assertion_revision() {
        let dir = std::env::temp_dir().join(format!("minsec-id-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("active"), "r0").unwrap();
        std::fs::write(dir.join("active.2"), "r2").unwrap();
        std::fs::write(dir.join("active.10"), "r10").unwrap();
        std::fs::write(dir.join("other"), "x").unwrap();
        let h = Host::default();
        assert_eq!(active(&h, dir.to_str().unwrap()).as_deref(), Some("r10"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn assertion_headers() {
        let a = "type: snap-revision\nauthority-id: canonical\nsnap-sha3-384: abc\nsnap-id: ID\n\
                 snap-size: 4096\nsnap-revision: 29\ntimestamp: 2024-01-01T00:00:00Z\n\n\
                 AcLBXAQAAQoABgUC...\n";
        let h = headers(a);
        assert_eq!(h["type"], "snap-revision");
        assert_eq!(h["snap-sha3-384"], "abc");
        assert_eq!(h["snap-revision"], "29");
        assert!(!h.contains_key("AcLBXAQAAQoABgUC..."));
    }
}
