//! Package integrity, without a hash database of our own.
//!
//! `pkg-verify` (full scans) compares installed files with the digests,
//! sizes, modes, and link targets the package manager recorded. It hashes a
//! file only when something says it may have changed:
//!
//! - its ctime is newer than its package's install time (plus slack): ctime
//!   cannot be set from userspace, so a later write or chmod shows;
//! - its size, mtime, or mode differ from the database;
//! - it falls in today's slice of the rolling sample, so every file is
//!   re-hashed once per `scan.sample_days` regardless.
//!
//! A file whose ctime moved for a benign reason (relabel, chmod) and that
//! hashed clean is remembered in `verified.bin` by (path hash, ctime), so
//! it is not re-hashed until its ctime moves again.
//!
//! Configuration files are expected to differ from the package and are not
//! verified here; the ones that matter are watched by `persistence`.
//!
//! `pkg-signatures` (quick) reports rpm's header verification failures,
//! which mean the rpmdb itself was edited, and unsigned packages.

use super::{path_is_code, Anchors, Check, Cost, Ctx};
use crate::digest;
use crate::finding::{fingerprint, Finding, Severity};
use crate::host::Host;
use crate::pkgdb::{File, Manager, Verify};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub struct PkgVerify;
pub struct PkgSignatures;

const SETID: u32 = libc::S_ISUID | libc::S_ISGID;

fn path_hash(p: &str) -> u64 {
    u64::from_str_radix(&fingerprint(&[p]), 16).unwrap_or(0)
}

/// `verified.bin`: sorted (path hash, ctime ns) pairs, little-endian.
fn load_verified(dir: &Path) -> HashMap<u64, i64> {
    let mut m = HashMap::new();
    let Ok(mut f) = std::fs::File::open(dir.join("verified.bin")) else {
        return m;
    };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return m;
    }
    for c in buf.chunks_exact(16) {
        m.insert(
            u64::from_le_bytes(c[..8].try_into().unwrap()),
            i64::from_le_bytes(c[8..].try_into().unwrap()),
        );
    }
    m
}

fn save_verified(dir: &Path, m: &HashMap<u64, i64>) -> std::io::Result<()> {
    let mut v: Vec<(&u64, &i64)> = m.iter().collect();
    v.sort();
    let mut buf = Vec::with_capacity(v.len() * 16);
    for (k, c) in v {
        buf.extend_from_slice(&k.to_le_bytes());
        buf.extend_from_slice(&c.to_le_bytes());
    }
    let tmp = dir.join("verified.bin.tmp");
    std::fs::File::create(&tmp)?.write_all(&buf)?;
    std::fs::rename(tmp, dir.join("verified.bin"))
}

struct Run<'a> {
    host: &'a Host,
    /// `minsec-id verify`: hash everything asked about, configuration included.
    force: bool,
    now: u64,
    slack: u64,
    sample_days: u64,
    verified: HashMap<u64, i64>,
    next_verified: HashMap<u64, i64>,
    /// Path hashes the daemon saw written (`dirty.list`): hashed regardless.
    dirty: std::collections::HashSet<u64>,
    out: Vec<Finding>,
    hashed: u64,
    bytes: u64,
}

impl Run<'_> {
    fn finding(&mut self, id: &str, sev: Severity, f: &File, salient: &str, msg: String, detail: serde_json::Value) {
        let mut d = detail;
        if let Some(o) = d.as_object_mut() {
            o.insert("package".into(), f.pkg.id.clone().into());
        }
        self.out
            .push(Finding::new(id, sev, f.path(), salient).message(msg).detail(d));
    }

    /// Verify one path against its owners (several, for shared files).
    fn path(&mut self, owners: &[File]) {
        let Some(f) = owners.iter().find(|f| f.installed && !f.ghost).copied() else {
            return;
        };
        let path = f.path();
        let path = path.as_str();
        let disk = self.host.path(path);
        let md = match std::fs::symlink_metadata(&disk) {
            Ok(m) => m,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::debug!("{path}: {e}");
                return;
            }
            Err(_) => {
                if !(f.missingok || f.doc || f.config) {
                    let sev = if path_is_code(path) {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    self.finding(
                        "pkg-missing",
                        sev,
                        &f,
                        "",
                        format!("{} from {} is missing", path, f.pkg.name),
                        serde_json::json!({}),
                    );
                }
                return;
            }
        };

        let v = f.verify;
        if let Some(target) = f.link.filter(|_| v.has(Verify::LINK)) {
            let actual = std::fs::read_link(&disk).ok().map(|t| t.to_string_lossy().into_owned());
            if actual.as_deref() != Some(target) {
                let sev = if path_is_code(path) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let a = actual.clone().unwrap_or_else(|| "(not a symlink)".into());
                self.finding(
                    "pkg-modified",
                    sev,
                    &f,
                    &a,
                    format!("{} points to {a}, not {target}", path),
                    serde_json::json!({ "kind": "symlink", "expected": target, "actual": actual }),
                );
            }
            return;
        }
        if f.link.is_some() || !f.is_regular() {
            return;
        }
        // As rpm -V: a type change matters for files whose content is verified.
        if !md.file_type().is_file() && v.has(Verify::MODE) && v.has(Verify::DIGEST) {
            self.finding(
                "pkg-modified",
                Severity::High,
                &f,
                "type",
                format!("{} is no longer a regular file", path),
                serde_json::json!({ "kind": "type" }),
            );
            return;
        }

        if !md.file_type().is_file() {
            return;
        }
        if let Some(mode) = f.mode.filter(|_| v.has(Verify::MODE)) {
            let (want, got) = (mode & 0o7777, md.mode() & 0o7777);
            if want != got {
                let gained = got & SETID & !want;
                let sev = if gained != 0 { Severity::High } else { Severity::Low };
                self.finding(
                    "pkg-mode-changed",
                    sev,
                    &f,
                    &format!("{got:o}"),
                    format!(
                        "{} mode is {got:04o}, packaged {want:04o}{}",
                        path,
                        if gained != 0 { " (gained setuid/setgid)" } else { "" }
                    ),
                    serde_json::json!({ "expected": format!("{want:04o}"), "actual": format!("{got:04o}") }),
                );
            }
        }

        if f.config && !self.force {
            return;
        }
        let ctime_ns = md.ctime() * 1_000_000_000 + md.ctime_nsec();
        let key = path_hash(path);
        let changed_since_install = (md.ctime() as u64) > f.pkg.install_time + self.slack;
        if f.digest.is_empty() || !v.has(Verify::DIGEST) {
            return;
        }
        let suspect = f.size.is_some_and(|s| v.has(Verify::SIZE) && s != md.size())
            || f.mtime.is_some_and(|t| v.has(Verify::MTIME) && t != md.mtime() as u64)
            || (changed_since_install && self.verified.get(&key) != Some(&ctime_ns))
            || self.dirty.contains(&key);
        let sampled = key % self.sample_days == (self.now / 86_400) % self.sample_days;
        if !(suspect || sampled || self.force) {
            if changed_since_install {
                self.next_verified.insert(key, ctime_ns);
            }
            return;
        }
        let Some(algo) = f.pkg.algo.filter(|a| a.digest_len() == f.digest.len()) else {
            return;
        };
        let got = match digest::file(algo, &disk) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("{}: {e}", path);
                return;
            }
        };
        self.hashed += 1;
        self.bytes += md.size();
        // A shared path is intact if any owner's digest matches.
        if owners.iter().any(|o| o.digest == got.as_slice()) {
            if changed_since_install {
                self.next_verified.insert(key, ctime_ns);
            }
            return;
        }
        let hex = digest::hex(&got);
        if f.config && self.force {
            self.finding(
                "pkg-config-modified",
                Severity::Info,
                &f,
                &hex,
                format!("{} (configuration) differs from {}", path, f.pkg.id),
                serde_json::json!({ "expected": digest::hex(f.digest), "actual": hex, "algo": algo.name() }),
            );
            return;
        }
        let sev = if path_is_code(path) {
            Severity::High
        } else {
            Severity::Medium
        };
        self.finding(
            "pkg-modified",
            sev,
            &f,
            &hex,
            format!("{} differs from {}", path, f.pkg.id),
            serde_json::json!({
                "kind": "content",
                "expected": digest::hex(f.digest),
                "actual": hex,
                "algo": algo.name(),
                "size": md.size(),
                "ctime": md.ctime(),
            }),
        );
    }
}

impl Check for PkgVerify {
    fn id(&self) -> &'static str {
        "pkg-verify"
    }

    fn description(&self) -> &'static str {
        "installed files against package digests, hashing only files with evidence of change"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["pkg-modified", "pkg-config-modified", "pkg-missing", "pkg-mode-changed"]
    }

    fn cost(&self) -> Cost {
        Cost::Full
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!crate::pkgdb::has_rpm(host) && !crate::pkgdb::has_dpkg(host)).then(|| "no rpm or dpkg database".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let db = ctx.owned()?;
        let claimed = crate::dirty::claim(&ctx.state_dir);
        let mut run = Run {
            host: ctx.host,
            force: false,
            now: ctx.now,
            slack: ctx.cfg.scan.ctime_slack.secs(),
            sample_days: ctx.cfg.scan.sample_days.max(1) as u64,
            verified: load_verified(&ctx.state_dir),
            next_verified: HashMap::new(),
            dirty: claimed.paths.iter().map(|p| path_hash(p)).collect(),
            out: Vec::new(),
            hashed: 0,
            bytes: 0,
        };
        // Owners of one path are adjacent: verify a group at a time.
        let mut group: Vec<File> = Vec::new();
        let mut total = 0usize;
        for f in db.files() {
            total += 1;
            if group.first().is_some_and(|g| g.dir != f.dir || g.name != f.name) {
                run.path(&group);
                group.clear();
            }
            group.push(f);
        }
        if !group.is_empty() {
            run.path(&group);
        }
        if let Err(e) = save_verified(&ctx.state_dir, &run.next_verified) {
            tracing::warn!("verified.bin: {e}");
        }
        tracing::info!(
            "pkg-verify: {} paths, {} hashed ({} MiB), {} written since the last full scan",
            total,
            run.hashed,
            run.bytes >> 20,
            claimed.paths.len()
        );
        claimed.done();
        Ok(run.out)
    }
}

/// What `minsec-id verify` found.
#[derive(Debug, serde::Serialize)]
pub struct VerifyReport {
    pub target: String,
    /// The packages the target belongs to (or is).
    pub packages: Vec<String>,
    pub files: usize,
    pub hashed: u64,
    pub findings: Vec<Finding>,
}

/// Verify one path, or every file of one package, hashing unconditionally.
pub fn verify(ctx: &Ctx, target: &str) -> anyhow::Result<VerifyReport> {
    let db = ctx.owned()?;
    let mut run = Run {
        host: ctx.host,
        force: true,
        now: ctx.now,
        slack: ctx.cfg.scan.ctime_slack.secs(),
        sample_days: 1,
        verified: HashMap::new(),
        next_verified: HashMap::new(),
        dirty: Default::default(),
        out: Vec::new(),
        hashed: 0,
        bytes: 0,
    };
    let mut packages = std::collections::BTreeSet::new();
    let mut files = 0;
    if target.starts_with('/') {
        let path = crate::host::Canon::new(ctx.host).path(target);
        let owners: Vec<File> = db.lookup(&path).collect();
        if owners.is_empty() {
            anyhow::bail!("{path} is not owned by any package");
        }
        packages.extend(owners.iter().map(|f| f.pkg.id.clone()));
        files = 1;
        run.path(&owners);
    } else {
        let pkgs = db.find_package(target);
        if pkgs.is_empty() {
            anyhow::bail!("no installed package `{target}`");
        }
        let ids: std::collections::HashSet<&str> = pkgs.iter().map(|p| p.id.as_str()).collect();
        packages.extend(ids.iter().map(|s| s.to_string()));
        for f in db.files().filter(|f| ids.contains(f.pkg.id.as_str())) {
            // Other owners of a shared path count: its digest may be theirs.
            let path = f.path();
            let owners: Vec<File> = db.lookup(&path).collect();
            files += 1;
            run.path(&owners);
        }
    }
    Ok(VerifyReport {
        target: target.to_string(),
        packages: packages.into_iter().collect(),
        files,
        hashed: run.hashed,
        findings: run.out,
    })
}

impl Check for PkgSignatures {
    fn id(&self) -> &'static str {
        "pkg-signatures"
    }

    fn description(&self) -> &'static str {
        "rpm header signature failures (an edited rpmdb) and unsigned packages"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["pkg-db-tampered", "pkg-unsigned"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!crate::pkgdb::has_rpm(host)).then(|| "no rpm database (dpkg records no signatures)".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let db = ctx.owned()?;
        let mut out = Vec::new();
        for w in &db.warnings {
            let (sev, what) = if w.contains("BAD") {
                (
                    Severity::Critical,
                    "failed verification: the package database was altered",
                )
            } else if w.contains("NOKEY") {
                (Severity::Medium, "is signed by a key that is not installed")
            } else {
                continue;
            };
            out.push(
                Finding::new("pkg-db-tampered", sev, w, "")
                    .message(format!("an rpm header {what}"))
                    .detail(serde_json::json!({ "rpm": w })),
            );
        }
        for p in &db.packages {
            if p.manager == Manager::Rpm && p.key_id.is_none() && p.name != "gpg-pubkey" {
                out.push(
                    Finding::new("pkg-unsigned", Severity::Low, &p.id, "")
                        .message(format!("package {} is not signed", p.id)),
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_roundtrip() {
        let dir = std::env::temp_dir().join(format!("minsec-id-verified-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = HashMap::from([(1u64, -5i64), (u64::MAX, 7)]);
        save_verified(&dir, &m).unwrap();
        assert_eq!(load_verified(&dir), m);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
