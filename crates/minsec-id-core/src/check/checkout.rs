//! Verifying an ostree checkout against its commit: shared by flatpak's
//! deployments and an ostree system's own.
//!
//! A checkout's files are hard links to the repository's content-addressed
//! objects, so most of the work is stat: a file missing, replaced (another
//! inode), of another type, or a symlink retargeted shows without reading
//! anything. Content is hashed only on evidence of change, as `pkg-verify`
//! does: the object's ctime is newer than the newest deployment the previous
//! scan saw (a write or chmod moves it, and userspace cannot set it back), or
//! the object falls in the day's slice of the rolling sample.
//!
//! A deployment links its objects again, which moves their ctimes too, so
//! the line is drawn at the previous scan's newest deployment, not the
//! current one: every object a newer deployment linked is hashed once, and
//! a change made just before a deployment cannot hide behind it. An object
//! that hashed clean after its ctime moved is remembered (in the caller's
//! memo file) until it moves again.

use super::path_is_code;
use super::pkg_verify::path_hash;
use crate::finding::{Finding, Severity};
use crate::ostree::{self, Csum, Repo};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One checkout to verify.
pub(crate) struct Checkout<'a> {
    /// The subject prefix: a flatpak ref, or the system's stateroot.
    pub label: String,
    pub commit: Csum,
    pub dir: PathBuf,
    /// Finding ids: a file changed or added; a file missing.
    pub modified: &'static str,
    pub missing: &'static str,
    /// Which of the commit's paths (relative, no leading slash) the
    /// checkout is expected to have.
    pub wanted: &'a dyn Fn(&str) -> bool,
    /// Paths the deployment legitimately has in another form.
    pub exempt: &'a dyn Fn(&str, &Path) -> bool,
    /// The directory under which files not in the commit are reported.
    pub extras_root: &'static str,
    /// The path a commit-relative path is known by, for its severity.
    pub host_path: fn(&str) -> String,
}

/// The anchor that carries the newest deployment from one scan to the next.
const SEEN: &str = "deployments-verified-through";

/// The ctime line for this scan: the newest deployment the previous scan
/// saw (or, on the first, the newest now), recording the newest now for the
/// next. Objects changed after the line are hashed.
pub(crate) fn since(anchors: &mut super::Anchors, newest: i64) -> i64 {
    let prev = anchors.map.get(SEEN).and_then(|v| v.parse().ok()).unwrap_or(newest);
    anchors.set(SEEN, &newest.to_string());
    prev.min(newest)
}

pub(crate) struct Verifier<'a> {
    pub repo: &'a Repo,
    /// The newest deployment the previous scan saw: objects changed after
    /// it are hashed.
    pub since: i64,
    pub sample_days: u64,
    pub today: u64,
    pub verified: HashMap<u64, i64>,
    pub next_verified: HashMap<u64, i64>,
    /// Objects already judged this run: shared by many checkouts.
    judged: HashMap<Csum, bool>,
    pub out: Vec<Finding>,
    pub hashed: u64,
    pub bytes: u64,
}

fn key(c: &Csum) -> u64 {
    u64::from_le_bytes(c[..8].try_into().unwrap())
}

impl<'a> Verifier<'a> {
    pub fn new(repo: &'a Repo, since: i64, sample_days: u64, today: u64, verified: HashMap<u64, i64>) -> Self {
        Self {
            repo,
            since,
            sample_days: sample_days.max(1),
            today,
            verified,
            next_verified: HashMap::new(),
            judged: HashMap::new(),
            out: Vec::new(),
            hashed: 0,
            bytes: 0,
        }
    }

    fn finding(&mut self, c: &Checkout, id: &str, sev: Severity, rel: &str, salient: &str, msg: String) {
        let subject = if rel.is_empty() {
            c.label.clone()
        } else {
            format!("{}/{rel}", c.label)
        };
        self.out.push(
            Finding::new(id, sev, subject, salient)
                .message(msg)
                .detail(serde_json::json!({
                    "deployment": c.label,
                    "commit": ostree::hex(&c.commit),
                    "path": rel,
                })),
        );
    }

    fn severity(c: &Checkout, rel: &str, mode: u32) -> Severity {
        if path_is_code(&(c.host_path)(rel)) || mode & 0o111 != 0 {
            Severity::High
        } else {
            Severity::Medium
        }
    }

    /// Whether `path`'s content matches `c`, hashing only when there is a
    /// reason to. `obj` says whether `path` is the repository object itself.
    fn intact(&mut self, c: &Csum, path: &Path, md: &std::fs::Metadata, obj: bool) -> bool {
        if obj {
            if let Some(&ok) = self.judged.get(c) {
                return ok;
            }
        }
        // A checkout's own copy (not the object) is remembered by its path.
        let k = if obj {
            key(c)
        } else {
            key(c) ^ path_hash(&path.to_string_lossy())
        };
        let ctime = md.ctime() * 1_000_000_000 + md.ctime_nsec();
        let changed = md.ctime() > self.since;
        let suspect = changed && self.verified.get(&k) != Some(&ctime);
        let sampled = k % self.sample_days == self.today % self.sample_days;
        if !(suspect || sampled) {
            if changed {
                self.next_verified.insert(k, ctime);
            }
            return true;
        }
        let ok = match self.repo.file_checksum(path) {
            Ok(got) => {
                self.hashed += 1;
                self.bytes += md.size();
                &got == c
            }
            Err(e) => {
                tracing::debug!("{}: {e}", path.display());
                return true;
            }
        };
        if ok && changed {
            self.next_verified.insert(k, ctime);
        }
        if obj {
            self.judged.insert(*c, ok);
        }
        ok
    }

    pub fn checkout(&mut self, c: &Checkout) {
        let commit = match self.repo.commit(&c.commit) {
            Ok(x) => x,
            Err(e) => {
                let msg = format!("{}: its commit cannot be verified: {e:#}", c.label);
                self.finding(c, c.modified, Severity::High, "", "commit", msg);
                return;
            }
        };
        let mut entries: Vec<(String, Option<Csum>)> = Vec::new();
        if let Err(e) = self.repo.walk(&commit.root_tree, &mut |rel, x| {
            entries.push((rel.to_string(), x.copied()));
        }) {
            let msg = format!("{}: its tree cannot be verified: {e:#}", c.label);
            self.finding(c, c.modified, Severity::High, "", "tree", msg);
            return;
        }
        let mut expected: HashSet<&str> = HashSet::with_capacity(entries.len());
        for (rel, x) in &entries {
            if !(c.wanted)(rel) {
                continue;
            }
            expected.insert(rel);
            if let Some(x) = x {
                self.file(c, rel, x);
            }
        }
        self.extras(c, &expected);
    }

    fn file(&mut self, c: &Checkout, rel: &str, x: &Csum) {
        let path = c.dir.join(rel);
        let obj = self.repo.object_path(x, "file");
        let omd = std::fs::symlink_metadata(&obj).ok();
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mode = omd.as_ref().map(|m| m.mode()).unwrap_or(0);
                let sev = Self::severity(c, rel, mode).min(Severity::Medium);
                self.finding(c, c.missing, sev, rel, "", format!("{}: {rel} is missing", c.label));
                return;
            }
            Err(e) => {
                tracing::debug!("{}: {e}", path.display());
                return;
            }
        };
        let Some(omd) = omd else {
            // The object is gone (pruned, or deleted): hash the checkout.
            if !self.repo.file_checksum(&path).is_ok_and(|g| &g == x) {
                self.modified(c, rel, md.mode(), "content");
            }
            return;
        };
        if md.file_type() != omd.file_type() {
            self.modified(c, rel, omd.mode(), "type");
            return;
        }
        if md.file_type().is_symlink() {
            if std::fs::read_link(&path).ok() != std::fs::read_link(&obj).ok() {
                self.modified(c, rel, 0, "symlink");
            }
            return;
        }
        let same = md.dev() == omd.dev() && md.ino() == omd.ino();
        let ok = if same {
            self.intact(x, &obj, &omd, true)
        } else {
            self.intact(x, &path, &md, false)
        };
        if !ok {
            self.modified(c, rel, md.mode(), "content");
        }
    }

    fn modified(&mut self, c: &Checkout, rel: &str, mode: u32, kind: &str) {
        if (c.exempt)(rel, &c.dir.join(rel)) {
            return;
        }
        let what = match kind {
            "type" => "is no longer the type its commit records",
            "symlink" => "points elsewhere than its commit records",
            _ => "differs from its commit",
        };
        let sev = Self::severity(c, rel, mode);
        self.finding(c, c.modified, sev, rel, kind, format!("{}: {rel} {what}", c.label));
    }

    /// Files in the checkout that its commit does not have.
    fn extras(&mut self, c: &Checkout, expected: &HashSet<&str>) {
        let mut stack = vec![c.extras_root.to_string()];
        let mut found = Vec::new();
        while let Some(rel) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(c.dir.join(&rel)) else {
                continue;
            };
            for e in rd.flatten() {
                let Ok(name) = e.file_name().into_string() else {
                    continue;
                };
                let r = format!("{rel}/{name}");
                if (c.exempt)(&r, &e.path()) {
                    continue;
                }
                if !expected.contains(r.as_str()) {
                    let mode = e.metadata().map(|m| m.mode()).unwrap_or(0);
                    found.push((r, mode));
                } else if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(r);
                }
            }
        }
        found.sort();
        for (r, mode) in found {
            let sev = Self::severity(c, &r, mode);
            self.finding(
                c,
                c.modified,
                sev,
                &r,
                "added",
                format!("{}: {r} is not in its commit", c.label),
            );
        }
    }
}
