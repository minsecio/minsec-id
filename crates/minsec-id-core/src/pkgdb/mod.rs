//! The package database as the baseline: which files the package manager
//! installed, with the digests, sizes, and modes it recorded. Loaded once
//! per scan by streaming the package manager's own data; nothing is cached.
//!
//! Paths are canonicalized (symlinked directories resolved) so lookups by
//! the paths the kernel reports work on merged-/usr systems. Directories are
//! interned: a workstation's half-million owned paths share ~50k of them.

use crate::digest::Algo;
use crate::host::{Canon, Host};

mod dpkg;
mod rpm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Rpm,
    Dpkg,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub manager: Manager,
    pub name: String,
    /// `name-version-release.arch` (rpm) or `name:arch=version` (dpkg).
    pub id: String,
    pub install_time: u64,
    pub algo: Option<Algo>,
    /// rpm only: the signing key id, `None` when unsigned.
    pub key_id: Option<String>,
    pub summary: String,
}

const F_CONFIG: u8 = 1;
const F_DOC: u8 = 2;
const F_GHOST: u8 = 4;
const F_MISSINGOK: u8 = 8;
const F_INSTALLED: u8 = 16;

/// 44 bytes: a workstation has half a million of these.
struct Entry {
    dir: u32,
    name_off: u32,
    link_off: u32,
    digest_off: u32,
    pkg: u32,
    mode: u32,
    mtime: u32,
    /// `u32::MAX`: unknown, or too large to record.
    size: u32,
    name_len: u16,
    link_len: u16,
    digest_len: u8,
    flags: u8,
    verify: u8,
}

impl Entry {
    fn name(&self) -> (u32, u32) {
        (self.name_off, self.name_len as u32)
    }
}

/// One owned path, as recorded by its package.
#[derive(Debug, Clone, Copy)]
pub struct File<'a> {
    /// Canonical directory (`/` for top-level paths) and file name.
    pub dir: &'a str,
    pub name: &'a str,
    pub pkg: &'a Package,
    /// Empty for directories, symlinks, and files without a recorded digest.
    pub digest: &'a [u8],
    pub size: Option<u64>,
    /// Full `st_mode` (type and permissions), when recorded (rpm).
    pub mode: Option<u32>,
    pub mtime: Option<u64>,
    /// rpm: the symlink target, when the entry is a symlink.
    pub link: Option<&'a str>,
    pub config: bool,
    pub doc: bool,
    pub ghost: bool,
    pub missingok: bool,
    /// Actually installed (not excluded as a doc or language, not replaced).
    pub installed: bool,
    /// Which attributes the package asks to be verified (rpm `%verify`).
    pub verify: Verify,
}

/// rpm's per-file `%verify(...)` attributes, reduced to the ones checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verify(u8);

impl Verify {
    pub const DIGEST: u8 = 1;
    pub const SIZE: u8 = 2;
    pub const LINK: u8 = 4;
    pub const MTIME: u8 = 8;
    pub const MODE: u8 = 16;
    pub const ALL: Verify = Verify(31);

    /// From rpm's `FILEVERIFYFLAGS` (rpmVerifyAttrs bits).
    pub fn from_rpm(v: u32) -> Self {
        let mut out = 0;
        for (rpm_bit, ours) in [
            (0, Self::DIGEST),
            (1, Self::SIZE),
            (2, Self::LINK),
            (5, Self::MTIME),
            (6, Self::MODE),
        ] {
            if v & (1 << rpm_bit) != 0 {
                out |= ours;
            }
        }
        Verify(out)
    }

    pub fn has(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

impl File<'_> {
    pub fn path(&self) -> String {
        join(self.dir, self.name)
    }

    pub fn is_regular(&self) -> bool {
        match self.mode {
            Some(m) => m & libc::S_IFMT == libc::S_IFREG,
            None => !self.digest.is_empty(),
        }
    }
}

#[derive(Default)]
pub struct PkgDb {
    pub packages: Vec<Package>,
    pub managers: Vec<Manager>,
    /// Diagnostics from the package manager (rpm's signature warnings).
    pub warnings: Vec<String>,
    /// Lines that could not be parsed.
    pub skipped: usize,
    entries: Vec<Entry>,
    /// Interned directories, sorted; an entry's `dir` indexes this.
    dirs: Vec<(u32, u32)>,
    arena: String,
    digests: Vec<u8>,
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// `/a/b/c` → (`/a/b`, `c`); `/c` → (`/`, `c`).
fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", n)) => ("/", n),
        Some((d, n)) => (d, n),
        None => ("/", path),
    }
}

/// Raw file record handed to the builder by a manager-specific loader.
pub(crate) struct RawFile<'a> {
    pub path: &'a str,
    pub digest_hex: &'a str,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub mtime: Option<u64>,
    pub link: Option<&'a str>,
    pub config: bool,
    pub doc: bool,
    pub ghost: bool,
    pub missingok: bool,
    pub installed: bool,
    pub verify: Verify,
}

pub fn has_rpm(host: &Host) -> bool {
    host.exists("/usr/lib/sysimage/rpm")
        || host.exists("/var/lib/rpm/rpmdb.sqlite")
        || host.exists("/var/lib/rpm/Packages")
}

pub fn has_dpkg(host: &Host) -> bool {
    host.exists("/var/lib/dpkg/status")
}

impl PkgDb {
    /// Load every package database present on the host.
    pub fn load(host: &Host) -> anyhow::Result<Self> {
        let mut b = Builder::new(host);
        if has_rpm(host) {
            rpm::load(host, &mut b)?;
            b.db.managers.push(Manager::Rpm);
        }
        if has_dpkg(host) {
            dpkg::load(host, &mut b)?;
            b.db.managers.push(Manager::Dpkg);
        }
        let db = b.finish();
        // Loading churned through transient allocations; hand them back.
        // SAFETY: glibc's malloc_trim only releases free heap memory.
        unsafe {
            libc::malloc_trim(0);
        }
        Ok(db)
    }

    pub fn is_empty(&self) -> bool {
        self.managers.is_empty()
    }

    fn str_at(&self, (off, len): (u32, u32)) -> &str {
        &self.arena[off as usize..(off + len) as usize]
    }

    fn dir_of(&self, e: &Entry) -> &str {
        self.str_at(self.dirs[e.dir as usize])
    }

    fn name_of(&self, e: &Entry) -> &str {
        self.str_at(e.name())
    }

    fn view<'a>(&'a self, e: &'a Entry) -> File<'a> {
        File {
            dir: self.dir_of(e),
            name: self.name_of(e),
            pkg: &self.packages[e.pkg as usize],
            digest: &self.digests[e.digest_off as usize..e.digest_off as usize + e.digest_len as usize],
            size: (e.size != u32::MAX).then_some(e.size as u64),
            mode: (e.mode != 0).then_some(e.mode),
            mtime: (e.mtime != 0).then_some(e.mtime as u64),
            link: (e.link_len != 0).then(|| self.str_at((e.link_off, e.link_len as u32))),
            config: e.flags & F_CONFIG != 0,
            doc: e.flags & F_DOC != 0,
            ghost: e.flags & F_GHOST != 0,
            missingok: e.flags & F_MISSINGOK != 0,
            installed: e.flags & F_INSTALLED != 0,
            verify: Verify(e.verify),
        }
    }

    /// Every package that owns `path` (canonical), in load order.
    pub fn lookup<'a>(&'a self, path: &str) -> impl Iterator<Item = File<'a>> + 'a {
        let (dir, name) = split(path);
        let range = match self.dirs.binary_search_by(|d| self.str_at(*d).cmp(dir)) {
            Ok(d) => {
                let d = d as u32;
                let start = self.entries.partition_point(|e| (e.dir, self.name_of(e)) < (d, name));
                let end = start
                    + self.entries[start..]
                        .iter()
                        .take_while(|e| e.dir == d && self.name_of(e) == name)
                        .count();
                start..end
            }
            Err(_) => 0..0,
        };
        self.entries[range].iter().map(|e| self.view(e))
    }

    pub fn owns(&self, path: &str) -> bool {
        self.lookup(path).next().is_some()
    }

    /// All owned paths, grouped by directory; owners of a path are adjacent.
    pub fn files(&self) -> impl Iterator<Item = File<'_>> {
        self.entries.iter().map(|e| self.view(e))
    }

    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    pub fn find_package(&self, name: &str) -> Vec<&Package> {
        self.packages
            .iter()
            .filter(|p| p.name == name || p.id == name)
            .collect()
    }
}

pub(crate) struct Builder<'h> {
    db: PkgDb,
    canon: Canon<'h>,
    /// Directory → provisional id (insertion order) while loading.
    dir_ids: std::collections::HashMap<String, u32>,
}

impl<'h> Builder<'h> {
    pub fn new(host: &'h Host) -> Self {
        Self {
            db: PkgDb::default(),
            canon: Canon::new(host),
            dir_ids: Default::default(),
        }
    }

    pub fn package(&mut self, p: Package) -> u32 {
        self.db.packages.push(p);
        (self.db.packages.len() - 1) as u32
    }

    pub fn warn(&mut self, w: String) {
        self.db.warnings.push(w);
    }

    pub fn skip(&mut self) {
        self.db.skipped += 1;
    }

    fn intern(&mut self, s: &str) -> (u32, u32) {
        let off = self.db.arena.len() as u32;
        self.db.arena.push_str(s);
        (off, s.len() as u32)
    }

    fn dir_id(&mut self, dir: &str) -> u32 {
        if let Some(id) = self.dir_ids.get(dir) {
            return *id;
        }
        let r = self.intern(dir);
        let id = self.db.dirs.len() as u32;
        self.db.dirs.push(r);
        self.dir_ids.insert(dir.to_string(), id);
        id
    }

    fn locate(&mut self, path: &str) -> (u32, (u32, u16)) {
        let canon = self.canon.path(path);
        let (dir, name) = split(&canon);
        let d = self.dir_id(dir);
        let n = self.intern(name);
        (d, (n.0, n.1.min(u16::MAX as u32) as u16))
    }

    pub fn file(&mut self, pkg: u32, f: RawFile) {
        if f.path.len() > u16::MAX as usize {
            self.skip();
            return;
        }
        let (dir, name) = self.locate(f.path);
        let (link_off, link_len) = match f.link {
            Some(l) if !l.is_empty() && l.len() <= u16::MAX as usize => {
                let r = self.intern(l);
                (r.0, r.1 as u16)
            }
            _ => (0, 0),
        };
        // Decode the hex digest straight into the shared buffer.
        let digest_off = self.db.digests.len() as u32;
        let hex = f.digest_hex.as_bytes();
        let mut digest_len = 0u8;
        if !hex.is_empty() && hex.len().is_multiple_of(2) && hex.len() <= 510 {
            let ok = hex.chunks_exact(2).all(|c| {
                match std::str::from_utf8(c).ok().and_then(|x| u8::from_str_radix(x, 16).ok()) {
                    Some(b) => {
                        self.db.digests.push(b);
                        true
                    }
                    None => false,
                }
            });
            if ok {
                digest_len = (hex.len() / 2) as u8;
            } else {
                self.db.digests.truncate(digest_off as usize);
            }
        }
        let mut flags = 0;
        for (on, bit) in [
            (f.config, F_CONFIG),
            (f.doc, F_DOC),
            (f.ghost, F_GHOST),
            (f.missingok, F_MISSINGOK),
            (f.installed, F_INSTALLED),
        ] {
            if on {
                flags |= bit;
            }
        }
        self.db.entries.push(Entry {
            dir,
            name_off: name.0,
            name_len: name.1,
            link_off,
            link_len,
            digest_off,
            digest_len,
            flags,
            pkg,
            size: f
                .size
                .filter(|s| *s < u32::MAX as u64)
                .map(|s| s as u32)
                .unwrap_or(u32::MAX),
            mode: f.mode.unwrap_or(0),
            mtime: f.mtime.map(|t| t.min(u32::MAX as u64) as u32).unwrap_or(0),
            verify: f.verify.0,
        });
    }

    /// Re-point a package's entry for `from` to `to` (dpkg diversions).
    pub fn rename(&mut self, pkg: u32, from: &str, to: &str) {
        let canon = self.canon.path(from);
        let (fd, fname) = split(&canon);
        let Some(&fd) = self.dir_ids.get(fd) else { return };
        let fname = fname.to_string();
        let idx = self.db.entries.iter().rposition(|e| {
            e.pkg == pkg
                && e.dir == fd
                && self.db.arena[e.name_off as usize..(e.name_off + e.name_len as u32) as usize] == fname
        });
        if let Some(i) = idx {
            let (d, n) = self.locate(to);
            self.db.entries[i].dir = d;
            (self.db.entries[i].name_off, self.db.entries[i].name_len) = n;
        }
    }

    fn finish(self) -> PkgDb {
        let mut db = self.db;
        // Renumber directories in sorted order so lookups can binary-search.
        let mut order: Vec<u32> = (0..db.dirs.len() as u32).collect();
        order.sort_by(|a, b| db.str_at(db.dirs[*a as usize]).cmp(db.str_at(db.dirs[*b as usize])));
        let mut remap = vec![0u32; order.len()];
        for (new, old) in order.iter().enumerate() {
            remap[*old as usize] = new as u32;
        }
        db.dirs = order.iter().map(|o| db.dirs[*o as usize]).collect();
        for e in &mut db.entries {
            e.dir = remap[e.dir as usize];
        }
        let arena = std::mem::take(&mut db.arena);
        let name = |e: &Entry| &arena[e.name_off as usize..(e.name_off + e.name_len as u32) as usize];
        db.entries
            .sort_by(|a, b| (a.dir, name(a), a.pkg).cmp(&(b.dir, name(b), b.pkg)));
        db.arena = arena;
        db.arena.shrink_to_fit();
        db.entries.shrink_to_fit();
        db.digests.shrink_to_fit();
        db.dirs.shrink_to_fit();
        db
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A tiny database for tests of checks that need ownership.
    pub fn sample(host: &Host, files: &[(&str, &str)]) -> PkgDb {
        let mut b = Builder::new(host);
        let pkg = b.package(Package {
            manager: Manager::Rpm,
            name: "sample".into(),
            id: "sample-1-1.noarch".into(),
            install_time: 1,
            algo: Some(Algo::Sha256),
            key_id: Some("abcd".into()),
            summary: String::new(),
        });
        for (path, hex) in files {
            b.file(
                pkg,
                RawFile {
                    path,
                    digest_hex: hex,
                    size: None,
                    mode: None,
                    mtime: None,
                    link: None,
                    config: false,
                    doc: false,
                    ghost: false,
                    missingok: false,
                    installed: true,
                    verify: Verify::ALL,
                },
            );
        }
        b.db.managers.push(Manager::Rpm);
        b.finish()
    }

    #[test]
    fn lookup_is_sorted_and_multi_owner() {
        let db = sample(
            &Host::with_root("/nonexistent"),
            &[("/usr/bin/b", ""), ("/usr/bin/a", "00"), ("/usr/bin/b", "")],
        );
        assert!(db.owns("/usr/bin/a"));
        assert!(!db.owns("/usr/bin/c"));
        assert_eq!(db.lookup("/usr/bin/b").count(), 2);
        let paths: Vec<String> = db.files().map(|f| f.path()).collect();
        assert_eq!(paths, vec!["/usr/bin/a", "/usr/bin/b", "/usr/bin/b"]);
        assert!(db.owns("/usr/bin/b") && !db.owns("/usr/bin") && !db.owns("/usr/sbin/a"));
        assert_eq!(db.lookup("/usr/bin/a").next().unwrap().digest, &[0]);
    }
}
