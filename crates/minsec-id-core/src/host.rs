//! The host being examined. Every probe reads through a `Host` so tests can
//! point it at a fixture tree (`--root`) instead of the live `/proc` and `/sys`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Host {
    root: PathBuf,
}

impl Default for Host {
    fn default() -> Self {
        Self { root: "/".into() }
    }
}

impl Host {
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Map an absolute host path into the root.
    pub fn path(&self, p: impl AsRef<Path>) -> PathBuf {
        let p = p.as_ref();
        self.root.join(p.strip_prefix("/").unwrap_or(p))
    }

    pub fn exists(&self, p: impl AsRef<Path>) -> bool {
        self.path(p).exists()
    }

    pub fn read(&self, p: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(p))
    }

    /// Read a small text file and trim surrounding whitespace.
    pub fn read_trim(&self, p: impl AsRef<Path>) -> std::io::Result<String> {
        Ok(std::fs::read_to_string(self.path(p))?.trim().to_string())
    }

    /// Like `read_trim`, but absent or unreadable is `None`.
    pub fn read_opt(&self, p: impl AsRef<Path>) -> Option<String> {
        self.read_trim(p).ok()
    }

    /// Names of the entries in a directory, sorted; absent is empty.
    pub fn list_dir(&self, p: impl AsRef<Path>) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.path(p))
            .map(|rd| {
                rd.filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Whether `p` (in the root) is a symlink, and its target if so.
    pub fn read_link(&self, p: impl AsRef<Path>) -> Option<String> {
        let full = self.path(p);
        let md = std::fs::symlink_metadata(&full).ok()?;
        if !md.file_type().is_symlink() {
            return None;
        }
        std::fs::read_link(&full)
            .ok()
            .and_then(|t| t.into_os_string().into_string().ok())
    }

    /// The current boot's id, used to scope findings that only make sense for
    /// one boot (kernel taint is sticky until reboot).
    pub fn boot_id(&self) -> Option<String> {
        self.read_opt("/proc/sys/kernel/random/boot_id")
    }
}

/// Canonicalizes host paths against a `Host`, resolving symlinked
/// directories (`/bin` → `/usr/bin` on merged-/usr systems) inside the root.
/// Memoized per directory, so each distinct directory costs one lstat.
pub struct Canon<'a> {
    host: &'a Host,
    memo: std::collections::HashMap<String, String>,
}

impl<'a> Canon<'a> {
    pub fn new(host: &'a Host) -> Self {
        Self {
            host,
            memo: Default::default(),
        }
    }

    /// Canonical form of a host-absolute path whose final component is not
    /// resolved (it may itself be a symlink the caller wants to inspect).
    pub fn path(&mut self, p: &str) -> String {
        match p.rsplit_once('/') {
            Some(("", name)) => format!("/{name}"),
            Some((dir, name)) => {
                let d = self.dir(dir, 0);
                if d == "/" {
                    format!("/{name}")
                } else {
                    format!("{d}/{name}")
                }
            }
            None => p.to_string(),
        }
    }

    /// Canonical form of a directory, every component resolved.
    pub fn resolve_dir(&mut self, dir: &str) -> String {
        self.dir(dir.trim_end_matches('/'), 0)
    }

    fn dir(&mut self, dir: &str, depth: u32) -> String {
        if dir.is_empty() || dir == "/" {
            return "/".into();
        }
        if let Some(c) = self.memo.get(dir) {
            return c.clone();
        }
        let (parent, name) = dir.rsplit_once('/').unwrap_or(("", dir));
        let parent = self.dir(parent, depth);
        let cand = if parent == "/" {
            format!("/{name}")
        } else {
            format!("{parent}/{name}")
        };
        let out = match self.host.read_link(&cand) {
            Some(target) if depth < 40 => {
                let abs = if target.starts_with('/') {
                    target
                } else {
                    format!("{parent}/{target}")
                };
                let norm = normalize(&abs);
                self.dir(&norm, depth + 1)
            }
            _ => cand,
        };
        self.memo.insert(dir.to_string(), out.clone());
        out
    }
}

/// Lexically normalize an absolute path: drop `.`, resolve `..`, collapse `//`.
pub fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_merged_usr() {
        let root = std::env::temp_dir().join(format!("minsec-id-canon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(root.join("usr/lib/x86_64-linux-gnu")).unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        std::os::unix::fs::symlink("/usr/lib", root.join("lib")).unwrap();
        let h = Host::with_root(&root);
        let mut c = Canon::new(&h);
        assert_eq!(c.path("/bin/ls"), "/usr/bin/ls");
        assert_eq!(
            c.path("/lib/x86_64-linux-gnu/libc.so.6"),
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        );
        assert_eq!(c.path("/usr/sbin/x"), "/usr/sbin/x");
        assert_eq!(c.path("/etc"), "/etc");
        assert_eq!(normalize("/a/./b/../c//d"), "/a/c/d");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maps_into_root() {
        let h = Host::with_root("/tmp/fixture");
        assert_eq!(h.path("/proc/x"), PathBuf::from("/tmp/fixture/proc/x"));
        assert_eq!(Host::default().path("/proc/x"), PathBuf::from("/proc/x"));
    }
}
