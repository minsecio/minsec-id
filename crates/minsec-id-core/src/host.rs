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

    /// The current boot's id, used to scope findings that only make sense for
    /// one boot (kernel taint is sticky until reboot).
    pub fn boot_id(&self) -> Option<String> {
        self.read_opt("/proc/sys/kernel/random/boot_id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_into_root() {
        let h = Host::with_root("/tmp/fixture");
        assert_eq!(h.path("/proc/x"), PathBuf::from("/tmp/fixture/proc/x"));
        assert_eq!(Host::default().path("/proc/x"), PathBuf::from("/proc/x"));
    }
}
