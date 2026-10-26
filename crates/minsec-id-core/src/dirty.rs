//! `dirty.list`: system files the daemon saw opened for writing outside a
//! package transaction, one path per line. The next full scan hashes them
//! whatever their ctime says, then forgets them.
//!
//! The daemon appends (opening the file each time); the scanner claims the
//! list by renaming it, so writes recorded during a scan go to a new list
//! for the scan after. A scan that fails leaves its claim to be merged next
//! time.

use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const FILE: &str = "dirty.list";
const CLAIMED: &str = "dirty.list.claimed";

pub fn append(state_dir: &Path, paths: &[String]) -> std::io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut buf = String::new();
    for p in paths {
        // Paths come from the kernel; a newline would split a record.
        if !p.contains('\n') {
            buf.push_str(p);
            buf.push('\n');
        }
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(state_dir.join(FILE))?
        .write_all(buf.as_bytes())
}

pub struct Claimed {
    pub paths: BTreeSet<String>,
    file: Option<PathBuf>,
}

impl Claimed {
    /// The scan used the list: delete it.
    pub fn done(self) {
        if let Some(f) = self.file {
            let _ = std::fs::remove_file(f);
        }
    }
}

pub fn claim(state_dir: &Path) -> Claimed {
    let (live, claimed) = (state_dir.join(FILE), state_dir.join(CLAIMED));
    let mut text = std::fs::read_to_string(&claimed).unwrap_or_default();
    if let Ok(new) = std::fs::read_to_string(&live) {
        text.push_str(&new);
        // Merge into the claimed file before removing the live one, so a
        // crash between the two loses nothing.
        if std::fs::write(&claimed, &text).is_ok() {
            let _ = std::fs::remove_file(&live);
        }
    }
    Claimed {
        paths: text.lines().filter(|l| l.starts_with('/')).map(String::from).collect(),
        file: claimed.exists().then_some(claimed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_claim_done() {
        let dir = std::env::temp_dir().join(format!("minsec-id-dirty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(claim(&dir).paths.is_empty());
        append(&dir, &["/usr/bin/a".into(), "/usr/bin/b".into()]).unwrap();
        let c = claim(&dir);
        assert_eq!(c.paths.len(), 2);
        // A write during the scan goes to a new list; an unfinished claim merges.
        append(&dir, &["/usr/bin/c".into()]).unwrap();
        drop(c);
        let c = claim(&dir);
        assert_eq!(c.paths.len(), 3);
        c.done();
        assert!(claim(&dir).paths.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
