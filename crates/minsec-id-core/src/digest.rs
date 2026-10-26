//! File digests in the algorithms package managers record. Reading is
//! sequential and drops the pages afterwards, so a full scan does not evict
//! the host's working set from the page cache.

use md5::Md5;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algo {
    Md5,
    Sha256,
    Sha384,
    Sha512,
}

impl Algo {
    /// rpm's `FILEDIGESTALGO` numbering (RFC 4880 hash ids).
    pub fn from_rpm(n: u32) -> Option<Self> {
        match n {
            1 => Some(Algo::Md5),
            8 => Some(Algo::Sha256),
            9 => Some(Algo::Sha384),
            10 => Some(Algo::Sha512),
            _ => None,
        }
    }

    pub fn digest_len(&self) -> usize {
        match self {
            Algo::Md5 => 16,
            Algo::Sha256 => 32,
            Algo::Sha384 => 48,
            Algo::Sha512 => 64,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Algo::Md5 => "md5",
            Algo::Sha256 => "sha256",
            Algo::Sha384 => "sha384",
            Algo::Sha512 => "sha512",
        }
    }
}

enum Hasher {
    Md5(Md5),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(a: Algo) -> Self {
        match a {
            Algo::Md5 => Hasher::Md5(Md5::new()),
            Algo::Sha256 => Hasher::Sha256(Sha256::new()),
            Algo::Sha384 => Hasher::Sha384(Sha384::new()),
            Algo::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(b),
            Hasher::Sha256(h) => h.update(b),
            Hasher::Sha384(h) => h.update(b),
            Hasher::Sha512(h) => h.update(b),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

pub fn bytes(a: Algo, data: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(a);
    h.update(data);
    h.finish()
}

/// Digest a file without following a final symlink.
pub fn file(a: Algo, path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let fd = f.as_raw_fd();
    // SAFETY: advisory calls on a valid descriptor; failures are harmless.
    unsafe {
        libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
    let mut h = Hasher::new(a);
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    unsafe {
        libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
    }
    Ok(h.finish())
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(hex(&bytes(Algo::Md5, b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&bytes(Algo::Sha256, b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(unhex("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(unhex("0").is_none() && unhex("zz").is_none());
    }

    #[test]
    fn file_digest_matches_bytes() {
        let p = std::env::temp_dir().join(format!("minsec-id-digest-{}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(file(Algo::Sha256, &p).unwrap(), bytes(Algo::Sha256, b"abc"));
        std::fs::remove_file(p).unwrap();
    }
}
