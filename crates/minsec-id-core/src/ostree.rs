//! Reading ostree repositories, where flatpak and the image-based systems
//! (Fedora CoreOS, Silverblue, bootc) keep their trees. Objects are
//! content-addressed: a metadata object (commit, dirtree, dirmeta) is named
//! by the SHA-256 of its bytes, and a file object by the SHA-256 of a header
//! (ownership, mode, symlink target, xattrs) followed by its content. A tree
//! can be verified from the repository alone, with no database of our own.
//!
//! Only the local repository modes are read: `bare` (ostree systems: real
//! ownership and xattrs) and `bare-user-only` (flatpak: owned by the
//! repository's user, no xattrs).

use crate::digest::{self, Algo};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub type Csum = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Bare,
    BareUserOnly,
}

pub struct Repo {
    pub dir: PathBuf,
    pub mode: Mode,
}

pub struct Commit {
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub root_tree: Csum,
    pub root_meta: Csum,
}

pub struct DirTree {
    pub files: Vec<(String, Csum)>,
    /// (name, dirtree, dirmeta)
    pub dirs: Vec<(String, Csum, Csum)>,
}

pub fn hex(c: &Csum) -> String {
    digest::hex(c)
}

pub fn parse_csum(s: &str) -> Option<Csum> {
    digest::unhex(s)?.try_into().ok()
}

fn csum_of(b: &[u8]) -> Option<Csum> {
    b.try_into().ok()
}

impl Repo {
    /// Open the repository at `dir` (the directory holding `config` and
    /// `objects`).
    pub fn open(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let dir = dir.into();
        let config = std::fs::read_to_string(dir.join("config"))
            .map_err(|e| anyhow::anyhow!("{}/config: {e}", dir.display()))?;
        let mode = config
            .lines()
            .filter_map(|l| l.trim().strip_prefix("mode"))
            .filter_map(|r| r.trim_start().strip_prefix('='))
            .map(|v| v.trim().to_string())
            .next()
            .unwrap_or_else(|| "bare".into());
        let mode = match mode.as_str() {
            "bare" => Mode::Bare,
            "bare-user-only" => Mode::BareUserOnly,
            m => anyhow::bail!("{}: repository mode {m} is not supported", dir.display()),
        };
        Ok(Self { dir, mode })
    }

    pub fn object_path(&self, c: &Csum, kind: &str) -> PathBuf {
        let h = hex(c);
        self.dir
            .join("objects")
            .join(&h[..2])
            .join(format!("{}.{kind}", &h[2..]))
    }

    /// A metadata object, verified against its name.
    fn meta(&self, c: &Csum, kind: &str) -> anyhow::Result<Vec<u8>> {
        let p = self.object_path(c, kind);
        let data = std::fs::read(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
        if digest::bytes(Algo::Sha256, &data) != c {
            anyhow::bail!("{}: content does not match its checksum", p.display());
        }
        Ok(data)
    }

    pub fn commit(&self, c: &Csum) -> anyhow::Result<Commit> {
        let data = self.meta(c, "commit")?;
        let v = Gv::new(&data, "(a{sv}aya(say)sstayay)");
        let f = v
            .fields()
            .ok_or_else(|| anyhow::anyhow!("commit {}: malformed", hex(c)))?;
        let bad = || anyhow::anyhow!("commit {}: malformed", hex(c));
        let timestamp = f[5].u64_be().ok_or_else(bad)?;
        let root_tree = csum_of(f[6].data).ok_or_else(bad)?;
        let root_meta = csum_of(f[7].data).ok_or_else(bad)?;
        Ok(Commit {
            data,
            timestamp,
            root_tree,
            root_meta,
        })
    }

    pub fn dirtree(&self, c: &Csum) -> anyhow::Result<DirTree> {
        let data = self.meta(c, "dirtree")?;
        let bad = || anyhow::anyhow!("dirtree {}: malformed", hex(c));
        let f = Gv::new(&data, "(a(say)a(sayay))").fields().ok_or_else(bad)?;
        let mut files = Vec::new();
        for e in f[0].items().ok_or_else(bad)? {
            let ef = e.fields().ok_or_else(bad)?;
            files.push((
                ef[0].str().ok_or_else(bad)?.to_string(),
                csum_of(ef[1].data).ok_or_else(bad)?,
            ));
        }
        let mut dirs = Vec::new();
        for e in f[1].items().ok_or_else(bad)? {
            let ef = e.fields().ok_or_else(bad)?;
            dirs.push((
                ef[0].str().ok_or_else(bad)?.to_string(),
                csum_of(ef[1].data).ok_or_else(bad)?,
                csum_of(ef[2].data).ok_or_else(bad)?,
            ));
        }
        Ok(DirTree { files, dirs })
    }

    /// Signatures in a commit's detached metadata (`ostree.gpgsigs`), if any.
    pub fn gpg_signatures(&self, c: &Csum) -> Vec<Vec<u8>> {
        let Ok(data) = std::fs::read(self.object_path(c, "commitmeta")) else {
            return Vec::new();
        };
        let v = Gv::new(&data, "a{sv}");
        let Some(sigs) = v.lookup("ostree.gpgsigs").filter(|s| s.ty == "aay") else {
            return Vec::new();
        };
        sigs.items()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.data.to_vec())
            .collect()
    }

    /// Walk a tree depth first, calling `f(relative path, entry)` for each
    /// file (`Some(checksum)`) and directory (`None`). Paths are relative to
    /// the tree's root, without a leading slash.
    pub fn walk(&self, tree: &Csum, f: &mut dyn FnMut(&str, Option<&Csum>)) -> anyhow::Result<()> {
        self.walk_in(tree, "", f, 0)
    }

    fn walk_in(
        &self,
        tree: &Csum,
        prefix: &str,
        f: &mut dyn FnMut(&str, Option<&Csum>),
        depth: u32,
    ) -> anyhow::Result<()> {
        if depth > 256 {
            anyhow::bail!("dirtree {}: nested too deep", hex(tree));
        }
        let t = self.dirtree(tree)?;
        for (name, c) in &t.files {
            f(&join(prefix, name), Some(c));
        }
        for (name, sub, _) in &t.dirs {
            let p = join(prefix, name);
            f(&p, None);
            self.walk_in(sub, &p, f, depth + 1)?;
        }
        Ok(())
    }

    /// The content checksum of a file (regular or symlink) on disk, as this
    /// repository's mode would compute it.
    pub fn file_checksum(&self, path: &Path) -> std::io::Result<Csum> {
        let md = std::fs::symlink_metadata(path)?;
        let (uid, gid, xattrs) = match self.mode {
            Mode::BareUserOnly => (0, 0, Vec::new()),
            Mode::Bare => (md.uid(), md.gid(), xattrs(path)?),
        };
        let target = if md.file_type().is_symlink() {
            std::fs::read_link(path)?.into_os_string().into_encoded_bytes()
        } else {
            Vec::new()
        };
        let header = file_header(uid, gid, md.mode(), &target, &xattrs);
        let d = if md.file_type().is_symlink() {
            digest::bytes(Algo::Sha256, &header)
        } else {
            digest::file_with_prefix(Algo::Sha256, &header, path)?
        };
        Ok(d.try_into().expect("sha256 is 32 bytes"))
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// A file's extended attributes, sorted by name, as ostree records them.
fn xattrs(path: &Path) -> std::io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut names = vec![0u8; 4096];
    // SAFETY: valid NUL-terminated path and a buffer of the given length.
    let n = unsafe { libc::llistxattr(c.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOTSUP) => Ok(Vec::new()),
            _ => Err(e),
        };
    }
    let mut out = Vec::new();
    for name in names[..n as usize].split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let cn = std::ffi::CString::new(name)?;
        let mut val = vec![0u8; 65536];
        // SAFETY: as above.
        let m = unsafe { libc::lgetxattr(c.as_ptr(), cn.as_ptr(), val.as_mut_ptr().cast(), val.len()) };
        if m < 0 {
            return Err(std::io::Error::last_os_error());
        }
        val.truncate(m as usize);
        // ostree's bytestrings keep the terminating NUL.
        let mut nm = name.to_vec();
        nm.push(0);
        out.push((nm, val));
    }
    out.sort();
    Ok(out)
}

/// The header ostree hashes before a file's content: the serialized
/// `(uuuusa(ayay))` of uid, gid, mode, rdev (0), symlink target, and
/// xattrs, numbers big-endian, preceded by its length (big-endian u32) and
/// four bytes of padding.
pub fn file_header(uid: u32, gid: u32, mode: u32, target: &[u8], xattrs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for n in [uid, gid, mode, 0] {
        body.extend_from_slice(&n.to_be_bytes());
    }
    body.extend_from_slice(target);
    body.push(0);
    let string_end = body.len();
    let elems: Vec<Vec<u8>> = xattrs
        .iter()
        .map(|(n, v)| {
            let mut e = n.clone();
            e.extend_from_slice(v);
            frame(e, &[n.len()])
        })
        .collect();
    let mut arr = Vec::new();
    let mut ends = Vec::new();
    for e in &elems {
        arr.extend_from_slice(e);
        ends.push(arr.len());
    }
    body.extend_from_slice(&frame(arr, &ends));
    let v = frame(body, &[string_end]);
    let mut out = Vec::with_capacity(8 + v.len());
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&v);
    out
}

/// GVariant's framing-offset size for a container of `n` bytes.
fn offset_size(n: usize) -> usize {
    match n {
        0 => 0,
        1..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xffff_ffff => 4,
        _ => 8,
    }
}

/// Append framing offsets to a container's content: in order for an array,
/// and (for the single offset ostree's headers need) a tuple alike.
fn frame(mut content: Vec<u8>, offsets: &[usize]) -> Vec<u8> {
    if offsets.is_empty() {
        return content;
    }
    let len = content.len();
    let w = [1, 2, 4, 8]
        .into_iter()
        .find(|&w| offset_size(len + offsets.len() * w) <= w)
        .unwrap_or(8);
    for &o in offsets {
        content.extend_from_slice(&(o as u64).to_le_bytes()[..w]);
    }
    content
}

/// A serialized GVariant of a known type: just enough of the format to read
/// ostree's objects. Malformed input yields `None`, never a panic.
#[derive(Debug, Clone, Copy)]
pub struct Gv<'a> {
    pub data: &'a [u8],
    pub ty: &'a str,
}

/// Length of the first complete type in `t`.
fn type_len(t: &str) -> usize {
    let b = t.as_bytes();
    match b.first() {
        Some(b'a') | Some(b'm') => 1 + type_len(&t[1..]),
        Some(b'(') | Some(b'{') => {
            let mut i = 1;
            while i < b.len() && b[i] != b')' && b[i] != b'}' {
                i += type_len(&t[i..]).max(1);
            }
            i + 1
        }
        Some(_) => 1,
        None => 0,
    }
}

fn members(t: &str) -> Vec<&str> {
    let inner = &t[1..t.len().saturating_sub(1).max(1)];
    let mut out = Vec::new();
    let mut i = 0;
    while i < inner.len() {
        let l = type_len(&inner[i..]).max(1);
        out.push(&inner[i..(i + l).min(inner.len())]);
        i += l;
    }
    out
}

fn alignment(t: &str) -> usize {
    match t.as_bytes().first() {
        Some(b'n' | b'q') => 2,
        Some(b'i' | b'u' | b'h') => 4,
        Some(b'x' | b't' | b'd' | b'v') => 8,
        Some(b'a' | b'm') => alignment(&t[1..]),
        Some(b'(' | b'{') => members(t).into_iter().map(alignment).max().unwrap_or(1),
        _ => 1,
    }
}

fn fixed_size(t: &str) -> Option<usize> {
    match t.as_bytes().first()? {
        b'y' | b'b' => Some(1),
        b'n' | b'q' => Some(2),
        b'i' | b'u' | b'h' => Some(4),
        b'x' | b't' | b'd' => Some(8),
        b'(' | b'{' => {
            let mut size = 0;
            for m in members(t) {
                size = round_up(size, alignment(m)) + fixed_size(m)?;
            }
            Some(round_up(size, alignment(t)).max(1))
        }
        _ => None,
    }
}

fn round_up(n: usize, a: usize) -> usize {
    n.div_ceil(a) * a
}

fn read_offset(b: &[u8]) -> usize {
    let mut v = [0u8; 8];
    v[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(v) as usize
}

impl<'a> Gv<'a> {
    pub fn new(data: &'a [u8], ty: &'a str) -> Self {
        Self { data, ty }
    }

    pub fn str(&self) -> Option<&'a str> {
        let (last, s) = self.data.split_last()?;
        if *last != 0 {
            return None;
        }
        std::str::from_utf8(s).ok()
    }

    /// A number ostree stored big-endian.
    pub fn u64_be(&self) -> Option<u64> {
        Some(u64::from_be_bytes(self.data.get(..8)?.try_into().ok()?))
    }

    /// The members of a tuple or dict entry.
    pub fn fields(&self) -> Option<Vec<Gv<'a>>> {
        let ms = members(self.ty);
        let n = self.data.len();
        let w = offset_size(n);
        let mut fo_end = n;
        let mut pos = 0;
        let mut out = Vec::with_capacity(ms.len());
        for (i, m) in ms.iter().enumerate() {
            pos = round_up(pos, alignment(m));
            let end = match fixed_size(m) {
                Some(s) => pos + s,
                None if i == ms.len() - 1 => fo_end,
                None => {
                    fo_end = fo_end.checked_sub(w)?;
                    read_offset(self.data.get(fo_end..fo_end + w)?)
                }
            };
            if pos > end || end > n {
                return None;
            }
            out.push(Gv::new(&self.data[pos..end], m));
            pos = end;
        }
        Some(out)
    }

    /// The elements of an array.
    pub fn items(&self) -> Option<Vec<Gv<'a>>> {
        let et = self.ty.get(1..)?;
        let n = self.data.len();
        if n == 0 {
            return Some(Vec::new());
        }
        if let Some(s) = fixed_size(et) {
            if !n.is_multiple_of(s) {
                return None;
            }
            return Some(self.data.chunks(s).map(|c| Gv::new(c, et)).collect());
        }
        let w = offset_size(n);
        let table = read_offset(self.data.get(n - w..)?);
        if table > n || !(n - table).is_multiple_of(w) {
            return None;
        }
        let count = (n - table) / w;
        let al = alignment(et);
        let mut start = 0;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let o = table + i * w;
            let end = read_offset(self.data.get(o..o + w)?);
            if start > end || end > table {
                return None;
            }
            out.push(Gv::new(&self.data[start..end], et));
            start = round_up(end, al);
        }
        Some(out)
    }

    /// The value inside a variant.
    pub fn variant(&self) -> Option<Gv<'a>> {
        let sep = self.data.iter().rposition(|&b| b == 0)?;
        let ty = std::str::from_utf8(&self.data[sep + 1..]).ok()?;
        if type_len(ty) != ty.len() || ty.is_empty() {
            return None;
        }
        Some(Gv::new(&self.data[..sep], ty))
    }

    /// Look up `key` in an `a{sv}`.
    pub fn lookup(&self, key: &str) -> Option<Gv<'a>> {
        self.items()?.into_iter().find_map(|e| {
            let f = e.fields()?;
            (f.first()?.str()? == key).then(|| f.get(1)?.variant())?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_ostree() {
        // A 0644 regular file owned by root, no xattrs, from a real
        // bare-user-only repository: sha256(header + content) is its name.
        let h = file_header(0, 0, 0o100644, b"", &[]);
        assert_eq!(&h[..8], &[0, 0, 0, 18, 0, 0, 0, 0]);
        assert_eq!(h.len(), 8 + 18);
        assert_eq!(&h[8 + 12..8 + 16], &[0, 0, 0, 0], "rdev");
        assert_eq!(h[8 + 17], 17, "framing offset: end of the symlink target");
        // With an xattr: (ayay) elements framed, then the array framed.
        let x = file_header(0, 0, 0o100644, b"", &[(b"user.a\0".to_vec(), b"v".to_vec())]);
        let v = Gv::new(&x[8..], "(uuuusa(ayay))");
        let f = v.fields().unwrap();
        assert_eq!(f[4].str(), Some(""));
        let xs = f[5].items().unwrap();
        assert_eq!(xs.len(), 1);
        let kv = xs[0].fields().unwrap();
        assert_eq!(kv[0].data, b"user.a\0");
        assert_eq!(kv[1].data, b"v");
    }

    #[test]
    fn reads_variants() {
        // a{sv} {"k": <"v">}: entry = "k\0", padding to the variant's
        // 8-byte alignment, "v\0" + "\0s", framing (the key's end: 2);
        // then the array's framing: the entry's end.
        let entry: &[u8] = b"k\0\0\0\0\0\0\0v\0\0s\x02";
        let mut a = entry.to_vec();
        a.push(entry.len() as u8);
        let v = Gv::new(&a, "a{sv}");
        assert_eq!(v.lookup("k").unwrap().str(), Some("v"));
        assert!(v.lookup("x").is_none());
        // Truncated or garbage input is None, not a panic.
        for bad in [&b""[..], b"\xff", b"k\0\xff", b"\x00\x00\x09"] {
            let _ = Gv::new(bad, "(a(say)a(sayay))").fields().map(|f| f[0].items());
            let _ = Gv::new(bad, "a{sv}").lookup("k");
        }
        assert_eq!(type_len("(a{sv}aya(say)sstayay)"), 22);
        assert_eq!(members("(a(say)a(sayay))"), vec!["a(say)", "a(sayay)"]);
        assert_eq!(fixed_size("(ut)"), Some(16));
        assert_eq!(fixed_size("(say)"), None);
    }

    /// Against the host's flatpak repository, when there is one: every
    /// deployed commit's tree reads, and sampled file objects hash to their
    /// names.
    #[test]
    fn host_flatpak_repo() {
        let Ok(repo) = Repo::open("/var/lib/flatpak/repo") else {
            return;
        };
        let mut checked = 0;
        for kind in ["app", "runtime"] {
            for d in std::fs::read_dir(repo.dir.join("..").join(kind))
                .into_iter()
                .flatten()
                .flatten()
            {
                for arch in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                    for br in std::fs::read_dir(arch.path()).into_iter().flatten().flatten() {
                        let Ok(c) = std::fs::read_link(br.path().join("active")) else {
                            continue;
                        };
                        let Some(c) = parse_csum(&c.to_string_lossy()) else {
                            continue;
                        };
                        let commit = repo.commit(&c).unwrap();
                        let mut n = 0;
                        repo.walk(&commit.root_tree, &mut |_, f| {
                            if let Some(f) = f {
                                n += 1;
                                if n % 97 == 0 {
                                    let p = repo.object_path(f, "file");
                                    if let Ok(got) = repo.file_checksum(&p) {
                                        assert_eq!(&got, f, "{}", p.display());
                                        checked += 1;
                                    }
                                }
                            }
                        })
                        .unwrap();
                    }
                }
            }
        }
        eprintln!("verified {checked} sampled objects");
    }
}
