//! `exe-unowned`: executables in the system binary directories, shared
//! libraries at the top of the library directories, and setuid, setgid, or
//! file-capability binaries there, that no package installed. A stat-only
//! walk; `/usr/local` and `/opt` are unowned by design and not walked, and
//! files from merged system extensions are reported by `sysext`.

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::{Canon, Host};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub struct ExeUnowned;

/// (directory, recurse) for executables.
const BIN_DIRS: &[(&str, bool)] = &[("/usr/bin", false), ("/usr/sbin", false), ("/usr/libexec", true)];
/// Top-level shared libraries only: the loader's default search path.
const LIB_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
];
const MAX_DEPTH: u32 = 6;

fn has_file_caps(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let name = c"security.capability";
    // SAFETY: valid C strings; a null buffer with size 0 asks for the length.
    let r = unsafe { libc::lgetxattr(c.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    r > 0
}

fn walk(host: &Host, dir: &str, recurse: bool, depth: u32, out: &mut Vec<(String, std::fs::Metadata)>) {
    let Ok(rd) = std::fs::read_dir(host.path(dir)) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        let p = format!("{dir}/{name}");
        let Ok(md) = e.metadata() else { continue }; // lstat
        if md.is_dir() && recurse && depth < MAX_DEPTH {
            walk(host, &p, recurse, depth + 1, out);
        } else if md.is_file() {
            out.push((p, md));
        }
    }
}

impl Check for ExeUnowned {
    fn id(&self) -> &'static str {
        "exe-unowned"
    }

    fn description(&self) -> &'static str {
        "executables, libraries, and setuid/capability binaries in system paths that no package owns"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!crate::pkgdb::has_rpm(host) && !crate::pkgdb::has_dpkg(host)).then(|| "no rpm or dpkg database".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.owned()?;
        let mut canon = Canon::new(host);
        let mut seen_dirs = std::collections::BTreeSet::new();
        let mut candidates = Vec::new();
        for (dir, recurse) in BIN_DIRS {
            let d = canon.resolve_dir(dir);
            if seen_dirs.insert(d.clone()) {
                walk(host, &d, *recurse, 0, &mut candidates);
            }
        }
        let bin_count = candidates.len();
        for dir in LIB_DIRS {
            let d = canon.resolve_dir(dir);
            if seen_dirs.insert(d.clone()) {
                walk(host, &d, false, 0, &mut candidates);
            }
        }
        // Files a merged system extension provides are the `sysext` check's
        // to report, as one extension, unless they are setuid or carry
        // capabilities.
        let layers = crate::sysext::Layers::usr(host, &crate::procfs::mounts(host));
        let mut out = Vec::new();
        for (i, (p, md)) in candidates.into_iter().enumerate() {
            let in_bin = i < bin_count;
            let mode = md.mode();
            let setid = mode & (libc::S_ISUID | libc::S_ISGID) != 0;
            let exec = mode & 0o111 != 0;
            let is_lib = p.contains(".so");
            if !(setid || (in_bin && exec) || (!in_bin && is_lib)) {
                continue;
            }
            if db.owns(&p) {
                continue;
            }
            let caps = has_file_caps(&host.path(&p));
            if !setid && !caps && layers.as_ref().is_some_and(|l| l.is_extension_file(&p, &md)) {
                continue;
            }
            let (sev, what) = if setid {
                (Severity::High, "setuid/setgid executable")
            } else if caps {
                (Severity::High, "executable with file capabilities")
            } else if in_bin {
                (Severity::Medium, "executable")
            } else {
                (Severity::Medium, "shared library")
            };
            out.push(
                Finding::new(self.id(), sev, &p, &format!("{}:{}", md.size(), md.mtime()))
                    .message(format!("{what} {p} is not owned by any package"))
                    .detail(serde_json::json!({
                        "mode": format!("{:04o}", mode & 0o7777),
                        "uid": md.uid(),
                        "size": md.size(),
                        "mtime": md.mtime(),
                        "ctime": md.ctime(),
                        "file_caps": caps,
                    })),
            );
        }
        Ok(out)
    }
}
