//! rpm: one `rpm -qa --queryformat` pass streams every header. rpm checks
//! header digests and signatures as it reads them; its warnings on stderr
//! (a BAD signature means the rpmdb was edited) are kept for the checks.

use super::{Builder, Manager, Package, RawFile, Verify};
use crate::digest::Algo;
use crate::host::Host;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

const HEADER: &str = "@@\t";

const QUERY: &str = "@@\t%{NAME}\t%{NEVRA}\t%{INSTALLTIME}\t%{FILEDIGESTALGO}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\t%{SUMMARY}\n\
[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILESIZES}\t%{FILEMODES}\t%{FILEMTIMES}\t%{FILEFLAGS}\t%{FILESTATES}\t%{FILEVERIFYFLAGS}\t%{FILELINKTOS}\n]";

// rpmfileAttrs and rpmfileState values.
const RPMFILE_CONFIG: u32 = 1 << 0;
const RPMFILE_DOC: u32 = 1 << 1;
const RPMFILE_MISSINGOK: u32 = 1 << 3;
const RPMFILE_GHOST: u32 = 1 << 6;
const RPMFILE_STATE_NORMAL: u32 = 0;

/// The rpm binary; `MINSEC_ID_RPM` substitutes a recording in tests.
fn rpm_command(host: &Host) -> Command {
    let bin = std::env::var("MINSEC_ID_RPM").unwrap_or_else(|_| "rpm".into());
    let mut c = Command::new(bin);
    if host.root() != std::path::Path::new("/") {
        c.arg("--root").arg(host.root());
    }
    c
}

pub(super) fn load(host: &Host, b: &mut Builder) -> anyhow::Result<()> {
    let mut child = rpm_command(host)
        .args(["-qa", "--queryformat", QUERY])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("rpm: {e}"))?;
    let mut stderr = child.stderr.take().expect("piped");
    let errs = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    parse(
        BufReader::with_capacity(256 * 1024, child.stdout.take().expect("piped")),
        b,
    )?;
    let status = child.wait()?;
    let errs = errs.join().unwrap_or_default();
    for l in errs.lines().filter(|l| !l.trim().is_empty()) {
        b.warn(l.trim().to_string());
    }
    if !status.success() {
        anyhow::bail!("rpm -qa exited with {status}: {}", errs.lines().next().unwrap_or(""));
    }
    Ok(())
}

pub(super) fn parse(mut r: impl BufRead, b: &mut Builder) -> anyhow::Result<()> {
    let mut pkg: Option<u32> = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let Ok(l) = std::str::from_utf8(&line) else {
            b.skip();
            continue;
        };
        let l = l.strip_suffix('\n').unwrap_or(l);
        if let Some(h) = l.strip_prefix(HEADER) {
            pkg = header(h).map(|p| b.package(p));
            if pkg.is_none() {
                b.skip();
            }
            continue;
        }
        let Some(p) = pkg else {
            b.skip();
            continue;
        };
        let mut f = [""; 9];
        let mut n = 0;
        for (i, part) in l.splitn(9, '\t').enumerate() {
            f[i] = part;
            n = i + 1;
        }
        if n < 9 || !f[0].starts_with('/') {
            b.skip();
            continue;
        }
        let flags: u32 = f[5].parse().unwrap_or(0);
        let state: u32 = f[6].parse().unwrap_or(RPMFILE_STATE_NORMAL);
        b.file(
            p,
            RawFile {
                path: f[0],
                digest_hex: f[1],
                size: f[2].parse().ok(),
                mode: f[3].parse().ok(),
                mtime: f[4].parse().ok(),
                link: Some(f[8]),
                config: flags & RPMFILE_CONFIG != 0,
                doc: flags & RPMFILE_DOC != 0,
                ghost: flags & RPMFILE_GHOST != 0,
                missingok: flags & RPMFILE_MISSINGOK != 0,
                installed: state == RPMFILE_STATE_NORMAL,
                verify: f[7].parse().map(Verify::from_rpm).unwrap_or(Verify::ALL),
            },
        );
    }
    Ok(())
}

fn header(h: &str) -> Option<Package> {
    let f: Vec<&str> = h.splitn(7, '\t').collect();
    if f.len() < 7 {
        return None;
    }
    let none = |s: &str| s == "(none)" || s.is_empty();
    let key_id = [f[4], f[5]].iter().find(|s| !none(s)).map(|s| {
        s.rsplit_once("Key ID ")
            .map(|(_, k)| k.trim().to_string())
            .unwrap_or_else(|| s.to_string())
    });
    Some(Package {
        manager: Manager::Rpm,
        name: f[0].into(),
        id: f[1].into(),
        install_time: f[2].parse().unwrap_or(0),
        algo: f[3].parse().ok().and_then(Algo::from_rpm),
        key_id,
        summary: f[6].into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = "@@\tbash\tbash-5.3.9-3.fc44.x86_64\t1778192531\t8\tRSA/SHA256, Tue 20 Jan 2026 02:22:11 AM CST, Key ID dbfcf71c6d9f90a6\t(none)\tThe GNU Bourne Again shell\n\
/etc/skel/.bashrc\tc5566fb3645f14ef9f8fd2bcb0ad468bf6ef8a0c51a55633cb57f4c3e572aac6\t522\t33188\t1768521600\t17\t0\t4294967295\t\n\
/usr/bin/bash\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\t3\t33261\t1768521600\t0\t0\t4294967260\t\n\
/usr/bin/sh\t\t4\t41471\t1768521600\t0\t0\t4294967295\tbash\n\
/usr/share/doc/bash/README\t00\t1\t33188\t1768521600\t2\t2\t4294967295\t\n\
@@\tgpg-pubkey\tgpg-pubkey-36f612dc-6786af3b\t1778198087\t(none)\t(none)\t(none)\tFedora (44) <fedora-44-primary@fedoraproject.org> public key\n\
garbage line\n";

    #[test]
    fn parses_headers_and_files() {
        let host = Host::with_root("/nonexistent");
        let mut b = Builder::new(&host);
        parse(SAMPLE.as_bytes(), &mut b).unwrap();
        let db = b.finish();
        assert_eq!(db.packages.len(), 2);
        assert_eq!(db.packages[0].key_id.as_deref(), Some("dbfcf71c6d9f90a6"));
        assert_eq!(db.packages[0].algo, Some(Algo::Sha256));
        assert_eq!(db.packages[1].key_id, None);
        assert_eq!(db.skipped, 1);
        let rc = db.lookup("/etc/skel/.bashrc").next().unwrap();
        assert!(rc.config && rc.is_regular() && rc.installed);
        assert!(rc.verify.has(Verify::DIGEST));
        let bash = db.lookup("/usr/bin/bash").next().unwrap();
        assert!(!bash.verify.has(Verify::DIGEST) && !bash.verify.has(Verify::MTIME) && bash.verify.has(Verify::MODE));
        let sh = db.lookup("/usr/bin/sh").next().unwrap();
        assert_eq!(sh.link, Some("bash"));
        assert!(!sh.is_regular());
        let doc = db.lookup("/usr/share/doc/bash/README").next().unwrap();
        assert!(doc.doc && !doc.installed);
    }
}
