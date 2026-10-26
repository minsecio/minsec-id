//! dpkg: `/var/lib/dpkg/status` for installed packages and conffile digests,
//! `info/<pkg>.list` for ownership, `info/<pkg>.md5sums` for file digests,
//! and `diversions` for files moved aside by another package. dpkg records
//! neither modes nor sizes, and its install time is the `.list` file's mtime.

use super::{Builder, Manager, Package, RawFile, Verify};
use crate::digest::Algo;
use crate::host::Host;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

struct Stanza {
    name: String,
    arch: String,
    version: String,
    summary: String,
    conffiles: Vec<(String, String)>,
}

pub(super) fn load(host: &Host, b: &mut Builder) -> anyhow::Result<()> {
    let status = std::fs::read_to_string(host.path("/var/lib/dpkg/status"))
        .map_err(|e| anyhow::anyhow!("/var/lib/dpkg/status: {e}"))?;
    let diversions = diversions(host);
    for st in parse_status(&status) {
        let info = host.path("/var/lib/dpkg/info");
        let qualified = format!("{}:{}", st.name, st.arch);
        let (list_path, base) = [&qualified, &st.name]
            .iter()
            .map(|n| (info.join(format!("{n}.list")), n.to_string()))
            .find(|(p, _)| p.exists())
            .unwrap_or_else(|| (info.join(format!("{}.list", st.name)), st.name.clone()));
        let Ok(list) = std::fs::read_to_string(&list_path) else {
            // Installed with no file list (metapackages): nothing to own.
            continue;
        };
        let install_time = std::fs::metadata(&list_path).map(|m| m.mtime() as u64).unwrap_or(0);
        let sums: HashMap<String, String> = std::fs::read_to_string(info.join(format!("{base}.md5sums")))
            .map(|s| parse_md5sums(&s))
            .unwrap_or_default();
        let conf: HashMap<&str, &str> = st.conffiles.iter().map(|(p, d)| (p.as_str(), d.as_str())).collect();
        let pkg = b.package(Package {
            manager: Manager::Dpkg,
            name: st.name.clone(),
            id: format!("{}:{}={}", st.name, st.arch, st.version),
            install_time,
            algo: Some(Algo::Md5),
            key_id: None,
            summary: st.summary.clone(),
        });
        for path in list.lines() {
            if path.is_empty() || path == "/." || !path.starts_with('/') {
                continue;
            }
            let (digest, config) = match conf.get(path) {
                // "newconffile" marks a conffile not yet configured.
                Some(d) if d.len() == 32 => (*d, true),
                Some(_) => ("", true),
                None => (sums.get(path).map(String::as_str).unwrap_or(""), false),
            };
            b.file(
                pkg,
                RawFile {
                    path,
                    digest_hex: digest,
                    size: None,
                    mode: None,
                    mtime: None,
                    link: None,
                    config,
                    doc: path.starts_with("/usr/share/doc/"),
                    ghost: false,
                    missingok: false,
                    installed: true,
                    verify: Verify::ALL,
                },
            );
        }
        // A file diverted by another package lives under the diverted name.
        for (from, (to, by)) in &diversions {
            if by != &st.name && list.lines().any(|l| l == from) {
                b.rename(pkg, from, to);
            }
        }
    }
    Ok(())
}

fn parse_status(s: &str) -> Vec<Stanza> {
    let mut out = Vec::new();
    for block in s.split("\n\n") {
        let mut st = Stanza {
            name: String::new(),
            arch: String::new(),
            version: String::new(),
            summary: String::new(),
            conffiles: Vec::new(),
        };
        let mut installed = false;
        let mut in_conffiles = false;
        for line in block.lines() {
            if let Some(cont) = line.strip_prefix(' ') {
                if in_conffiles {
                    let mut f = cont.split_whitespace();
                    if let (Some(p), Some(d)) = (f.next(), f.next()) {
                        if f.next() != Some("obsolete") {
                            st.conffiles.push((p.to_string(), d.to_string()));
                        }
                    }
                }
                continue;
            }
            in_conffiles = false;
            let Some((k, v)) = line.split_once(':') else { continue };
            let v = v.trim();
            match k {
                "Package" => st.name = v.into(),
                "Architecture" => st.arch = v.into(),
                "Version" => st.version = v.into(),
                "Description" => st.summary = v.into(),
                "Status" => {
                    let state = v.split_whitespace().nth(2).unwrap_or("");
                    installed = !matches!(state, "not-installed" | "config-files" | "");
                }
                "Conffiles" => in_conffiles = true,
                _ => {}
            }
        }
        if installed && !st.name.is_empty() {
            out.push(st);
        }
    }
    out
}

/// `md5  relative/path` lines → absolute path → hex digest.
fn parse_md5sums(s: &str) -> HashMap<String, String> {
    s.lines()
        .filter_map(|l| {
            let (d, p) = l.split_once(char::is_whitespace)?;
            Some((format!("/{}", p.trim_start()), d.to_string()))
        })
        .collect()
}

/// from → (to, diverting package); `:` is a local (admin) diversion.
fn diversions(host: &Host) -> HashMap<String, (String, String)> {
    let s = std::fs::read_to_string(host.path("/var/lib/dpkg/diversions")).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines
        .chunks_exact(3)
        .map(|c| (c[0].to_string(), (c[1].to_string(), c[2].to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let s = "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2\n\
Conffiles:\n /etc/ssh/moduli 0123456789abcdef0123456789abcdef\n /etc/old abcd obsolete\nDescription: secure shell server\n\n\
Package: gone\nStatus: deinstall ok config-files\nArchitecture: all\n";
        let st = parse_status(s);
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].name, "openssh-server");
        assert_eq!(st[0].conffiles.len(), 1);
        let m = parse_md5sums("d41d8cd98f00b204e9800998ecf8427e  usr/bin/x\n");
        assert_eq!(m["/usr/bin/x"], "d41d8cd98f00b204e9800998ecf8427e");
    }
}
