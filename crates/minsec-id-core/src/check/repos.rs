//! Supply-chain anchors: the keys packages are verified with
//! (`repo-key-changed`) and the repositories they come from
//! (`repo-changed`), against the baseline; plus repositories configured to
//! skip signature checks (`repo-insecure`), whenever present.

use super::{Anchors, Check, Cost, Ctx};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::pkgdb::Manager;
use std::collections::BTreeMap;

pub struct RepoKeys;
pub struct Repos;

/// Directories of trusted key files (apt, rpm, flatpak).
const KEY_DIRS: &[&str] = &[
    "/etc/apt/trusted.gpg.d",
    "/etc/apt/keyrings",
    "/usr/share/keyrings",
    "/etc/pki/rpm-gpg",
    "/etc/flatpak/remotes.d",
];
const KEY_FILES: &[&str] = &["/etc/apt/trusted.gpg"];

impl Check for RepoKeys {
    fn id(&self) -> &'static str {
        "repo-key-changed"
    }

    fn description(&self) -> &'static str {
        "package signing keys added or changed since the baseline"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, _: &Host) -> Option<String> {
        None
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.pkgdb()?;
        let mut out = Vec::new();
        // rpm imports keys as gpg-pubkey pseudo-packages.
        for p in db
            .packages
            .iter()
            .filter(|p| p.manager == Manager::Rpm && p.name == "gpg-pubkey")
        {
            let key = format!("rpm:{}", p.id);
            if anchors.observe(&key, &p.summary).is_some() {
                out.push(
                    Finding::new(self.id(), Severity::High, &key, "")
                        .message(format!("rpm signing key added: {}", p.summary))
                        .detail(serde_json::json!({ "key": p.id, "summary": p.summary })),
                );
            }
        }
        let mut files: Vec<String> = KEY_FILES.iter().map(|s| s.to_string()).collect();
        for d in KEY_DIRS {
            files.extend(host.list_dir(d).into_iter().map(|n| format!("{d}/{n}")));
        }
        files.extend(
            host.list_dir("/var/lib/flatpak/repo")
                .into_iter()
                .filter(|n| n.ends_with(".trustedkeys.gpg"))
                .map(|n| format!("/var/lib/flatpak/repo/{n}")),
        );
        for path in files {
            let Ok(md) = std::fs::metadata(host.path(&path)) else {
                continue;
            };
            if !md.is_file() {
                continue;
            }
            let Ok(sha) = digest::file(Algo::Sha256, &host.path(&path)) else {
                continue;
            };
            // A packaged keyring as shipped is covered by pkg-verify, and
            // keyring package updates are not news.
            let pristine = db.lookup(&path).any(|f| {
                f.pkg
                    .algo
                    .is_some_and(|a| digest::file(a, &host.path(&path)).is_ok_and(|d| d == f.digest))
            });
            if pristine {
                continue;
            }
            let hex = digest::hex(&sha);
            if let Some(old) = anchors.observe(&format!("file:{path}"), &hex) {
                let what = if old.is_some() { "changed" } else { "added" };
                out.push(
                    Finding::new(self.id(), Severity::High, &path, &hex)
                        .message(format!("trusted key file {path} {what}"))
                        .detail(serde_json::json!({ "sha256": hex, "baseline": old })),
                );
            }
        }
        Ok(out)
    }
}

/// One configured repository, reduced to what matters for trust.
#[derive(Debug, PartialEq)]
struct Repo {
    subject: String,
    /// Normalized trust-relevant settings, for the baseline.
    settings: String,
    /// Why it is insecure, if it is.
    insecure: Option<String>,
}

fn falsy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "no" | "false" | "off")
}

/// INI sections → key/value maps (dnf repo files, flatpak's repo config).
fn ini(s: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut out: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for l in s.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(name) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            out.push((name.to_string(), BTreeMap::new()));
        } else if let (Some((k, v)), Some(last)) = (l.split_once('='), out.last_mut()) {
            last.1.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn dnf_repos(host: &Host) -> Vec<Repo> {
    let main_gpgcheck = ["/etc/dnf/dnf.conf", "/etc/yum.conf"].iter().find_map(|p| {
        let s = host.read_opt(p)?;
        ini(&s)
            .into_iter()
            .find(|(n, _)| n == "main")?
            .1
            .get("gpgcheck")
            .cloned()
    });
    let mut out = Vec::new();
    for name in host
        .list_dir("/etc/yum.repos.d")
        .into_iter()
        .filter(|n| n.ends_with(".repo"))
    {
        let Some(s) = host.read_opt(format!("/etc/yum.repos.d/{name}")) else {
            continue;
        };
        for (id, kv) in ini(&s) {
            if kv.get("enabled").is_some_and(|v| falsy(v)) {
                continue;
            }
            let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
            let gpgcheck = kv.get("gpgcheck").cloned().or_else(|| main_gpgcheck.clone());
            let insecure = gpgcheck
                .as_deref()
                .filter(|v| falsy(v))
                .map(|_| "gpgcheck is off: packages are installed unverified".to_string());
            out.push(Repo {
                subject: format!("dnf:{id}"),
                settings: format!(
                    "baseurl={} metalink={} mirrorlist={} gpgcheck={} gpgkey={} sslverify={}",
                    get("baseurl"),
                    get("metalink"),
                    get("mirrorlist"),
                    gpgcheck.unwrap_or_default(),
                    get("gpgkey"),
                    get("sslverify")
                ),
                insecure,
            });
        }
    }
    out
}

fn apt_options_insecure(opts: &str) -> Option<String> {
    let o = opts.to_ascii_lowercase().replace(' ', "");
    if o.contains("trusted=yes") {
        Some("trusted=yes: signatures are not checked".into())
    } else if o.contains("allow-insecure=yes") || o.contains("allow-weak=yes") {
        Some("allow-insecure/allow-weak: unsigned or weakly signed metadata accepted".into())
    } else {
        None
    }
}

fn apt_repos(host: &Host) -> Vec<Repo> {
    let mut out = Vec::new();
    let mut files = vec!["/etc/apt/sources.list".to_string()];
    files.extend(
        host.list_dir("/etc/apt/sources.list.d")
            .into_iter()
            .map(|n| format!("/etc/apt/sources.list.d/{n}")),
    );
    for f in files {
        let Some(s) = host.read_opt(&f) else { continue };
        if f.ends_with(".sources") {
            // deb822 stanzas.
            for st in s.split("\n\n") {
                let mut kv = BTreeMap::new();
                for l in st.lines().filter(|l| !l.starts_with('#') && !l.starts_with(' ')) {
                    if let Some((k, v)) = l.split_once(':') {
                        kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                    }
                }
                if kv.get("enabled").is_some_and(|v| falsy(v)) || !kv.contains_key("uris") {
                    continue;
                }
                let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
                let opts = format!("trusted={} allow-insecure={}", get("trusted"), get("allow-insecure"));
                out.push(Repo {
                    subject: format!("apt:{} {}", get("uris"), get("suites")),
                    settings: format!("components={} signed-by={} {opts}", get("components"), get("signed-by")),
                    insecure: apt_options_insecure(&opts),
                });
            }
        } else if f.ends_with(".list") || f == "/etc/apt/sources.list" {
            for l in s.lines().map(str::trim).filter(|l| l.starts_with("deb")) {
                let (kind, rest) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
                let rest = rest.trim();
                let (opts, rest) = match rest.strip_prefix('[') {
                    Some(r) => r.split_once(']').map(|(o, r)| (o, r.trim())).unwrap_or(("", r)),
                    None => ("", rest),
                };
                let mut parts = rest.split_whitespace();
                let (uri, suite) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let comps: Vec<&str> = parts.collect();
                out.push(Repo {
                    subject: format!("apt:{kind} {uri} {suite}"),
                    settings: format!("components={} options={}", comps.join(" "), opts.trim()),
                    insecure: apt_options_insecure(opts),
                });
            }
        }
    }
    out
}

fn flatpak_remotes(host: &Host) -> Vec<Repo> {
    let Some(s) = host.read_opt("/var/lib/flatpak/repo/config") else {
        return Vec::new();
    };
    ini(&s)
        .into_iter()
        .filter_map(|(sec, kv)| {
            let name = sec.strip_prefix("remote \"")?.strip_suffix('"')?.to_string();
            let gpg = kv.get("gpg-verify").cloned().unwrap_or_default();
            Some(Repo {
                subject: format!("flatpak:{name}"),
                settings: format!(
                    "url={} gpg-verify={gpg} gpg-verify-summary={}",
                    kv.get("url").cloned().unwrap_or_default(),
                    kv.get("gpg-verify-summary").cloned().unwrap_or_default()
                ),
                insecure: falsy(&gpg).then(|| "gpg-verify=false: refs are not verified".to_string()),
            })
        })
        .collect()
}

impl Check for Repos {
    fn id(&self) -> &'static str {
        "repo-changed"
    }

    fn description(&self) -> &'static str {
        "package repositories added or changed, and repositories that skip signature checks"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["repo-insecure"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, _: &Host) -> Option<String> {
        None
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let mut out = Vec::new();
        let repos = dnf_repos(host)
            .into_iter()
            .chain(apt_repos(host))
            .chain(flatpak_remotes(host));
        for r in repos {
            if let Some(why) = &r.insecure {
                out.push(
                    Finding::new("repo-insecure", Severity::High, &r.subject, &r.settings)
                        .message(format!("repository {}: {why}", r.subject))
                        .detail(serde_json::json!({ "settings": r.settings })),
                );
            }
            if let Some(old) = anchors.observe(&r.subject, &r.settings) {
                let what = if old.is_some() { "changed" } else { "added" };
                out.push(
                    Finding::new(self.id(), Severity::Medium, &r.subject, &r.settings)
                        .message(format!("repository {} {what}", r.subject))
                        .detail(serde_json::json!({ "settings": r.settings, "baseline": old })),
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_options() {
        assert!(apt_options_insecure("arch=amd64 trusted=yes").is_some());
        assert!(apt_options_insecure("signed-by=/etc/apt/keyrings/x.gpg").is_none());
    }

    #[test]
    fn parses_sources() {
        let root = std::env::temp_dir().join(format!("minsec-id-repos-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/apt/sources.list.d")).unwrap();
        std::fs::create_dir_all(root.join("etc/yum.repos.d")).unwrap();
        std::fs::create_dir_all(root.join("etc/dnf")).unwrap();
        std::fs::write(
            root.join("etc/apt/sources.list"),
            "# c\ndeb http://deb.debian.org/debian bookworm main\ndeb [trusted=yes] http://evil.example/ ./\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/apt/sources.list.d/x.sources"),
            "Types: deb\nURIs: https://example.org/\nSuites: stable\nComponents: main\nSigned-By: /k.gpg\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/dnf/dnf.conf"), "[main]\ngpgcheck=True\n").unwrap();
        std::fs::write(
            root.join("etc/yum.repos.d/r.repo"),
            "[ok]\nbaseurl=https://a/\n[bad]\nbaseurl=http://b/\ngpgcheck=0\n[off]\nenabled=0\ngpgcheck=0\n",
        )
        .unwrap();
        let h = Host::with_root(&root);
        let apt = apt_repos(&h);
        assert_eq!(apt.len(), 3);
        assert_eq!(apt.iter().filter(|r| r.insecure.is_some()).count(), 1);
        let dnf = dnf_repos(&h);
        assert_eq!(
            dnf.iter().map(|r| r.subject.as_str()).collect::<Vec<_>>(),
            vec!["dnf:ok", "dnf:bad"]
        );
        assert!(dnf[0].insecure.is_none() && dnf[1].insecure.is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
}
