//! Flatpak's system installation, verified from its own ostree repository.
//!
//! A deployment (`/var/lib/flatpak/{app,runtime}/ID/ARCH/BRANCH/active`) is
//! a checkout of a commit, its files hard links to the repository's
//! content-addressed objects. So:
//!
//! - `flatpak-verify` (full) walks each deployed commit's tree and compares
//!   the deployment with it: files missing, replaced, or of another type,
//!   symlinks retargeted, and files that are not in the commit. It hashes a
//!   file object only on evidence of change, as `pkg-verify` does: its
//!   ctime is newer than the newest deployment, or it falls in the day's
//!   slice of the rolling sample. Objects that hashed clean after their
//!   ctime moved are remembered in `flatpak-verified.bin`.
//! - `flatpak-signatures` (quick) checks that each deployed commit from a
//!   remote that requires signatures carries one that verifies (`gpgv`
//!   against the remote's keyring) — so a commit made locally and deployed
//!   in place of the real one is found.
//!
//! Commits from OCI remotes (Fedora's registry) are made on the host when
//! the image is pulled and carry no signature to check. Exported files
//! (`export/`) are rewritten by flatpak on deployment and are not compared.
//! Per-user installations are writable by their user and are not checked.

use super::checkout::{Checkout, Verifier};
use super::pkg_verify::{load_verified, save_verified};
use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::ostree::{self, Csum, Gv, Repo};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct FlatpakVerify;
pub struct FlatpakSignatures;

const INSTALL: &str = "/var/lib/flatpak";
const VERIFIED: &str = "flatpak-verified.bin";

/// One active deployment.
pub(crate) struct Deployment {
    /// `app/org.example.App/x86_64/stable`
    pub r#ref: String,
    pub commit: Csum,
    /// The checkout (`…/BRANCH/<commit>`), as a path on this host.
    pub dir: PathBuf,
    pub origin: String,
    /// Partial checkouts (locale extensions): the `files/` subpaths deployed.
    pub subpaths: Vec<String>,
    /// When it was deployed: the `deploy` file's ctime.
    pub deployed: i64,
}

pub(crate) fn deployments(host: &Host) -> Vec<Deployment> {
    let mut out = Vec::new();
    for kind in ["app", "runtime"] {
        let base = format!("{INSTALL}/{kind}");
        for id in host.list_dir(&base) {
            for arch in host.list_dir(format!("{base}/{id}")) {
                for branch in host.list_dir(format!("{base}/{id}/{arch}")) {
                    let r#ref = format!("{kind}/{id}/{arch}/{branch}");
                    let br = format!("{INSTALL}/{ref}");
                    let Some(c) = host.read_link(format!("{br}/active")) else {
                        continue;
                    };
                    let Some(commit) = ostree::parse_csum(&c) else {
                        continue;
                    };
                    let dir = host.path(format!("{br}/{c}"));
                    let deploy = std::fs::read(dir.join("deploy")).unwrap_or_default();
                    let (origin, subpaths) = parse_deploy(&deploy).unwrap_or_default();
                    let deployed = std::fs::metadata(dir.join("deploy")).map(|m| m.ctime()).unwrap_or(0);
                    out.push(Deployment {
                        r#ref,
                        commit,
                        dir,
                        origin,
                        subpaths,
                        deployed,
                    });
                }
            }
        }
    }
    out
}

/// The `deploy` file: `(ssasta{sv})` — origin, commit, subpaths, installed
/// size, metadata.
fn parse_deploy(b: &[u8]) -> Option<(String, Vec<String>)> {
    let f = Gv::new(b, "(ssasta{sv})").fields()?;
    let origin = f.first()?.str()?.to_string();
    let subpaths = f
        .get(2)?
        .items()?
        .iter()
        .filter_map(|s| s.str().map(str::to_string))
        .collect();
    Some((origin, subpaths))
}

fn repo(host: &Host) -> anyhow::Result<Repo> {
    let dir = host.path(format!("{INSTALL}/repo"));
    if !dir.join("config").exists() {
        return Err(Unavailable("no system flatpak installation".into()).into());
    }
    Repo::open(dir)
}

fn unavailable(host: &Host) -> Option<String> {
    (!host.exists(format!("{INSTALL}/repo/config"))).then(|| "no system flatpak installation".into())
}

/// Whether a commit-relative path is deployed under these subpaths (all of
/// them when there are none).
fn in_subpaths(rel: &str, subpaths: &[String]) -> bool {
    if subpaths.is_empty() || !rel.starts_with("files/") {
        return true;
    }
    let under = &rel["files".len()..];
    subpaths.iter().any(|s| {
        let s = s.trim_end_matches('/');
        under == s || under.starts_with(&format!("{s}/")) || s.starts_with(&format!("{under}/"))
    })
}

/// Files flatpak itself writes into a deployment after checkout.
fn generated(rel: &str) -> bool {
    rel == "deploy" || rel.starts_with("export/") || rel == "files/.ref" || rel.starts_with("files/extra/")
}

/// Placeholders flatpak creates in a runtime's `etc` on deployment, which
/// are bind-mounted over when an app runs: empty account and machine-id
/// files, and symlinks into the host's `/run/host`. Anything else at these
/// paths is not a placeholder.
fn placeholder(rel: &str, path: &Path) -> bool {
    let Some(name) = rel.strip_prefix("files/etc/") else {
        return false;
    };
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    match name {
        "passwd" | "group" | "machine-id" => md.file_type().is_file() && md.len() == 0,
        "resolv.conf" | "host.conf" | "hosts" | "localtime" | "timezone" => {
            md.file_type().is_symlink() && std::fs::read_link(path).is_ok_and(|t| t.starts_with("/run/host/"))
        }
        _ => false,
    }
}

/// A flatpak path as the sandbox knows it, for its severity: `files/` is
/// the app's or runtime's `/usr`.
fn host_path(rel: &str) -> String {
    match rel.strip_prefix("files/") {
        Some(r) => format!("/usr/{r}"),
        None => format!("/{rel}"),
    }
}

impl Check for FlatpakVerify {
    fn id(&self) -> &'static str {
        "flatpak-verify"
    }

    fn description(&self) -> &'static str {
        "deployed flatpak apps and runtimes against their ostree commits"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["flatpak-modified", "flatpak-missing"]
    }

    fn cost(&self) -> Cost {
        Cost::Full
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let repo = repo(ctx.host)?;
        let deps = deployments(ctx.host);
        // flatpak writes `deploy` after the checkout's links, so no slack is
        // needed: later ctimes are later changes.
        let newest = deps.iter().map(|d| d.deployed).max().unwrap_or(0);
        let mut run = Verifier::new(
            &repo,
            super::checkout::since(anchors, newest),
            ctx.cfg.scan.sample_days as u64,
            ctx.now / 86_400,
            load_verified(&ctx.state_dir, VERIFIED),
        );
        let exempt = |rel: &str, p: &Path| generated(rel) || placeholder(rel, p);
        for d in &deps {
            let wanted = |rel: &str| !generated(rel) && in_subpaths(rel, &d.subpaths);
            run.checkout(&Checkout {
                label: d.r#ref.clone(),
                commit: d.commit,
                dir: d.dir.clone(),
                modified: "flatpak-modified",
                missing: "flatpak-missing",
                wanted: &wanted,
                exempt: &exempt,
                extras_root: "files",
                host_path,
            });
        }
        if let Err(e) = save_verified(&ctx.state_dir, VERIFIED, &run.next_verified) {
            tracing::warn!("{VERIFIED}: {e}");
        }
        tracing::info!(
            "flatpak-verify: {} deployments, {} objects hashed ({} MiB)",
            deps.len(),
            run.hashed,
            run.bytes >> 20
        );
        Ok(run.out)
    }
}

/// A remote's settings from the repository's `config`.
fn remote<'a>(config: &'a [(String, BTreeMap<String, String>)], name: &str) -> Option<&'a BTreeMap<String, String>> {
    let section = format!("remote \"{name}\"");
    config.iter().find(|(s, _)| *s == section).map(|(_, m)| m)
}

/// Whether one of `sigs` is a good signature of `data` by a key in
/// `keyrings`, according to gpgv.
fn gpg_verified(data: &Path, sigs: &[Vec<u8>], keyrings: &[PathBuf]) -> anyhow::Result<bool> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for sig in sigs {
        let mut cmd = Command::new("gpgv");
        cmd.args(["--homedir", "/nonexistent", "--status-fd", "1"]);
        for k in keyrings {
            cmd.arg("--keyring").arg(k);
        }
        let mut child = cmd
            .arg("-")
            .arg(data)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("gpgv: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(sig);
        }
        let out = child.wait_with_output()?;
        let status = String::from_utf8_lossy(&out.stdout);
        if status.lines().any(|l| l.starts_with("[GNUPG:] VALIDSIG ")) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Check for FlatpakSignatures {
    fn id(&self) -> &'static str {
        "flatpak-signatures"
    }

    fn description(&self) -> &'static str {
        "deployed flatpak commits signed by their remote's key"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let repo = repo(ctx.host)?;
        let config = super::repos::ini(&std::fs::read_to_string(repo.dir.join("config")).unwrap_or_default());
        let mut out = Vec::new();
        for d in deployments(ctx.host) {
            let Some(r) = remote(&config, &d.origin) else {
                // A remote removed after install: nothing to verify against.
                continue;
            };
            let url = r.get("url").map(String::as_str).unwrap_or("");
            let verify = !r.get("gpg-verify").is_some_and(|v| super::repos::falsy(v));
            if url.starts_with("oci+") || !verify {
                continue;
            }
            let mut keyrings: Vec<PathBuf> = [repo.dir.join(format!("{}.trustedkeys.gpg", d.origin))]
                .into_iter()
                .filter(|p| p.exists())
                .collect();
            for dir in ["/etc/flatpak/trusted.gpg.d", "/usr/share/ostree/trusted.gpg.d"] {
                for n in ctx.host.list_dir(dir).into_iter().filter(|n| n.ends_with(".gpg")) {
                    keyrings.push(ctx.host.path(format!("{dir}/{n}")));
                }
            }
            let sigs = repo.gpg_signatures(&d.commit);
            let commit = repo.object_path(&d.commit, "commit");
            let problem = if sigs.is_empty() {
                Some("is not signed")
            } else if keyrings.is_empty() {
                Some("cannot be verified: the remote has no keyring")
            } else {
                match gpg_verified(&commit, &sigs, &keyrings) {
                    Ok(true) => None,
                    Ok(false) => Some("has no signature that verifies"),
                    Err(e) => return Err(Unavailable(format!("{e}")).into()),
                }
            };
            if let Some(p) = problem {
                out.push(
                    Finding::new("flatpak-signatures", Severity::High, &d.r#ref, &ostree::hex(&d.commit))
                        .message(format!(
                            "{}: deployed commit {} {p} (remote {})",
                            d.r#ref,
                            &ostree::hex(&d.commit)[..12],
                            d.origin
                        ))
                        .detail(serde_json::json!({
                            "commit": ostree::hex(&d.commit),
                            "origin": d.origin,
                            "signatures": sigs.len(),
                        })),
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
    fn subpaths_select_files() {
        let subs = vec!["/de".to_string()];
        assert!(in_subpaths("metadata", &subs));
        assert!(in_subpaths("files", &subs));
        assert!(in_subpaths("files/de", &subs));
        assert!(in_subpaths("files/de/LC_MESSAGES/x.mo", &subs));
        assert!(!in_subpaths("files/fr/LC_MESSAGES/x.mo", &subs));
        assert!(!in_subpaths("files/den", &subs));
        assert!(in_subpaths("files/fr/x", &[]));
        // A nested subpath keeps its parents.
        assert!(in_subpaths("files/share", &["/share/locale".to_string()]));
    }

    #[test]
    fn placeholders_are_exact() {
        let dir = std::env::temp_dir().join(format!("minsec-id-flatpak-{}", std::process::id()));
        let etc = dir.join("files/etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("passwd"), b"").unwrap();
        std::fs::write(etc.join("group"), b"root:x:0:\n").unwrap();
        std::os::unix::fs::symlink("/run/host/monitor/resolv.conf", etc.join("resolv.conf")).unwrap();
        std::os::unix::fs::symlink("/tmp/x", etc.join("hosts")).unwrap();
        let p = |n: &str| placeholder(&format!("files/etc/{n}"), &etc.join(n));
        assert!(p("passwd"));
        assert!(!p("group"), "a non-empty account file is not a placeholder");
        assert!(p("resolv.conf"));
        assert!(!p("hosts"), "a symlink outside /run/host is not a placeholder");
        assert!(!placeholder("files/bin/passwd", &etc.join("passwd")));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deploy_file_parses() {
        // ("flathub", "c", ["/de"], 7, {})
        let mut b = Vec::new();
        b.extend_from_slice(b"flathub\0c\0");
        let arr_start = b.len();
        b.extend_from_slice(b"/de\0");
        b.push(4); // the array's framing: the element's end
        let arr_end = b.len();
        while b.len() % 8 != 0 {
            b.push(0);
        }
        b.extend_from_slice(&7u64.to_be_bytes());
        // a{sv} empty, then the tuple's framing offsets, last first.
        b.push(arr_end as u8);
        b.push(10);
        b.push(8);
        let _ = arr_start;
        let (origin, subs) = parse_deploy(&b).unwrap();
        assert_eq!(origin, "flathub");
        assert_eq!(subs, vec!["/de"]);
    }
}
