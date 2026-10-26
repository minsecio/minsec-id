//! Image-based systems booted from ostree: Fedora CoreOS, Silverblue and its
//! siblings, and bootc images. The booted deployment
//! (`/sysroot/ostree/deploy/STATEROOT/deploy/COMMIT.SERIAL`) is a checkout
//! of a commit in `/sysroot/ostree/repo`, and with composefs its files are
//! served straight from that repository's objects. So:
//!
//! - `ostree-verify` (full) compares the booted deployment's `/usr` with its
//!   commit, hashing objects only on evidence of change (see `checkout`).
//!   It replaces `pkg-verify` on these systems, whose rpm database describes
//!   packages rather than the composed tree.
//! - `ostree-deployment` (quick) watches what decides what boots and runs:
//!   the image or ref the deployment follows, and how it is verified; a
//!   staged deployment of something else; `/usr` unlocked for writing; the
//!   composefs image; and packages layered on top of the image.

use super::checkout::{Checkout, Verifier};
use super::pkg_verify::{load_verified, save_verified};
use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::ostree::{self, Csum, Gv, Repo};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub struct OstreeVerify;
pub struct OstreeDeployment;

const BOOTED: &str = "/run/ostree-booted";
const DEPLOY: &str = "/sysroot/ostree/deploy";
const STAGED: &str = "/run/ostree/staged-deployment";
const VERIFIED: &str = "ostree-verified.bin";

pub(crate) fn is_ostree(host: &Host) -> bool {
    host.exists(BOOTED)
}

fn unavailable(host: &Host) -> Option<String> {
    (!is_ostree(host)).then(|| "not an ostree-booted system".into())
}

/// The booted deployment.
struct Deployment {
    stateroot: String,
    /// `COMMIT.SERIAL`
    name: String,
    commit: Csum,
    dir: PathBuf,
    origin: Origin,
}

/// A deployment's `.origin`: what it follows, and what is layered on it.
#[derive(Debug, Default, PartialEq)]
struct Origin {
    /// `container-image-reference` (with its verification transport) or
    /// `refspec`.
    source: String,
    unlocked: Option<String>,
    /// package → how it got there (`layered`, `local`, `removed`,
    /// `replaced-local`).
    packages: BTreeMap<String, &'static str>,
}

fn parse_origin(s: &str) -> Origin {
    let ini = super::repos::ini(s);
    let get = |sec: &str, k: &str| ini.iter().find(|(n, _)| n == sec).and_then(|(_, m)| m.get(k)).cloned();
    let mut o = Origin {
        source: get("origin", "container-image-reference")
            .or_else(|| get("origin", "refspec"))
            .or_else(|| get("origin", "baserefspec"))
            .unwrap_or_default(),
        unlocked: get("origin", "unlocked").filter(|u| u != "none"),
        ..Default::default()
    };
    for (sec, key, how) in [
        ("packages", "requested", "layered"),
        ("packages", "requested-local", "local"),
        ("overrides", "remove", "removed"),
        ("overrides", "replace-local", "replaced-local"),
    ] {
        for p in get(sec, key).unwrap_or_default().split(';').filter(|p| !p.is_empty()) {
            o.packages.insert(p.to_string(), how);
        }
    }
    o
}

/// The booted deployment, with its origin.
fn booted(host: &Host) -> anyhow::Result<Deployment> {
    let b = ostree::booted(host).map_err(|e| Unavailable(format!("{e:#}")))?;
    let origin = parse_origin(&std::fs::read_to_string(b.dir.with_extension(origin_ext(&b.name))).unwrap_or_default());
    Ok(Deployment {
        stateroot: b.stateroot,
        name: b.name,
        commit: b.commit,
        dir: b.dir,
        origin,
    })
}

/// `COMMIT.SERIAL.origin` sits beside the deployment: `with_extension`
/// replaces the serial, so give it back.
fn origin_ext(name: &str) -> String {
    format!("{}.origin", name.rsplit('.').next().unwrap_or("0"))
}

/// Every deployment's (name, origin, ctime) under the stateroot.
fn deployments(host: &Host, stateroot: &str) -> Vec<(String, Origin, i64)> {
    let d = format!("{DEPLOY}/{stateroot}/deploy");
    host.list_dir(&d)
        .into_iter()
        .filter_map(|n| {
            let name = n.strip_suffix(".origin")?.to_string();
            let p = host.path(format!("{d}/{n}"));
            let ctime = std::fs::metadata(&p).ok()?.ctime();
            Some((name, parse_origin(&std::fs::read_to_string(p).ok()?), ctime))
        })
        .collect()
}

impl Check for OstreeVerify {
    fn id(&self) -> &'static str {
        "ostree-verify"
    }

    fn description(&self) -> &'static str {
        "the booted ostree deployment's /usr against its commit"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["ostree-modified", "ostree-missing"]
    }

    fn cost(&self) -> Cost {
        Cost::Full
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let d = booted(ctx.host)?;
        let repo = Repo::open(ctx.host.path(ostree::SYSTEM_REPO))?;
        // Objects are linked when a deployment is written, before its origin.
        let newest = deployments(ctx.host, &d.stateroot)
            .iter()
            .map(|(_, _, t)| *t)
            .max()
            .unwrap_or(0);
        let mut v = Verifier::new(
            &repo,
            super::checkout::since(anchors, newest),
            ctx.cfg.scan.sample_days as u64,
            ctx.now / 86_400,
            load_verified(&ctx.state_dir, VERIFIED),
        );
        let wanted = |rel: &str| rel == "usr" || rel.starts_with("usr/");
        let exempt = |_: &str, _: &std::path::Path| false;
        v.checkout(&Checkout {
            label: format!("ostree:{}", d.stateroot),
            commit: d.commit,
            dir: d.dir.clone(),
            modified: "ostree-modified",
            missing: "ostree-missing",
            wanted: &wanted,
            exempt: &exempt,
            extras_root: "usr",
            host_path: |rel| format!("/{rel}"),
        });
        if let Err(e) = save_verified(&ctx.state_dir, VERIFIED, &v.next_verified) {
            tracing::warn!("{VERIFIED}: {e}");
        }
        tracing::info!(
            "ostree-verify: {} {}, {} objects hashed ({} MiB)",
            d.stateroot,
            &d.name,
            v.hashed,
            v.bytes >> 20
        );
        Ok(v.out)
    }
}

/// The staged deployment's origin, if one is waiting for the next boot.
fn staged(host: &Host) -> Option<Origin> {
    let b = host.read(STAGED).ok()?;
    let o = Gv::new(&b, "a{sv}").lookup("origin")?;
    Some(parse_origin(o.str()?))
}

/// How a container image reference is verified, from its transport.
fn unverified(source: &str) -> bool {
    source.starts_with("ostree-unverified-registry:") || source.starts_with("ostree-unverified-image:")
}

impl Check for OstreeDeployment {
    fn id(&self) -> &'static str {
        "ostree-deployment"
    }

    fn description(&self) -> &'static str {
        "what an ostree system boots: its image, staged changes, unlocked /usr, composefs, layered packages"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        unavailable(host)
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let d = booted(host)?;
        let mut out = Vec::new();
        let f = |sev: Severity, subject: &str, salient: &str, msg: String| {
            Finding::new("ostree-deployment", sev, subject, salient).message(msg)
        };

        let src = &d.origin.source;
        if let Some(Some(old)) = anchors.observe("source", src) {
            out.push(
                f(
                    Severity::High,
                    "source",
                    src,
                    format!("the booted deployment follows {src}, not {old} as before"),
                )
                .detail(serde_json::json!({ "source": src, "was": old })),
            );
        }
        if unverified(src) {
            out.push(f(
                Severity::Low,
                "unverified",
                src,
                format!("updates come from {src}, which is pulled without signature verification"),
            ));
        }

        // What the next boot will run, if it is something else.
        let mut next: Vec<(String, Origin)> = staged(host).map(|o| ("staged".to_string(), o)).into_iter().collect();
        let booted_ctime = deployments(host, &d.stateroot)
            .iter()
            .find(|(n, _, _)| *n == d.name)
            .map(|(_, _, t)| *t)
            .unwrap_or(0);
        for (name, o, t) in deployments(host, &d.stateroot) {
            if name != d.name && t > booted_ctime {
                next.push((name, o));
            }
        }
        for (name, o) in next {
            if !o.source.is_empty() && o.source != *src {
                out.push(
                    f(
                        Severity::High,
                        "next-boot",
                        &o.source,
                        format!("the next boot switches to {} (deployment {name})", o.source),
                    )
                    .detail(serde_json::json!({ "deployment": name, "source": o.source, "booted": src })),
                );
            }
            for (p, how) in &o.packages {
                if d.origin.packages.get(p) != Some(how) && *how != "layered" {
                    out.push(f(
                        Severity::Medium,
                        &format!("next-boot:{p}"),
                        how,
                        format!("the next boot adds package {p} ({how})"),
                    ));
                }
            }
        }

        let usr_overlay = crate::procfs::mounts(host)
            .iter()
            .any(|m| m.target == "/usr" && m.fstype == "overlay");
        if let Some(how) = d.origin.unlocked.as_deref().or(usr_overlay.then_some("development")) {
            out.push(f(
                Severity::Medium,
                "unlocked",
                how,
                format!("/usr is unlocked ({how}): it can be changed outside the image"),
            ));
        }

        // The composefs image of a deployment never changes once written.
        let cfs = d.dir.join(".ostree.cfs");
        if let Ok(dg) = digest::file(Algo::Sha256, &cfs) {
            let key = format!("composefs:{}", d.name);
            let dg = digest::hex(&dg);
            if anchors.map.contains_key(&key) {
                if let Some(Some(old)) = anchors.observe(&key, &dg) {
                    out.push(
                        f(
                            Severity::Critical,
                            "composefs",
                            &dg,
                            format!(
                                "the booted deployment's composefs image ({}) changed after deployment",
                                cfs.display()
                            ),
                        )
                        .detail(serde_json::json!({ "sha256": dg, "was": old })),
                    );
                }
            } else {
                anchors.set(&key, &dg);
            }
        }
        // Deployments that are gone need no record.
        let live: std::collections::HashSet<String> =
            deployments(host, &d.stateroot).into_iter().map(|(n, _, _)| n).collect();
        anchors
            .map
            .retain(|k, _| k.strip_prefix("composefs:").is_none_or(|n| live.contains(n)));

        for (p, how) in &d.origin.packages {
            let key = format!("package:{p}");
            if let Some(was) = anchors.observe(&key, how) {
                let sev = match *how {
                    "local" | "replaced-local" => Severity::Medium,
                    _ => Severity::Low,
                };
                out.push(
                    f(
                        sev,
                        &format!("package:{p}"),
                        how,
                        format!(
                            "package {p} is {} the image{}",
                            match *how {
                                "layered" => "layered on",
                                "local" => "installed from a local file on",
                                "removed" => "removed from",
                                _ => "replaced from a local file in",
                            },
                            was.map(|w| format!(" (was {w})")).unwrap_or_default()
                        ),
                    )
                    .detail(serde_json::json!({ "package": p, "how": how })),
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
    fn origins() {
        let o = parse_origin(
            "[origin]\ncontainer-image-reference=ostree-image-signed:docker://quay.io/fedora/fedora-coreos:stable\n\
             [packages]\nrequested=vim-enhanced;htop;\nrequested-local=evil.rpm;\n\
             [overrides]\nremove=nano;\n",
        );
        assert_eq!(
            o.source,
            "ostree-image-signed:docker://quay.io/fedora/fedora-coreos:stable"
        );
        assert_eq!(o.packages["vim-enhanced"], "layered");
        assert_eq!(o.packages["evil.rpm"], "local");
        assert_eq!(o.packages["nano"], "removed");
        assert_eq!(o.unlocked, None);
        let o = parse_origin("[origin]\nrefspec=fedora:fedora/42/x86_64/silverblue\nunlocked=hotfix\n");
        assert_eq!(o.source, "fedora:fedora/42/x86_64/silverblue");
        assert_eq!(o.unlocked.as_deref(), Some("hotfix"));
        assert!(unverified("ostree-unverified-registry:quay.io/x/y"));
        assert!(!unverified("ostree-image-signed:docker://quay.io/x/y"));
    }

    #[test]
    fn origin_beside_deployment() {
        let d = PathBuf::from("/sysroot/ostree/deploy/os/deploy/abc.0");
        assert_eq!(
            d.with_extension(origin_ext("abc.0")),
            PathBuf::from("/sysroot/ostree/deploy/os/deploy/abc.0.origin")
        );
    }
}
