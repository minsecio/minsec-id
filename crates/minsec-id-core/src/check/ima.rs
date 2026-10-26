//! `ima-verify`: the kernel's IMA measurement list as free hashes. Where a
//! measurement policy is active (`ima_policy=tcb`, or a loaded policy), the
//! kernel records the digest of every program it runs and every file root
//! reads, before use. Each measured digest of a packaged file is compared
//! with the package's.
//!
//! The list is append-only for the boot, so a file swapped and swapped back
//! still shows. A measurement of a file whose package was installed or
//! updated during this boot may be of either version and is not compared;
//! configuration files are expected to differ and are not compared either.
//! Only digests in a package's own algorithm can be compared: rpm's SHA-256,
//! not dpkg's MD5. On an ostree system, a file the image composed
//! differently from its rpm (os-release) is compared with what the image
//! now has, which `ostree-verify` vouches for.

use super::{path_is_code, Anchors, Check, Cost, Ctx, Unavailable};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::{Canon, Host};
use crate::pkgdb::{Manager, Verify};
use std::collections::{BTreeMap, BTreeSet};

pub struct ImaVerify;

const DIR: &str = "/sys/kernel/security/ima";

/// The measurement list: path → the distinct (algorithm, digest) measured.
fn measurements(s: &str) -> BTreeMap<String, BTreeSet<(Algo, Vec<u8>)>> {
    let mut out: BTreeMap<String, BTreeSet<(Algo, Vec<u8>)>> = BTreeMap::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        // PCR, template hash, template, file digest, path [, signature]
        if f.len() < 5 || !matches!(f[2], "ima-ng" | "ima-sig" | "ima-modsig") {
            continue;
        }
        let Some((algo, hex)) = f[3].split_once(':') else {
            continue;
        };
        let algo = match algo {
            "sha256" => Algo::Sha256,
            "sha384" => Algo::Sha384,
            "sha512" => Algo::Sha512,
            _ => continue,
        };
        let (Some(d), true) = (digest::unhex(hex), f[4].starts_with('/')) else {
            continue;
        };
        out.entry(f[4].to_string()).or_default().insert((algo, d));
    }
    out
}

fn list(host: &Host) -> anyhow::Result<String> {
    // The SHA-1 bank is always there; the file digests in it are whatever
    // ima_hash says, with their algorithm named.
    let names = ["ascii_runtime_measurements", "ascii_runtime_measurements_sha1"];
    let mut last = None;
    for n in names {
        match host.read(format!("{DIR}/{n}")) {
            Ok(b) => return Ok(String::from_utf8_lossy(&b).into_owned()),
            Err(e) => last = Some(e),
        }
    }
    let e = last.map(|e| e.to_string()).unwrap_or_default();
    Err(Unavailable(format!("the IMA measurement list cannot be read ({e}); run as root")).into())
}

/// When this boot began.
fn boot_time(host: &Host) -> u64 {
    host.read_opt("/proc/stat")
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok()))
        .unwrap_or(0)
}

impl Check for ImaVerify {
    fn id(&self) -> &'static str {
        "ima-verify"
    }

    fn description(&self) -> &'static str {
        "the kernel's IMA measurements of packaged files against package digests"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["ima-mismatch"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists(DIR)).then(|| "IMA is not enabled in this kernel".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let m = measurements(&list(ctx.host)?);
        if m.is_empty() {
            return Err(Unavailable("no IMA measurement policy is active (boot with ima_policy=tcb)".into()).into());
        }
        let db = ctx.owned()?;
        let boot = boot_time(ctx.host);
        let mut canon = Canon::new(ctx.host);
        let mut out = Vec::new();
        for (path, digests) in &m {
            let p = canon.path(path);
            // As rpm -V: files whose digest the package says not to verify
            // (caches and policies rebuilt on the host) are not compared.
            let owners: Vec<_> = db
                .lookup(&p)
                .filter(|f| f.installed && !f.config && !f.digest.is_empty() && f.verify.has(Verify::DIGEST))
                .collect();
            // On an ostree system the image may carry a composed version
            // (os-release): ostree-verify vouches for its content, so a
            // measurement of the content the image now has is not a change.
            let in_image = db.lookup(&p).any(|f| f.pkg.manager == Manager::Ostree);
            // Every owner predates the boot, with a digest to compare in a
            // measured algorithm.
            if owners.is_empty() || owners.iter().any(|f| f.pkg.install_time >= boot) {
                continue;
            }
            for (algo, d) in digests {
                let comparable: Vec<_> = owners.iter().filter(|f| f.pkg.algo == Some(*algo)).collect();
                if comparable.is_empty() || comparable.iter().any(|f| f.digest == d.as_slice()) {
                    continue;
                }
                if in_image && digest::file(*algo, &ctx.host.path(&p)).is_ok_and(|now| now == *d) {
                    continue;
                }
                let hex = digest::hex(d);
                let pkg = &comparable[0].pkg.id;
                out.push(
                    Finding::new(
                        "ima-mismatch",
                        if path_is_code(&p) {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        &p,
                        &hex,
                    )
                    .message(format!(
                        "{p} was used with content that differs from {pkg} (measured by IMA this boot)"
                    ))
                    .detail(serde_json::json!({
                        "measured": hex,
                        "expected": digest::hex(comparable[0].digest),
                        "algo": algo.name(),
                        "package": pkg,
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
    fn parses_measurements() {
        let s = "10 9797edf8d0fed6b0fc4a3fd0f4eb47ba4c1fd2a8 ima-ng sha256:7a5e5a1fd2a8e0d8f8b7e1d0c0e6d3ee58bfd6e3c3f71b7e15b5d6e8f2bb4cba boot_aggregate\n\
                 10 1111111111111111111111111111111111111111 ima-ng sha256:00ff /usr/bin/bash\n\
                 10 2222222222222222222222222222222222222222 ima-sig sha256:00ff /usr/bin/bash \n\
                 10 3333333333333333333333333333333333333333 ima-ng sha256:0102 /usr/bin/bash\n\
                 10 4444444444444444444444444444444444444444 ima sha1hex /old/template\n\
                 10 5555555555555555555555555555555555555555 ima-ng md5:00 /usr/bin/x\n";
        let m = measurements(s);
        assert_eq!(m.len(), 1, "boot_aggregate, the old template, and md5 are skipped");
        assert_eq!(m["/usr/bin/bash"].len(), 2, "distinct digests, not lines");
    }
}
