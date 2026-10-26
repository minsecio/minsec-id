//! An ostree system's booted commit as an owner: on an image-based system
//! the image, not the rpm database, says which files belong in `/usr`
//! (scripts and units added when the image was composed belong to no rpm).

use super::{Builder, Manager, Package, RawFile, Verify};
use crate::host::Host;
use crate::ostree::{self, Repo};
use std::os::unix::fs::MetadataExt;

pub(crate) fn load(host: &Host, b: &mut Builder) -> anyhow::Result<()> {
    let booted = ostree::booted(host)?;
    let repo = Repo::open(host.path(ostree::SYSTEM_REPO))?;
    let commit = repo.commit(&booted.commit)?;
    let install_time = std::fs::metadata(
        booted
            .dir
            .with_extension(format!("{}.origin", booted.name.rsplit('.').next().unwrap_or("0"))),
    )
    .map(|m| m.ctime().max(0) as u64)
    .unwrap_or(0);
    let pkg = b.package(Package {
        manager: Manager::Ostree,
        name: booted.stateroot.clone(),
        id: format!("ostree:{}@{}", booted.stateroot, &ostree::hex(&booted.commit)[..12]),
        install_time,
        algo: None,
        key_id: None,
        summary: "the booted ostree deployment".into(),
    });
    let mut paths = Vec::new();
    repo.walk(&commit.root_tree, &mut |rel, c| {
        if c.is_some() && rel.starts_with("usr/") {
            paths.push(format!("/{rel}"));
        }
    })?;
    for p in &paths {
        b.file(
            pkg,
            RawFile {
                path: p,
                digest_hex: "",
                size: None,
                mode: None,
                mtime: None,
                link: None,
                config: false,
                doc: false,
                ghost: false,
                missingok: false,
                installed: true,
                verify: Verify(0),
            },
        );
    }
    Ok(())
}
