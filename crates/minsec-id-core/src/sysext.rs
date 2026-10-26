//! systemd-sysext and systemd-confext: extension images or directories
//! merged over `/usr` and `/opt` (sysext) or `/etc` (confext) as a read-only
//! overlay. The merge is visible as an overlay whose source is `sysext` or
//! `confext`, its lower layers named
//! `/run/systemd/{sysext,confext}/extensions/NAME/...`; the extensions' own
//! mounts are in a private namespace, so their sources are found in the
//! standard extension directories.

use crate::host::Host;
use crate::procfs::Mount;
use std::os::unix::fs::MetadataExt;

/// One merged extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub name: String,
    /// `sysext` or `confext`.
    pub class: &'static str,
    /// The hierarchy it is merged into.
    pub hierarchy: String,
}

const SYSEXT_DIRS: &[&str] = &[
    "/etc/extensions",
    "/run/extensions",
    "/var/lib/extensions",
    "/usr/local/lib/extensions",
    "/usr/lib/extensions",
    "/.extra/sysext",
];
const CONFEXT_DIRS: &[&str] = &[
    "/etc/confexts",
    "/run/confexts",
    "/var/lib/confexts",
    "/usr/local/lib/confexts",
    "/usr/lib/confexts",
    "/.extra/confext",
];

fn class_of(m: &Mount) -> Option<&'static str> {
    if m.fstype != "overlay" {
        return None;
    }
    match m.source.as_str() {
        "sysext" => Some("sysext"),
        "confext" => Some("confext"),
        _ => None,
    }
}

/// The extensions merged on this host, from the overlays' lower layers.
pub fn merged(mounts: &[Mount]) -> Vec<Extension> {
    let mut out = Vec::new();
    for m in mounts {
        let Some(class) = class_of(m) else { continue };
        let Some(lower) = m.options.split(',').find_map(|o| o.strip_prefix("lowerdir=")) else {
            continue;
        };
        let prefix = format!("/run/systemd/{class}/extensions/");
        for l in lower.split(':') {
            if let Some(name) = l.strip_prefix(&prefix).and_then(|r| r.split('/').next()) {
                out.push(Extension {
                    name: name.to_string(),
                    class,
                    hierarchy: m.target.clone(),
                });
            }
        }
    }
    out
}

/// Where an extension came from: an image file or a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Image(String),
    Directory(String),
}

pub fn source(host: &Host, e: &Extension) -> Option<Source> {
    let dirs = if e.class == "sysext" { SYSEXT_DIRS } else { CONFEXT_DIRS };
    for d in dirs {
        let img = format!("{d}/{}.raw", e.name);
        if host.path(&img).is_file() {
            return Some(Source::Image(img));
        }
        let dir = format!("{d}/{}", e.name);
        if host.path(&dir).is_dir() {
            return Some(Source::Directory(dir));
        }
    }
    None
}

/// Whether an image is mounted through dm-verity: a `CRYPT-VERITY-` device
/// mapper target over the loop device backed by it.
pub fn verity(host: &Host, image: &str) -> bool {
    let base = image.rsplit('/').next().unwrap_or(image);
    for dm in host.list_dir("/sys/block").into_iter().filter(|d| d.starts_with("dm-")) {
        let uuid = host.read_opt(format!("/sys/block/{dm}/dm/uuid")).unwrap_or_default();
        if !uuid.starts_with("CRYPT-VERITY-") {
            continue;
        }
        for slave in host.list_dir(format!("/sys/block/{dm}/slaves")) {
            let backing = host
                .read_opt(format!("/sys/block/{slave}/loop/backing_file"))
                .unwrap_or_default();
            if backing.rsplit('/').next() == Some(base) {
                return true;
            }
        }
    }
    false
}

/// Tells files an extension provides from the base `/usr`'s. overlayfs
/// marks which layer a file comes from: either each lower filesystem gets
/// its own device number, or ("xino") the layer is encoded in the top bits
/// of the inode number. A file whose device and top inode byte are not the
/// base layer's came from an extension image. A directory extension on the
/// base's own filesystem shares its marks, so a file is also an extension's
/// when that extension's tree has the path.
pub struct Layers {
    base: (u64, u64),
    dirs: Vec<std::path::PathBuf>,
}

fn layer(md: &std::fs::Metadata) -> (u64, u64) {
    (md.dev(), md.ino() >> 56)
}

impl Layers {
    /// `None` when no extension is merged over `/usr`.
    pub fn usr(host: &Host, mounts: &[Mount]) -> Option<Self> {
        mounts.iter().rev().find(|m| m.target == "/usr").and_then(class_of)?;
        // os-release is the base's: an extension carries extension-release.
        let base = layer(&std::fs::metadata(host.path("/usr/lib/os-release")).ok()?);
        let dirs = merged(mounts)
            .iter()
            .filter(|e| e.hierarchy == "/usr")
            .filter_map(|e| match source(host, e) {
                Some(Source::Directory(d)) => Some(host.path(d)),
                _ => None,
            })
            .collect();
        Some(Self { base, dirs })
    }

    /// Whether `path` (under `/usr`), with metadata `md`, is an extension's.
    pub fn is_extension_file(&self, path: &str, md: &std::fs::Metadata) -> bool {
        let rel = path.trim_start_matches('/');
        layer(md) != self.base || self.dirs.iter().any(|d| d.join(rel).symlink_metadata().is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::parse_mountinfo;

    #[test]
    fn finds_merged_extensions() {
        let m = parse_mountinfo(
            "530 46 0:61 / /usr ro,nodev,relatime shared:450 - overlay sysext ro,seclabel,\
             lowerdir=/run/systemd/sysext/meta/usr:/run/systemd/sysext/extensions/minsec-img/usr:\
             /run/systemd/sysext/extensions/minsec-dir/usr:/usr,redirect_dir=on\n\
             531 46 0:62 / /etc ro - overlay confext ro,lowerdir=/run/systemd/confext/extensions/site/etc:/etc\n\
             46 1 0:34 / / ro,relatime shared:1 - overlay composefs ro,lowerdir+=/run/ostree/.private/cfsroot-lower\n",
        );
        let e = merged(&m);
        let names: Vec<(&str, &str, &str)> = e
            .iter()
            .map(|x| (x.name.as_str(), x.class, x.hierarchy.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("minsec-img", "sysext", "/usr"),
                ("minsec-dir", "sysext", "/usr"),
                ("site", "confext", "/etc")
            ]
        );
    }
}
