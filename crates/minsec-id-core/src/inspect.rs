//! `minsec-id inspect`: what this host offers (kernel features, package
//! managers, image-based or not), where configuration comes from, and which
//! checks can run. Stable machine-readable output with a schema version.

use crate::check::{self, Cost};
use crate::config::{self, Config};
use crate::host::Host;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;
/// The oldest kernel minsec-id supports (EL9).
pub const MIN_KERNEL: (u32, u32) = (5, 14);

const SECURE_BOOT_VAR: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    pub schema_version: u32,
    pub ok: bool,
    pub version: String,
    pub os: Os,
    pub kernel: Kernel,
    pub packages: Packages,
    pub image: Image,
    pub paths: Paths,
    pub files: Files,
    pub checks: Vec<CheckInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Os {
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Kernel {
    pub release: Option<String>,
    /// At least `MIN_KERNEL`.
    pub supported: bool,
    /// `/sys/kernel/btf/vmlinux`: needed for CO-RE eBPF.
    pub btf: bool,
    /// Active LSMs, in order.
    pub lsm: Vec<String>,
    pub bpf_lsm: bool,
    pub ima: bool,
    /// `none`, `integrity`, or `confidentiality`.
    pub lockdown: Option<String>,
    /// `None` when not booted via UEFI.
    pub secure_boot: Option<bool>,
    /// `enforcing` or `permissive`; `None` without SELinux.
    pub selinux: Option<String>,
    pub apparmor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Packages {
    pub rpm: bool,
    pub dpkg: bool,
    pub flatpak: bool,
    pub snap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Image {
    /// Booted from an ostree deployment (Fedora CoreOS, bootc, Silverblue).
    pub ostree: bool,
    /// Root filesystem type, e.g. `xfs`, `btrfs`, `composefs`.
    pub root_fstype: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub main_config: PathBuf,
    pub conf_dir: PathBuf,
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub events_file: PathBuf,
    pub control_socket: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Files {
    pub main: Option<PathBuf>,
    pub dropins: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckInfo {
    pub id: String,
    pub description: String,
    pub cost: Cost,
    pub enabled: bool,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

pub fn checks(cfg: &Config, host: &Host) -> Vec<CheckInfo> {
    check::all()
        .iter()
        .map(|c| {
            let why = c.unavailable(host);
            CheckInfo {
                id: c.id().into(),
                description: c.description().into(),
                cost: c.cost(),
                enabled: cfg.check_enabled(c.id(), c.default_enabled()),
                available: why.is_none(),
                unavailable: why,
            }
        })
        .collect()
}

pub fn inspect(config_dir: &Path, host: &Host, version: &str) -> anyhow::Result<Inspection> {
    let cfg = Config::load_dir(config_dir)?;
    let main = config_dir.join(config::MAIN_FILE);
    let kernel = kernel(host);
    Ok(Inspection {
        schema_version: SCHEMA_VERSION,
        ok: kernel.supported,
        version: version.into(),
        os: os_release(host),
        kernel,
        packages: Packages {
            rpm: crate::pkgdb::has_rpm(host),
            dpkg: crate::pkgdb::has_dpkg(host),
            flatpak: host.exists("/var/lib/flatpak/repo"),
            snap: host.exists("/var/lib/snapd/state.json"),
        },
        image: Image {
            ostree: host.exists("/run/ostree-booted"),
            root_fstype: root_fstype(host),
        },
        paths: Paths {
            config_dir: config_dir.to_path_buf(),
            main_config: main.clone(),
            conf_dir: config_dir.join("conf.d"),
            state_dir: cfg.paths.state_dir.clone(),
            state_file: cfg.state_file(),
            events_file: cfg.events_file(),
            control_socket: cfg.paths.socket.clone(),
        },
        files: Files {
            main: main.exists().then_some(main),
            dropins: config::dropins(config_dir),
        },
        checks: checks(&cfg, host),
    })
}

fn kernel(host: &Host) -> Kernel {
    let release = host.read_opt("/proc/sys/kernel/osrelease");
    let lsm: Vec<String> = host
        .read_opt("/sys/kernel/security/lsm")
        .map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect())
        .unwrap_or_default();
    Kernel {
        supported: release
            .as_deref()
            .and_then(parse_release)
            .is_some_and(|v| v >= MIN_KERNEL),
        release,
        btf: host.exists("/sys/kernel/btf/vmlinux"),
        bpf_lsm: lsm.iter().any(|l| l == "bpf"),
        ima: host.exists("/sys/kernel/security/ima") || lsm.iter().any(|l| l == "ima"),
        lockdown: host
            .read_opt("/sys/kernel/security/lockdown")
            .and_then(|s| bracketed(&s)),
        secure_boot: host.exists("/sys/firmware/efi").then(|| secure_boot(host)),
        selinux: host.read_opt("/sys/fs/selinux/enforce").map(|s| {
            if s == "1" {
                "enforcing".into()
            } else {
                "permissive".into()
            }
        }),
        apparmor: host.exists("/sys/kernel/security/apparmor") || lsm.iter().any(|l| l == "apparmor"),
        lsm,
    }
}

/// `"6.12.0-55.el10.x86_64"` → `(6, 12)`.
fn parse_release(r: &str) -> Option<(u32, u32)> {
    let mut it = r.split(|c: char| !c.is_ascii_digit());
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// The selected option in a sysfs choice list: `"[none] integrity"` → `none`.
fn bracketed(s: &str) -> Option<String> {
    let start = s.find('[')? + 1;
    let end = s[start..].find(']')? + start;
    Some(s[start..end].to_string())
}

/// The SecureBoot variable is 4 attribute bytes followed by a 1-byte value.
pub fn secure_boot(host: &Host) -> bool {
    host.read(SECURE_BOOT_VAR)
        .ok()
        .and_then(|b| b.get(4).copied())
        .is_some_and(|v| v == 1)
}

fn os_release(host: &Host) -> Os {
    let text = host
        .read_opt("/etc/os-release")
        .or_else(|| host.read_opt("/usr/lib/os-release"))
        .unwrap_or_default();
    let mut os = Os::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "ID" => os.id = Some(v),
            "VERSION_ID" => os.version_id = Some(v),
            "PRETTY_NAME" => os.pretty_name = Some(v),
            _ => {}
        }
    }
    os
}

fn root_fstype(host: &Host) -> Option<String> {
    let mounts = host.read_opt("/proc/self/mounts")?;
    // The last mount on `/` is the one in effect.
    mounts.lines().rev().find_map(|l| {
        let mut f = l.split_whitespace();
        let (_src, target, fstype) = (f.next()?, f.next()?, f.next()?);
        (target == "/").then(|| fstype.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_release() {
        assert_eq!(parse_release("5.14.0-503.el9.x86_64"), Some((5, 14)));
        assert_eq!(parse_release("7.2.11-200.fc44.x86_64"), Some((7, 2)));
        assert_eq!(parse_release("6"), None);
        assert!((5, 15) >= MIN_KERNEL && (4, 18) < MIN_KERNEL);
    }

    #[test]
    fn parses_choice_lists() {
        assert_eq!(bracketed("[none] integrity confidentiality").as_deref(), Some("none"));
        assert_eq!(
            bracketed("none [integrity] confidentiality").as_deref(),
            Some("integrity")
        );
        assert_eq!(bracketed("none"), None);
    }
}
