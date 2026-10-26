//! Loaded kernel modules: where each came from (`kmod-unowned`) and whether
//! the kernel's views of the module list agree (`kmod-hidden`). Rootkits
//! that unlink themselves from the module list usually forget one view.

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::{Canon, Host};
use std::collections::{BTreeMap, BTreeSet};

pub struct KmodUnowned;
pub struct KmodHidden;

/// Names in `/proc/modules`.
fn proc_modules(host: &Host) -> Option<BTreeSet<String>> {
    let s = host.read_opt("/proc/modules")?;
    Some(
        s.lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(String::from)
            .collect(),
    )
}

/// Loadable modules in sysfs: built-ins have a `/sys/module` entry too, but
/// only loaded modules have `initstate`.
fn sysfs_modules(host: &Host) -> BTreeSet<String> {
    host.list_dir("/sys/module")
        .into_iter()
        .filter(|m| host.exists(format!("/sys/module/{m}/initstate")))
        .collect()
}

/// Module names that own symbols in `/proc/kallsyms` (`[name]` tags).
fn kallsyms_modules(host: &Host) -> BTreeSet<String> {
    let Ok(s) = std::fs::read_to_string(host.path("/proc/kallsyms")) else {
        return BTreeSet::new();
    };
    s.lines()
        .filter_map(|l| {
            let tag = l.rsplit_once('[')?.1.strip_suffix(']')?;
            // Pseudo-modules for BPF, ftrace, and kprobe trampolines.
            (!tag.is_empty() && tag != "bpf" && !tag.starts_with("__builtin")).then(|| tag.to_string())
        })
        .collect()
}

/// `modules.dep`: module name → path, for the running kernel.
pub(crate) fn modules_dep(host: &Host) -> Option<(String, BTreeMap<String, String>)> {
    let rel = host.read_opt("/proc/sys/kernel/osrelease")?;
    let base = format!("/usr/lib/modules/{rel}");
    let base = if host.exists(&base) {
        base
    } else {
        format!("/lib/modules/{rel}")
    };
    let dep = host.read_opt(format!("{base}/modules.dep"))?;
    let map = dep
        .lines()
        .filter_map(|l| {
            let path = l.split(':').next()?.trim();
            let file = path.rsplit('/').next()?;
            let name = file.split(".ko").next()?.replace('-', "_");
            let abs = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("{base}/{path}")
            };
            Some((name, abs))
        })
        .collect();
    Some((base, map))
}

impl Check for KmodUnowned {
    fn id(&self) -> &'static str {
        "kmod-unowned"
    }

    fn description(&self) -> &'static str {
        "loaded kernel modules not installed by a package"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/modules")).then(|| "kernel without loadable modules".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.owned()?;
        let loaded = proc_modules(host).unwrap_or_default();
        let (_, dep) = modules_dep(host).unwrap_or_default();
        let mut canon = Canon::new(host);
        let mut out = Vec::new();
        for m in loaded {
            let (severity, message, path) = match dep.get(&m) {
                None => (
                    Severity::High,
                    format!("module {m} is loaded but not in modules.dep: loaded from an arbitrary path"),
                    None,
                ),
                Some(p) => {
                    let p = canon.path(p);
                    if db.owns(&p) {
                        continue;
                    }
                    let dkms = p.contains("/updates/dkms/") || p.contains("/extra/");
                    (
                        if dkms { Severity::Low } else { Severity::Medium },
                        format!(
                            "module {m} ({p}) is not owned by any package{}",
                            if dkms { " (DKMS-built)" } else { "" }
                        ),
                        Some(p),
                    )
                }
            };
            out.push(
                Finding::new(self.id(), severity, &m, path.as_deref().unwrap_or(""))
                    .message(message)
                    .detail(serde_json::json!({ "path": path })),
            );
        }
        Ok(out)
    }
}

impl Check for KmodHidden {
    fn id(&self) -> &'static str {
        "kmod-hidden"
    }

    fn description(&self) -> &'static str {
        "kernel modules missing from one of the kernel's module lists"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/modules")).then(|| "kernel without loadable modules".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let diff = || {
            let listed = proc_modules(host).unwrap_or_default();
            let sysfs = sysfs_modules(host);
            let syms = kallsyms_modules(host);
            let unlisted: BTreeSet<String> = sysfs.union(&syms).filter(|m| !listed.contains(*m)).cloned().collect();
            let no_sysfs: BTreeSet<String> = listed.difference(&sysfs).cloned().collect();
            (unlisted, no_sysfs, syms)
        };
        let (a1, b1, _) = diff();
        if a1.is_empty() && b1.is_empty() {
            return Ok(Vec::new());
        }
        // A module loading or unloading mid-read shows up in one view first:
        // only a difference that persists is reported.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (a2, b2, syms) = diff();
        let mut out = Vec::new();
        for m in a1.intersection(&a2) {
            out.push(
                Finding::new(self.id(), Severity::Critical, m, "unlisted")
                    .message(format!("module {m} is present in the kernel but hidden from /proc/modules"))
                    .detail(serde_json::json!({ "in_sysfs": sysfs_modules(host).contains(m), "in_kallsyms": syms.contains(m) })),
            );
        }
        for m in b1.intersection(&b2) {
            out.push(
                Finding::new(self.id(), Severity::High, m, "no-sysfs")
                    .message(format!("module {m} is in /proc/modules but hidden from /sys/module")),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_module_views() {
        let root = std::env::temp_dir().join(format!("minsec-id-kmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in [
            "proc/sys/kernel",
            "sys/module/xfs",
            "sys/module/rk",
            "sys/module/builtin",
            "usr/lib/modules/6.1.0",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("proc/modules"), "xfs 1 0 - Live 0x0\n").unwrap();
        std::fs::write(root.join("sys/module/xfs/initstate"), "live\n").unwrap();
        std::fs::write(root.join("sys/module/rk/initstate"), "live\n").unwrap();
        std::fs::write(root.join("proc/kallsyms"), "0 t f [xfs]\n0 t g [bpf]\n0 t h\n").unwrap();
        std::fs::write(root.join("proc/sys/kernel/osrelease"), "6.1.0\n").unwrap();
        std::fs::write(
            root.join("usr/lib/modules/6.1.0/modules.dep"),
            "kernel/fs/xfs/xfs.ko.xz: libcrc32c\n",
        )
        .unwrap();
        let h = Host::with_root(&root);
        assert_eq!(sysfs_modules(&h), BTreeSet::from(["rk".to_string(), "xfs".to_string()]));
        assert_eq!(kallsyms_modules(&h), BTreeSet::from(["xfs".to_string()]));
        let (_, dep) = modules_dep(&h).unwrap();
        assert_eq!(dep["xfs"], "/usr/lib/modules/6.1.0/kernel/fs/xfs/xfs.ko.xz");
        std::fs::remove_dir_all(root).unwrap();
    }
}
