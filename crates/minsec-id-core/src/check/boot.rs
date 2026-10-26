//! Boot and kernel security posture.
//!
//! `boot-posture` records lockdown, Secure Boot, module signature
//! enforcement, the LSM modes, and hardening sysctls on its first run, and
//! reports any that later get weaker (stronger values are adopted silently).
//! It also reports command-line parameters that disable protections
//! (`boot-cmdline`) whenever they are present.
//!
//! `boot-kernel` compares each installed kernel image in `/boot` with the
//! packaged copy the distribution keeps under `/usr/lib/modules`.

use super::{Anchors, Check, Cost, Ctx};
use crate::digest;
use crate::finding::{Finding, Severity};
use crate::host::Host;

pub struct BootPosture;
pub struct BootKernel;

/// (key, how to read it, strength ranks for known values, severity of a
/// regression). An unknown value ranks as its numeric value when it parses.
struct Item {
    key: &'static str,
    path: &'static str,
    ranks: &'static [(&'static str, i32)],
    severity: Severity,
}

const ITEMS: &[Item] = &[
    Item {
        key: "sig_enforce",
        path: "/sys/module/module/parameters/sig_enforce",
        ranks: &[("N", 0), ("Y", 1)],
        severity: Severity::High,
    },
    Item {
        key: "selinux",
        path: "/sys/fs/selinux/enforce",
        ranks: SELINUX_RANKS,
        severity: Severity::High,
    },
    Item {
        key: "apparmor",
        path: "/sys/module/apparmor/parameters/enabled",
        ranks: &[("N", 0), ("Y", 1)],
        severity: Severity::High,
    },
    Item {
        key: "kptr_restrict",
        path: "/proc/sys/kernel/kptr_restrict",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "dmesg_restrict",
        path: "/proc/sys/kernel/dmesg_restrict",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "ptrace_scope",
        path: "/proc/sys/kernel/yama/ptrace_scope",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "unprivileged_bpf_disabled",
        // 1 cannot be undone without a reboot; 2 can.
        path: "/proc/sys/kernel/unprivileged_bpf_disabled",
        ranks: &[("0", 0), ("2", 1), ("1", 2)],
        severity: Severity::Medium,
    },
    Item {
        key: "modules_disabled",
        path: "/proc/sys/kernel/modules_disabled",
        ranks: &[],
        severity: Severity::High,
    },
    Item {
        key: "kexec_load_disabled",
        path: "/proc/sys/kernel/kexec_load_disabled",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "randomize_va_space",
        path: "/proc/sys/kernel/randomize_va_space",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "perf_event_paranoid",
        path: "/proc/sys/kernel/perf_event_paranoid",
        ranks: &[],
        severity: Severity::Low,
    },
    Item {
        key: "protected_symlinks",
        path: "/proc/sys/fs/protected_symlinks",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "protected_hardlinks",
        path: "/proc/sys/fs/protected_hardlinks",
        ranks: &[],
        severity: Severity::Medium,
    },
    Item {
        key: "suid_dumpable",
        path: "/proc/sys/fs/suid_dumpable",
        ranks: &[("1", 0), ("2", 1), ("0", 2)],
        severity: Severity::Medium,
    },
];

/// (key, current value, strength ranks, severity of a regression)
type Reading = (&'static str, String, &'static [(&'static str, i32)], Severity);

const SELINUX_RANKS: &[(&str, i32)] = &[("disabled", 0), ("0", 1), ("1", 2)];
const LOCKDOWN_RANKS: &[(&str, i32)] = &[("none", 0), ("integrity", 1), ("confidentiality", 2)];

fn rank(ranks: &[(&str, i32)], v: &str) -> Option<i32> {
    match ranks.iter().find(|(k, _)| *k == v) {
        Some((_, r)) => Some(*r),
        None if ranks.is_empty() => v.parse().ok(),
        None => None,
    }
}

/// Parameters that switch off a protection or hand over early boot.
fn dangerous_param(p: &str) -> Option<(Severity, &'static str)> {
    let (k, v) = p.split_once('=').unwrap_or((p, ""));
    Some(match (k, v) {
        ("init" | "rdinit", _) => (Severity::High, "replaces the init program"),
        ("selinux", "0") => (Severity::High, "disables SELinux"),
        ("enforcing", "0") => (Severity::High, "boots SELinux permissive"),
        ("apparmor", "0") => (Severity::High, "disables AppArmor"),
        ("security", "none") => (Severity::High, "disables the major LSM"),
        ("lsm", _) if !v.contains("selinux") && !v.contains("apparmor") => {
            (Severity::Medium, "LSM list without SELinux or AppArmor")
        }
        ("ima_appraise", "off" | "fix" | "log") => (Severity::High, "turns off IMA appraisal"),
        ("module.sig_enforce", "0") => (Severity::Medium, "turns off module signature enforcement"),
        ("rd.break" | "single" | "emergency" | "rescue", _) => (Severity::High, "boots to a root shell"),
        ("systemd.unit", "rescue.target" | "emergency.target") => (Severity::High, "boots to a root shell"),
        ("nokaslr", _) => (Severity::Medium, "disables kernel address randomization"),
        ("mitigations", "off") => (Severity::Low, "disables CPU vulnerability mitigations"),
        _ => return None,
    })
}

/// The command line without the per-boot image path, for comparison.
fn normalized_cmdline(s: &str) -> String {
    let mut parts: Vec<&str> = s
        .split_whitespace()
        .filter(|p| !p.starts_with("BOOT_IMAGE=") && !p.starts_with("initrd="))
        .collect();
    parts.sort();
    parts.join(" ")
}

impl Check for BootPosture {
    fn id(&self) -> &'static str {
        "boot-posture"
    }

    fn description(&self) -> &'static str {
        "lockdown, Secure Boot, LSM modes, and hardening sysctls getting weaker"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["boot-cmdline"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/cmdline")).then(|| "/proc/cmdline is missing".into())
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let mut out = Vec::new();
        let mut values: Vec<Reading> = ITEMS
            .iter()
            .filter_map(|i| Some((i.key, host.read_opt(i.path)?, i.ranks, i.severity)))
            .collect();
        if let Some(l) = host.read_opt("/sys/kernel/security/lockdown").and_then(|s| {
            let start = s.find('[')? + 1;
            Some(s[start..start + s[start..].find(']')?].to_string())
        }) {
            values.push(("lockdown", l, LOCKDOWN_RANKS, Severity::High));
        }
        if host.exists("/sys/firmware/efi") {
            let sb = crate::inspect::secure_boot(host);
            values.push((
                "secure_boot",
                if sb { "1" } else { "0" }.into(),
                &[("0", 0), ("1", 1)],
                Severity::High,
            ));
        }
        // SELinux that was enforcing and is now absent was disabled at boot.
        if anchors.map.contains_key("selinux") && !host.exists("/sys/fs/selinux/enforce") {
            values.push(("selinux", "disabled".into(), SELINUX_RANKS, Severity::High));
        }

        for (key, value, ranks, severity) in values {
            match anchors.map.get(key).cloned() {
                None => anchors.set(key, &value),
                Some(old) if old == value => {}
                Some(old) => match (rank(ranks, &old), rank(ranks, &value)) {
                    (Some(a), Some(b)) if b < a => out.push(
                        Finding::new(self.id(), severity, key, &value)
                            .message(format!("{key} weakened from {old} to {value}"))
                            .detail(serde_json::json!({ "baseline": old, "now": value })),
                    ),
                    // Stronger, or not comparable: the new value is the baseline.
                    _ => anchors.set(key, &value),
                },
            }
        }

        if host.read_opt("/sys/kernel/kexec_loaded").as_deref() == Some("1") {
            out.push(
                Finding::new(self.id(), Severity::Medium, "kexec_loaded", "")
                    .message("a kexec kernel is staged to replace the running one"),
            );
        }

        let cmdline = host.read_opt("/proc/cmdline").unwrap_or_default();
        for p in cmdline.split_whitespace() {
            if let Some((severity, why)) = dangerous_param(p) {
                out.push(
                    Finding::new("boot-cmdline", severity, p, "")
                        .message(format!("kernel command line has {p}: {why}")),
                );
            }
        }
        let norm = normalized_cmdline(&cmdline);
        if let Some(old) = anchors.observe("cmdline", &norm) {
            out.push(
                Finding::new(self.id(), Severity::Low, "cmdline", &norm)
                    .message("kernel command line changed since the baseline")
                    .detail(serde_json::json!({ "baseline": old, "now": norm })),
            );
        }
        Ok(out)
    }
}

impl Check for BootKernel {
    fn id(&self) -> &'static str {
        "boot-kernel"
    }

    fn description(&self) -> &'static str {
        "kernel images in /boot compared with their packaged copies"
    }

    fn cost(&self) -> Cost {
        Cost::Full
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/boot")).then(|| "no /boot".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let db = ctx.owned()?;
        let mut out = Vec::new();
        for name in host.list_dir("/boot") {
            let Some(ver) = name.strip_prefix("vmlinuz-") else {
                continue;
            };
            let boot_path = format!("/boot/{name}");
            if db.lookup(&boot_path).any(|f| !f.digest.is_empty()) {
                continue; // packaged as itself (Debian): pkg-verify covers it.
            }
            let packaged = format!("/usr/lib/modules/{ver}/vmlinuz");
            let Some(src) = db.lookup(&packaged).find(|f| !f.digest.is_empty()) else {
                if !db.owns(&boot_path) && !ver.contains("rescue") {
                    out.push(
                        Finding::new(self.id(), Severity::Medium, &boot_path, "unowned")
                            .message(format!("{boot_path} matches no installed kernel package")),
                    );
                }
                continue;
            };
            let Some(algo) = src.pkg.algo else { continue };
            let got = match digest::file(algo, &host.path(&boot_path)) {
                Ok(d) => d,
                Err(e) => anyhow::bail!("{boot_path}: {e}"),
            };
            if got != src.digest {
                out.push(
                    Finding::new(self.id(), Severity::High, &boot_path, &digest::hex(&got))
                        .message(format!("{boot_path} differs from the kernel package's {packaged}"))
                        .detail(serde_json::json!({
                            "package": src.pkg.id,
                            "expected": digest::hex(src.digest),
                            "actual": digest::hex(&got),
                            "algo": algo.name(),
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
    fn ranks_and_params() {
        assert!(rank(LOCKDOWN_RANKS, "none") < rank(LOCKDOWN_RANKS, "integrity"));
        assert_eq!(rank(&[], "2"), Some(2));
        assert_eq!(rank(&[("N", 0)], "?"), None);
        assert!(dangerous_param("init=/bin/sh").is_some());
        assert!(dangerous_param("selinux=1").is_none());
        assert!(dangerous_param("quiet").is_none());
        assert_eq!(normalized_cmdline("BOOT_IMAGE=/v ro quiet root=x"), "quiet ro root=x");
    }
}
