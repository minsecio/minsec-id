//! `kernel-tainted`: decode `/proc/sys/kernel/tainted` and name the modules
//! responsible (`/sys/module/*/taint`). Taint is sticky until reboot, so a
//! finding is scoped to the boot: the same flag re-reports after a reboot only
//! if it is set again.

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;

pub struct KernelTainted;

const TAINTED: &str = "/proc/sys/kernel/tainted";

/// (bit, flag letter, meaning, severity). From the kernel's
/// Documentation/admin-guide/tainted-kernels.rst.
const FLAGS: &[(u32, char, &str, Severity)] = &[
    (0, 'P', "proprietary module loaded", Severity::Low),
    (1, 'F', "module was force-loaded", Severity::High),
    (
        2,
        'S',
        "kernel running on an out-of-specification system",
        Severity::Low,
    ),
    (3, 'R', "module was force-unloaded", Severity::Medium),
    (4, 'M', "machine check exception", Severity::Info),
    (5, 'B', "bad page referenced", Severity::Info),
    (6, 'U', "taint requested by userspace", Severity::Medium),
    (7, 'D', "kernel oops or BUG", Severity::Medium),
    (8, 'A', "ACPI table overridden", Severity::Medium),
    (9, 'W', "kernel warning", Severity::Low),
    (10, 'C', "staging driver loaded", Severity::Low),
    (11, 'I', "platform firmware workaround applied", Severity::Info),
    (12, 'O', "out-of-tree module loaded", Severity::Medium),
    (13, 'E', "unsigned module loaded", Severity::High),
    (14, 'L', "soft lockup", Severity::Info),
    (15, 'K', "kernel live-patched", Severity::Info),
    (16, 'X', "distribution-defined auxiliary taint", Severity::Info),
    (17, 'T', "built with the struct randomization plugin", Severity::Info),
    (18, 'N', "in-kernel test run", Severity::Low),
    (19, 'J', "userspace used a mutating debug interface", Severity::Medium),
];

impl Check for KernelTainted {
    fn id(&self) -> &'static str {
        "kernel-tainted"
    }

    fn description(&self) -> &'static str {
        "kernel taint flags, with the modules responsible"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists(TAINTED)).then(|| format!("{TAINTED} is missing"))
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let raw = host.read_trim(TAINTED).map_err(|e| anyhow::anyhow!("{TAINTED}: {e}"))?;
        let mask: u64 = raw
            .parse()
            .map_err(|_| anyhow::anyhow!("{TAINTED}: unexpected contents `{raw}`"))?;
        let boot = host.boot_id().unwrap_or_default();
        let modules = module_taints(host);
        let packaged = packaged_modules(ctx, &modules);
        Ok(decode(mask)
            .into_iter()
            .map(|(bit, flag)| {
                let (letter, meaning, severity) = match flag {
                    Some((l, m, s)) => (l.to_string(), m.to_string(), s),
                    None => (
                        format!("bit{bit}"),
                        format!("unknown taint bit {bit}"),
                        Severity::Medium,
                    ),
                };
                let culprits: Vec<&str> = modules
                    .iter()
                    .filter(|(_, t)| t.contains(letter.as_str()))
                    .map(|(m, _)| m.as_str())
                    .collect();
                // Out-of-tree and proprietary modules a package installed, and
                // signed (Ubuntu's zfs, a packaged NVIDIA driver), are the
                // distribution's choice: still reported, but as information.
                let from_packages = matches!(letter.as_str(), "P" | "O")
                    && !culprits.is_empty()
                    && culprits.iter().all(|m| packaged.contains(*m));
                let severity = if from_packages { Severity::Info } else { severity };
                let message = if culprits.is_empty() {
                    format!("kernel tainted ({letter}): {meaning}")
                } else {
                    format!(
                        "kernel tainted ({letter}): {meaning}: {}{}",
                        culprits.join(", "),
                        if from_packages { " (signed, from packages)" } else { "" }
                    )
                };
                Finding::new(self.id(), severity, &letter, &format!("{boot}\0{}", culprits.join(",")))
                    .message(message)
                    .detail(serde_json::json!({ "bit": bit, "meaning": meaning, "modules": culprits }))
            })
            .collect())
    }
}

type Flag = (char, &'static str, Severity);

/// Set bits of the taint mask, each with its documented meaning if known.
fn decode(mask: u64) -> Vec<(u32, Option<Flag>)> {
    (0..64)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| {
            let flag = FLAGS.iter().find(|f| f.0 == bit).map(|f| (f.1, f.2, f.3));
            (bit, flag)
        })
        .collect()
}

/// The tainting modules that are signed (not `E`) and whose file a package
/// installed.
fn packaged_modules(ctx: &Ctx, modules: &[(String, String)]) -> std::collections::HashSet<String> {
    let Ok(db) = ctx.owned() else {
        return Default::default();
    };
    let (_, dep) = super::kmod::modules_dep(ctx.host).unwrap_or_default();
    let mut canon = crate::host::Canon::new(ctx.host);
    modules
        .iter()
        .filter(|(m, t)| !t.contains('E') && dep.get(m).is_some_and(|p| db.owns(&canon.path(p))))
        .map(|(m, _)| m.clone())
        .collect()
}

/// (module, taint letters) for every loaded module that taints the kernel.
fn module_taints(host: &Host) -> Vec<(String, String)> {
    host.list_dir("/sys/module")
        .into_iter()
        .filter_map(|m| {
            let t = host.read_opt(format!("/sys/module/{m}/taint"))?;
            (!t.is_empty()).then_some((m, t))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bits() {
        assert!(decode(0).is_empty());
        // P + O + E, as an unsigned out-of-tree proprietary driver would set.
        let d = decode(1 | (1 << 12) | (1 << 13));
        let letters: Vec<char> = d.iter().map(|(_, f)| f.unwrap().0).collect();
        assert_eq!(letters, vec!['P', 'O', 'E']);
        assert_eq!(d[2].1.unwrap().2, Severity::High);
        let unknown = decode(1 << 40);
        assert_eq!(unknown, vec![(40, None)]);
    }

    #[test]
    fn table_is_consistent() {
        for (i, f) in FLAGS.iter().enumerate() {
            assert_eq!(f.0 as usize, i, "FLAGS must be in bit order without gaps");
        }
    }
}
