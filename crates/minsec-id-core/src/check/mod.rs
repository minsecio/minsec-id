//! The check registry. Each check has a stable kebab-case id: it is what
//! operators enable, disable, and accept, and what the minsec.io registry will
//! map to categories (as minsec's filter names are).

use crate::finding::Finding;
use crate::host::Host;
use serde::{Deserialize, Serialize};

mod kernel_tainted;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cost {
    /// stat, /proc, /sys only: run every quick scan.
    Quick,
    /// Reads file contents: run in full scans only.
    Full,
}

pub struct Ctx<'a> {
    pub host: &'a Host,
}

pub trait Check: Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn cost(&self) -> Cost;
    fn default_enabled(&self) -> bool {
        true
    }
    /// Why this check cannot run on this host, if it cannot.
    fn unavailable(&self, host: &Host) -> Option<String>;
    fn run(&self, ctx: &Ctx) -> anyhow::Result<Vec<Finding>>;
}

static ALL: &[&dyn Check] = &[&kernel_tainted::KernelTainted];

pub fn all() -> &'static [&'static dyn Check] {
    ALL
}

pub fn get(id: &str) -> Option<&'static dyn Check> {
    ALL.iter().copied().find(|c| c.id() == id)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_are_unique_kebab_case() {
        let mut seen = std::collections::BTreeSet::new();
        for c in super::all() {
            let id = c.id();
            assert!(seen.insert(id), "duplicate check id {id}");
            assert!(
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "check id {id} is not kebab-case"
            );
        }
    }
}
