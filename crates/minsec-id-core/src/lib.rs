//! minsec-id core: host probes → checks → findings → state and sinks.
//!
//! Design goals (see docs/PLAN.md): ask the package manager and the kernel
//! instead of keeping parallel state; no file-hash database; nothing resident
//! unless the optional eBPF daemon is enabled.

pub mod check;
pub mod config;
pub mod duration;
pub mod events;
pub mod finding;
pub mod host;
pub mod inspect;
pub mod scan;
pub mod sink;
pub mod state;

pub use config::Config;
pub use finding::{Finding, Severity};
pub use host::Host;
