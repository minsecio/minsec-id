//! Command definitions.

use clap::{Parser, Subcommand};
use minsec_id_core::config::DEFAULT_CONFIG_DIR;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "minsec-id",
    version,
    about = "Minimalist intrusion detection for modern Linux"
)]
pub(crate) struct Cli {
    /// Configuration directory.
    #[arg(short = 'c', long, default_value = DEFAULT_CONFIG_DIR, global = true)]
    pub(crate) config_dir: PathBuf,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Examine a host tree mounted here instead of `/` (tests, offline images).
    #[arg(long, default_value = "/", global = true, hide = true)]
    pub(crate) root: PathBuf,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Run checks. Exits 0 when clean, 2 with open findings, 1 on error.
    Scan {
        /// Run every enabled check, including ones that read file contents.
        #[arg(long, conflicts_with = "quick")]
        full: bool,
        /// Run only cheap checks (the default).
        #[arg(long)]
        quick: bool,
        /// Run only this check (repeatable), even if disabled.
        #[arg(long = "check", value_name = "ID")]
        checks: Vec<String>,
        /// Print nothing; findings still go to the log, journal, and hook.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Last scan and open findings.
    Status,
    /// List open findings.
    Findings {
        /// Include accepted findings.
        #[arg(long)]
        all: bool,
        /// Only findings at or above this severity.
        #[arg(long, value_name = "SEVERITY")]
        severity: Option<String>,
    },
    /// Show one finding in full.
    Show {
        /// Fingerprint, or `check:subject`.
        finding: String,
    },
    /// Accept a finding (writes conf.d/accept.toml).
    Accept {
        /// Fingerprint, or `check:subject` (a trailing `*` matches by prefix).
        finding: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove an accept rule from conf.d/accept.toml.
    Unaccept {
        /// `check:subject`, as written by `accept`.
        key: String,
    },
    /// Verify a file, or every file of a package, against the package database.
    /// Exits 0 when intact, 2 when anything differs.
    Verify {
        /// An absolute path, or a package name.
        target: String,
    },
    /// Show the recorded baselines, or reset them after reviewing a change.
    Baseline {
        /// Forget the baselines; the next scan records the current state.
        #[arg(long)]
        reset: bool,
        /// Only this check's baseline (repeatable).
        #[arg(long = "check", value_name = "ID")]
        checks: Vec<String>,
    },
    /// List checks, with cost and availability on this host.
    Checks,
    /// Enable a check (writes conf.d/<check>.toml).
    Enable { check: String },
    /// Disable a check.
    Disable { check: String },
    /// Report host capabilities, configuration sources, and checks.
    Inspect,
    /// Validate configuration.
    Check,
    /// Print the findings log.
    Events {
        #[arg(short = 'n', long, default_value_t = 50)]
        last: usize,
    },
}
