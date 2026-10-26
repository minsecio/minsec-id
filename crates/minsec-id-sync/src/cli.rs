//! Command definitions. Keep completions/ in sync when changing these.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "minsec-id-sync",
    version,
    about = "minsec-id crowd client: hash checks of modified package files, finding counts"
)]
pub(crate) struct Cli {
    /// Configuration file.
    #[arg(short = 'c', long, default_value = "/etc/minsec-id/sync.toml", global = true)]
    pub(crate) config: PathBuf,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Generate a key (first run) and enroll with the server.
    Enroll,
    /// Report open finding counts (also the heartbeat).
    Report,
    /// Ask the crowd about modified package files; answers go to crowd.json.
    Check,
    /// Enroll if needed, report, then check. Intended for the systemd timer;
    /// exits 0 quietly when the crowd is not configured.
    Run,
    /// Show enrollment and crowd state.
    Status,
}
