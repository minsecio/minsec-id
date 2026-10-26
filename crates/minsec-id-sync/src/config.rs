//! `/etc/minsec-id/sync.toml`: the crowd client's own config file, separate
//! from minsec-id.toml. Every field has a default; the file's existence is
//! the opt-in switch for the systemd timer (`run` exits quietly without it).

use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_SERVER: &str = "https://api.minsec.io";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/minsec-id";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Backend base URL.
    pub server: String,
    /// The scanner's state directory: its state.json is read; the `sync`
    /// directory in it is this client's.
    pub state_dir: PathBuf,
    /// Report finding counts per check (also this host's heartbeat).
    pub findings: bool,
    /// Ask the crowd about package files whose content changed.
    pub hashcheck: bool,
    /// Include rpm packages no key signed in hash checks. Their names are
    /// often local (an in-house build), so they are left out by default.
    pub unsigned: bool,
    /// Packages never named in a hash check: globs over the package id,
    /// where `*` matches anything (`oneleet-*`, `*.local.*`).
    pub exclude: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: DEFAULT_SERVER.into(),
            state_dir: DEFAULT_STATE_DIR.into(),
            findings: true,
            hashcheck: true,
            unsigned: false,
            exclude: Vec::new(),
        }
    }
}

impl Config {
    /// Load the config file. `Ok(None)` when it does not exist (the crowd
    /// is not configured).
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
        };
        let cfg: Config = toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        if !cfg.server.starts_with("http://") && !cfg.server.starts_with("https://") {
            anyhow::bail!("{}: server must be an http(s) URL", path.display());
        }
        Ok(Some(cfg))
    }

    pub fn excluded(&self, package: &str) -> bool {
        self.exclude.iter().any(|g| glob(g, package))
    }
}

/// `*` matches any run of characters; everything else matches itself.
fn glob(pattern: &str, s: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == s;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !s.starts_with(first) || s.len() < first.len() + last.len() || !s.ends_with(last) {
        return false;
    }
    let mut rest = &s[first.len()..s.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let cfg: Config = toml::from_str("hashcheck = false\nexclude = [\"acme-*\"]\n").unwrap();
        assert!(!cfg.hashcheck && cfg.findings && !cfg.unsigned);
        assert_eq!(cfg.server, DEFAULT_SERVER);
        assert!(cfg.excluded("acme-agent-1.0-1.x86_64"));
        assert!(!cfg.excluded("coreutils-9.5-1.fc44.x86_64"));
        assert!(toml::from_str::<Config>("hashchek = false\n").is_err());
    }

    #[test]
    fn globs() {
        assert!(glob("a*", "abc"));
        assert!(glob("*c", "abc"));
        assert!(glob("a*c", "abc"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(glob("*", ""));
        assert!(glob("abc", "abc"));
        assert!(!glob("abc", "abcd"));
        assert!(!glob("a*c", "ab"));
        assert!(!glob("ab*bc", "abc"), "the two ends may not overlap");
        assert!(!glob("a*x*c", "abc"));
    }
}
