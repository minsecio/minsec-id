//! This client's state, in the `sync` directory of the scanner's state
//! directory: the Ed25519 identity key (`key`, 0600) and `state.json`
//! (host id, sequence, last report). The crowd's answers go beside them in
//! `crowd.json`, which the scanner reads.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub host_id: Option<String>,
    /// Next findings report sequence number (see findings.rs).
    #[serde(default)]
    pub next_seq: u64,
    /// Unix time of the last findings report the server accepted: findings
    /// first seen after it are new.
    #[serde(default)]
    pub last_report: u64,
    #[serde(default)]
    pub min_report_interval: u64,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(state_dir: &Path) -> anyhow::Result<Self> {
        let dir = state_dir.join("sync");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", dir.display()))?;
        Ok(Self { dir })
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn load_state(&self) -> anyhow::Result<State> {
        match std::fs::read(self.state_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt {}: {e}", self.state_path().display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", self.state_path().display())),
        }
    }

    pub fn save_state(&self, state: &State) -> anyhow::Result<()> {
        let tmp = self.dir.join("state.json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(state)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, self.state_path())?;
        Ok(())
    }

    pub fn load_or_create_key(&self) -> anyhow::Result<SigningKey> {
        Ok(minsec_proto::key::load_or_create(&self.dir)?)
    }

    pub fn rotate_key(&self) -> anyhow::Result<SigningKey> {
        Ok(minsec_proto::key::rotate(&self.dir)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_in_private_dir() {
        let base = std::env::temp_dir().join(format!("minsec-id-sync-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let store = Store::open(&base).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(base.join("sync")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(store.load_state().unwrap().host_id.is_none());
        let st = State {
            host_id: Some("h".into()),
            next_seq: 9,
            last_report: 7,
            min_report_interval: 3600,
        };
        store.save_state(&st).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(
            (back.host_id.as_deref(), back.next_seq, back.last_report),
            (Some("h"), 9, 7)
        );
        let k = store.load_or_create_key().unwrap();
        assert_eq!(k.to_bytes(), store.load_or_create_key().unwrap().to_bytes());
        let _ = std::fs::remove_dir_all(&base);
    }
}
