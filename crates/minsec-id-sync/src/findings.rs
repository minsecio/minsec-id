//! `minsec-id-sync report`: the host's open findings, counted per check and
//! severity, as the scanner left them in state.json. Counts only: no
//! subject, message, or detail leaves the host. Each report is also the
//! host's heartbeat.
//!
//! Sequence numbers work as minsec-sync's do: `max(stored next_seq, unix
//! time)`, so they survive a lost state file; on a duplicate (clock
//! rollback) jump a day ahead and retry once.

use crate::client::{now_unix, Api, AGENT_VERSION};
use crate::config::Config;
use crate::store::{State, Store};
use ed25519_dalek::SigningKey;
use minsec_id_core::state::State as ScanState;
use minsec_proto::types::{FindingCount, FindingsReport, FindingsResponse, OsInfo};
use std::collections::BTreeMap;

const SEQ_JUMP: u64 = 86_400;

/// The report for `scan`, counting as new what was first seen after
/// `since`. Its seq is left for the caller.
pub fn build(scan: &ScanState, since: u64, os: OsInfo) -> FindingsReport {
    let mut counts: BTreeMap<(String, &str), FindingCount> = BTreeMap::new();
    for o in scan.open.values() {
        let f = &o.finding;
        let c = counts
            .entry((f.check.clone(), f.severity.as_str()))
            .or_insert_with(|| FindingCount {
                check: f.check.clone(),
                severity: f.severity.as_str().into(),
                open: 0,
                accepted: 0,
                new: 0,
            });
        if o.accepted.is_some() {
            c.accepted += 1;
        } else {
            c.open += 1;
            if o.first_seen > since {
                c.new += 1;
            }
        }
    }
    FindingsReport {
        seq: 0,
        agent_version: AGENT_VERSION.into(),
        os,
        checks: scan.last_scan.as_ref().map(|l| l.checks.clone()).unwrap_or_default(),
        counts: counts.into_values().collect(),
        label: None,
    }
}

pub struct Outcome {
    pub counts: usize,
    pub accepted: u64,
}

pub fn run(cfg: &Config, api: &Api, store: &Store, st: &mut State, key: &SigningKey) -> anyhow::Result<Outcome> {
    let host_id = st.host_id.clone().ok_or_else(|| anyhow::anyhow!("not enrolled"))?;
    let scan = ScanState::load(&cfg.state_dir.join("state.json"))?;
    let mut rep = build(&scan, st.last_report, crate::os::release());
    rep.seq = st.next_seq.max(now_unix());
    // A host in an organization keeps its fleet name current.
    if st.org.is_some() {
        rep.label = cfg.label();
    }
    let mut resp: FindingsResponse = api.post_signed(
        "/v1/findings",
        minsec_proto::sign::PURPOSE_FINDINGS,
        key,
        &host_id,
        &rep,
    )?;
    if resp.duplicate {
        rep.seq += SEQ_JUMP;
        resp = api.post_signed(
            "/v1/findings",
            minsec_proto::sign::PURPOSE_FINDINGS,
            key,
            &host_id,
            &rep,
        )?;
        if resp.duplicate {
            anyhow::bail!("server rejects our sequence numbers as duplicates; will retry next run");
        }
    }
    st.next_seq = rep.seq + 1;
    // New next time means first seen by a scan after the newest finding
    // this report counted.
    st.last_report = scan
        .open
        .values()
        .map(|o| o.first_seen)
        .max()
        .unwrap_or(0)
        .max(st.last_report);
    store.save_state(st)?;
    Ok(Outcome {
        counts: rep.counts.len(),
        accepted: resp.accepted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use minsec_id_core::state::OpenFinding;
    use minsec_id_core::{Finding, Severity};

    fn open(check: &str, sev: Severity, subject: &str, first_seen: u64, accepted: bool) -> OpenFinding {
        OpenFinding {
            finding: Finding::new(check, sev, subject, "").message("secret detail about the host"),
            first_seen,
            last_seen: first_seen,
            accepted: accepted.then(|| "rule".to_string()),
        }
    }

    #[test]
    fn counts_only() {
        let mut scan = ScanState::default();
        for o in [
            open("pkg-modified", Severity::High, "/usr/bin/a", 100, false),
            open("pkg-modified", Severity::High, "/usr/bin/b", 200, false),
            open("pkg-modified", Severity::Medium, "/usr/share/c", 50, false),
            open("exe-unowned", Severity::High, "/usr/bin/minsec-id", 300, true),
        ] {
            scan.open.insert(o.finding.fingerprint.clone(), o);
        }
        let rep = build(&scan, 150, OsInfo::default());
        let got: Vec<_> = rep
            .counts
            .iter()
            .map(|c| (c.check.as_str(), c.severity.as_str(), c.open, c.accepted, c.new))
            .collect();
        assert_eq!(
            got,
            vec![
                ("exe-unowned", "high", 0, 1, 0),
                ("pkg-modified", "high", 2, 0, 1),
                ("pkg-modified", "medium", 1, 0, 0),
            ]
        );
        let json = serde_json::to_string(&rep).unwrap();
        assert!(!json.contains("/usr/bin") && !json.contains("secret"), "{json}");
    }
}
