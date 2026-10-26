//! `minsec-id-sync check`: ask the crowd about package files whose content
//! changed. For each open `pkg-modified` finding the request names the
//! package, the path, and the two digests (what the package database
//! records, what is on disk); never the content. Answers are written to
//! crowd.json for the scanner, and re-asked daily while a finding stays
//! open, which also keeps this host's vote from aging out on the server.

use crate::client::{now_unix, Api, ApiError, AGENT_VERSION};
use crate::config::Config;
use crate::store::State;
use ed25519_dalek::SigningKey;
use minsec_id_core::crowd::{self, Answer, Crowd};
use minsec_id_core::state::State as ScanState;
use minsec_proto::types::{HashCheckItem, HashCheckRequest, HashCheckResponse};

/// How old an answer may get before it is asked again.
const RECHECK: u64 = 20 * 3600;

/// The open findings that may be sent, with their fingerprints.
pub fn items(scan: &ScanState, cfg: &Config) -> Vec<(String, HashCheckItem)> {
    let mut out = Vec::new();
    for o in scan.open.values() {
        let f = &o.finding;
        if !crowd::CHECKS.contains(&f.check.as_str()) {
            continue;
        }
        let d = &f.detail;
        let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if s("kind") != "content" {
            continue;
        }
        let manager = s("manager");
        let package = s("package");
        if !matches!(manager.as_str(), "rpm" | "dpkg") || package.is_empty() || cfg.excluded(&package) {
            continue;
        }
        // An rpm no key signed is often a local build, its name local too.
        if manager == "rpm" && d.get("signed").and_then(|v| v.as_bool()) != Some(true) && !cfg.unsigned {
            continue;
        }
        out.push((
            f.fingerprint.clone(),
            HashCheckItem {
                manager,
                package,
                path: f.subject.clone(),
                algo: s("algo"),
                expected: s("expected"),
                actual: s("actual"),
            },
        ));
    }
    out
}

#[derive(Default)]
pub struct Outcome {
    pub sent: usize,
    pub shared: usize,
    pub rare: usize,
    pub rejected: usize,
    pub cached: usize,
}

pub fn run(cfg: &Config, api: &Api, st: &State, key: &SigningKey) -> anyhow::Result<Outcome> {
    let host_id = st.host_id.clone().ok_or_else(|| anyhow::anyhow!("not enrolled"))?;
    let scan = ScanState::load(&cfg.state_dir.join("state.json"))?;
    let old = Crowd::load(&cfg.state_dir);
    let now = now_unix();
    let all = items(&scan, cfg);

    // Answers for findings no longer open are dropped.
    let mut next = Crowd {
        version: crowd::VERSION,
        ..Default::default()
    };
    let mut due = Vec::new();
    let mut out = Outcome::default();
    for (fp, it) in all {
        match old.answers.get(&fp) {
            Some(a) if a.checked + RECHECK > now => {
                next.answers.insert(fp, a.clone());
                out.cached += 1;
            }
            _ => due.push((fp, it)),
        }
    }

    let mut result = Ok(());
    for chunk in due.chunks(minsec_proto::MAX_BATCH_ITEMS) {
        let req = HashCheckRequest {
            agent_version: AGENT_VERSION.into(),
            items: chunk.iter().map(|(_, it)| it.clone()).collect(),
        };
        let resp: Result<HashCheckResponse, ApiError> = api.post_signed(
            "/v1/hashcheck",
            minsec_proto::sign::PURPOSE_HASHCHECK,
            key,
            &host_id,
            &req,
        );
        let resp = match resp {
            Ok(r) if r.results.len() == chunk.len() => r,
            Ok(r) => {
                result = Err(anyhow::anyhow!("{} answers for {} items", r.results.len(), chunk.len()));
                break;
            }
            Err(e) => {
                result = Err(e.into());
                break;
            }
        };
        out.sent += chunk.len();
        for ((fp, _), r) in chunk.iter().zip(resp.results) {
            match r.verdict.as_str() {
                minsec_proto::types::VERDICT_SHARED => out.shared += 1,
                minsec_proto::types::VERDICT_RARE => out.rare += 1,
                _ => out.rejected += 1,
            }
            next.answers.insert(
                fp.clone(),
                Answer {
                    verdict: r.verdict,
                    same: r.same,
                    different: r.different,
                    expected_disputed: r.expected_disputed,
                    checked: now,
                },
            );
        }
    }
    // Keep what was answered even when a later batch failed; an answer not
    // yet replaced stays until it is.
    for (fp, _) in &due {
        if let (false, Some(a)) = (next.answers.contains_key(fp), old.answers.get(fp)) {
            next.answers.insert(fp.clone(), a.clone());
        }
    }
    next.save(&cfg.state_dir)?;
    result.map(|_| out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minsec_id_core::state::OpenFinding;
    use minsec_id_core::{Finding, Severity};

    fn modified(path: &str, detail: serde_json::Value) -> OpenFinding {
        OpenFinding {
            finding: Finding::new("pkg-modified", Severity::High, path, "x").detail(detail),
            first_seen: 1,
            last_seen: 1,
            accepted: None,
        }
    }

    #[test]
    fn selects_what_may_be_sent() {
        let content = |pkg: &str, manager: &str, signed: Option<bool>| {
            let mut d = serde_json::json!({
                "kind": "content", "package": pkg, "manager": manager,
                "algo": "sha256", "expected": "aa", "actual": "bb",
            });
            if let Some(s) = signed {
                d["signed"] = s.into();
            }
            d
        };
        let mut scan = ScanState::default();
        for o in [
            modified("/usr/bin/a", content("coreutils-9.5-1.fc44.x86_64", "rpm", Some(true))),
            modified("/usr/bin/b", content("inhouse-1-1.x86_64", "rpm", Some(false))),
            modified("/usr/bin/c", content("acme-agent-2-1.x86_64", "rpm", Some(true))),
            modified("/usr/bin/d", content("bash:amd64=5.2-1", "dpkg", None)),
            modified("/usr/bin/e", serde_json::json!({ "kind": "symlink", "package": "x" })),
        ] {
            scan.open.insert(o.finding.fingerprint.clone(), o);
        }
        let mut cfg = Config {
            exclude: vec!["acme-*".into()],
            ..Default::default()
        };
        let mut paths: Vec<String> = items(&scan, &cfg).into_iter().map(|(_, i)| i.path).collect();
        paths.sort();
        assert_eq!(paths, vec!["/usr/bin/a", "/usr/bin/d"]);

        cfg.unsigned = true;
        assert_eq!(items(&scan, &cfg).len(), 3);
    }
}
