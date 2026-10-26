//! One scan: run the selected checks, apply accept rules, compare with the
//! open findings in `state.json`, and send only what is new or resolved to the
//! sinks.

use crate::check::{self, Anchors, Check, Cost, Ctx};
use crate::config::Config;
use crate::events::{now, Event, EventLog};
use crate::finding::Finding;
use crate::host::Host;
use crate::sink;
use crate::state::{LastScan, Lock, OpenFinding, State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Quick,
    Full,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Quick => "quick",
            Mode::Full => "full",
        }
    }

    fn includes(&self, cost: Cost) -> bool {
        *self == Mode::Full || cost == Cost::Quick
    }
}

pub struct Options {
    pub mode: Mode,
    /// Run exactly these checks (enabled or not); empty means every enabled
    /// check the mode includes.
    pub only: Vec<String>,
    pub host: Host,
    /// Where journald listens; `None` disables the journal sink.
    pub journal_socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub ok: bool,
    pub mode: Mode,
    pub ts: u64,
    pub duration_ms: u64,
    pub checks: Vec<CheckRun>,
    /// Every open, unaccepted finding after this scan, most severe first.
    pub findings: Vec<ReportFinding>,
    pub new: usize,
    pub resolved: usize,
    pub accepted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRun {
    pub id: String,
    /// `ok`, `error`, or `unavailable`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    #[serde(flatten)]
    pub finding: Finding,
    pub new: bool,
    pub first_seen: u64,
}

/// The checks a scan would run, in registry order.
pub fn select(cfg: &Config, mode: Mode, only: &[String]) -> anyhow::Result<Vec<&'static dyn Check>> {
    if !only.is_empty() {
        return only
            .iter()
            .map(|id| check::get(id).ok_or_else(|| anyhow::anyhow!("unknown check `{id}` (see `minsec-id checks`)")))
            .collect();
    }
    Ok(check::all()
        .iter()
        .copied()
        .filter(|c| mode.includes(c.cost()) && cfg.check_enabled(c.id(), c.default_enabled()))
        .collect())
}

pub fn run(cfg: &Config, opts: &Options) -> anyhow::Result<Report> {
    let started = Instant::now();
    let ts = now();
    let checks = select(cfg, opts.mode, &opts.only)?;
    let _lock = Lock::acquire(&cfg.paths.state_dir)?;
    let state_path = cfg.state_file();
    let mut state = State::load(&state_path)?;
    // Findings of checks disabled since they were reported are dropped, not
    // resolved: nothing re-examined them.
    state.open.retain(|_, o| {
        check::producer(&o.finding.check)
            .is_some_and(|c| opts.only.iter().any(|id| id == c.id()) || cfg.check_enabled(c.id(), c.default_enabled()))
    });
    let mut log = EventLog::open(&cfg.events_file())?;
    let ctx = Ctx::new(&opts.host, cfg, ts);
    let crowd = crate::crowd::Crowd::load(&cfg.paths.state_dir);

    let mut runs = Vec::new();
    let mut errors = BTreeMap::new();
    let mut fresh: Vec<Finding> = Vec::new();
    let mut resolved: Vec<Finding> = Vec::new();
    let mut new_fps = std::collections::BTreeSet::new();

    for c in &checks {
        let id = c.id();
        if let Some(why) = c.unavailable(&opts.host) {
            runs.push(CheckRun {
                id: id.into(),
                status: "unavailable".into(),
                error: Some(why),
                findings: 0,
            });
            continue;
        }
        let mut anchors = Anchors {
            fresh: !state.anchors.contains_key(id),
            map: state.anchors.get(id).cloned().unwrap_or_default(),
        };
        let found = match c.run(&ctx, &mut anchors) {
            Ok(f) => {
                state.anchors.insert(id.to_string(), anchors.map);
                f
            }
            Err(e) if e.downcast_ref::<check::Unavailable>().is_some() => {
                runs.push(CheckRun {
                    id: id.into(),
                    status: "unavailable".into(),
                    error: Some(format!("{e}")),
                    findings: 0,
                });
                continue;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!("check {id}: {msg}");
                errors.insert(id.to_string(), msg.clone());
                runs.push(CheckRun {
                    id: id.into(),
                    status: "error".into(),
                    error: Some(msg),
                    findings: 0,
                });
                // Keep its previous findings open: a failed check proves nothing.
                continue;
            }
        };
        runs.push(CheckRun {
            id: id.into(),
            status: "ok".into(),
            error: None,
            findings: found.len(),
        });

        let mut seen = std::collections::BTreeSet::new();
        for mut f in found {
            if let Some(s) = cfg.severity_override(id) {
                f.severity = s;
            }
            crowd.annotate(&mut f);
            let accepted = cfg.accepted(&f).map(|(k, _)| k.to_string());
            seen.insert(f.fingerprint.clone());
            match state.open.get_mut(&f.fingerprint) {
                Some(o) => {
                    // Notify when an accept rule is removed, not when added.
                    let unaccepted_now = o.accepted.is_some() && accepted.is_none();
                    o.last_seen = ts;
                    o.accepted = accepted;
                    o.finding = f.clone();
                    if unaccepted_now {
                        new_fps.insert(f.fingerprint.clone());
                        fresh.push(f);
                    }
                }
                None => {
                    if accepted.is_none() {
                        new_fps.insert(f.fingerprint.clone());
                        fresh.push(f.clone());
                    }
                    state.open.insert(
                        f.fingerprint.clone(),
                        OpenFinding {
                            finding: f,
                            first_seen: ts,
                            last_seen: ts,
                            accepted,
                        },
                    );
                }
            }
        }
        let gone: Vec<String> = state
            .open
            .iter()
            .filter(|(fp, o)| check::producer(&o.finding.check).is_some_and(|p| p.id() == id) && !seen.contains(*fp))
            .map(|(fp, _)| fp.clone())
            .collect();
        for fp in gone {
            if let Some(o) = state.open.remove(&fp) {
                if o.accepted.is_none() {
                    resolved.push(o.finding);
                }
            }
        }
    }

    for f in &fresh {
        log.append(&Event::Finding { ts, finding: f.clone() });
        if f.severity < cfg.output.min_severity {
            continue;
        }
        if let (true, Some(sock)) = (cfg.output.journal, &opts.journal_socket) {
            sink::journal_finding(sock, f);
        }
        if let Some(cmd) = &cfg.output.exec {
            if let Err(e) = sink::exec_hook(cmd, f) {
                tracing::warn!("{}: {e:#}", f.fingerprint);
            }
        }
    }
    for f in &resolved {
        log.append(&Event::Resolved {
            ts,
            check: f.check.clone(),
            subject: f.subject.clone(),
            fingerprint: f.fingerprint.clone(),
        });
        if let (true, Some(sock)) = (cfg.output.journal, &opts.journal_socket) {
            if f.severity >= cfg.output.min_severity {
                sink::journal_resolved(sock, f);
            }
        }
    }

    let duration_ms = started.elapsed().as_millis() as u64;
    let mut findings: Vec<ReportFinding> = state
        .unaccepted()
        .map(|o| ReportFinding {
            finding: o.finding.clone(),
            new: new_fps.contains(&o.finding.fingerprint),
            first_seen: o.first_seen,
        })
        .collect();
    findings.sort_by(|a, b| {
        b.finding
            .severity
            .cmp(&a.finding.severity)
            .then_with(|| a.finding.key().cmp(&b.finding.key()))
    });
    let accepted = state.open.values().filter(|o| o.accepted.is_some()).count();
    log.append(&Event::Scan {
        ts,
        mode: opts.mode.as_str().into(),
        checks: runs.len(),
        open: findings.len(),
        new: fresh.len(),
        resolved: resolved.len(),
        errors: errors.len(),
        duration_ms,
    });
    state.last_scan = Some(LastScan {
        ts,
        mode: opts.mode.as_str().into(),
        duration_ms,
        checks: runs.iter().map(|r| r.id.clone()).collect(),
        errors: errors.clone(),
    });
    state.save(&state_path)?;

    Ok(Report {
        schema_version: SCHEMA_VERSION,
        ok: errors.is_empty(),
        mode: opts.mode,
        ts,
        duration_ms,
        checks: runs,
        findings,
        new: fresh.len(),
        resolved: resolved.len(),
        accepted,
    })
}
