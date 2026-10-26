//! `minsec-id`: scanner and CLI in one binary.

mod cli;
mod daemon;

use clap::Parser;
use cli::{Cli, Cmd};
use minsec_id_core::config::{self, Config};
use minsec_id_core::events::{now, EventLog};
use minsec_id_core::scan::{self, Mode};
use minsec_id_core::state::{OpenFinding, State};
use minsec_id_core::{check, control, inspect, monitor, sink, Host, Severity};
use std::time::Duration;

/// `scan` exit status when unaccepted findings are open, so the scanner can
/// double as a monitoring plugin. (minsec uses only 0 and 1.)
const EXIT_FINDINGS: i32 = 2;

fn main() {
    let cli = Cli::parse();
    // The daemon reports what it attached and when it reloads; a scan only warns.
    init_logging(if matches!(cli.cmd, Cmd::Daemon) { "info" } else { "warn" });
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("minsec-id: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let host = Host::with_root(&cli.root);
    match cli.cmd {
        Cmd::Scan {
            full,
            quick: _,
            checks,
            quiet,
        } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            // Only a scan of the live host reports to the live journal.
            let journal = (cli.root == std::path::Path::new("/")).then(|| sink::JOURNAL_SOCKET.into());
            let opts = scan::Options {
                mode: if full { Mode::Full } else { Mode::Quick },
                only: checks,
                host,
                journal_socket: journal,
            };
            let report = scan::run(&cfg, &opts)?;
            if cli.json {
                println!("{}", serde_json::to_string(&report)?);
            } else if !quiet {
                print_report(&report);
            }
            Ok(if !report.findings.is_empty() {
                EXIT_FINDINGS
            } else if !report.ok {
                1
            } else {
                0
            })
        }
        Cmd::Status => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let state = State::load(&cfg.state_file())?;
            let daemon = daemon_status(&cfg);
            if cli.json {
                let open: Vec<&OpenFinding> = state.unaccepted().collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": scan::SCHEMA_VERSION,
                        "version": env!("CARGO_PKG_VERSION"),
                        "last_scan": state.last_scan,
                        "open": open.len(),
                        "by_severity": by_severity(open.iter().copied()),
                        "accepted": state.open.len() - open.len(),
                        "daemon": match &daemon {
                            Ok(s) => serde_json::to_value(s)?,
                            Err(e) => serde_json::json!({ "running": false, "error": e }),
                        },
                    })
                );
                return Ok(0);
            }
            let open: Vec<&OpenFinding> = state.unaccepted().collect();
            let last = match &state.last_scan {
                Some(s) => format!(
                    "last scan {} {} ago ({}ms, {} checks{})",
                    s.mode,
                    ago(s.ts),
                    s.duration_ms,
                    s.checks.len(),
                    if s.errors.is_empty() {
                        String::new()
                    } else {
                        format!(", {} failed", s.errors.len())
                    }
                ),
                None => "never scanned".into(),
            };
            let sev: Vec<String> = by_severity(open.iter().copied())
                .iter()
                .rev()
                .map(|(s, n)| format!("{n} {s}"))
                .collect();
            println!(
                "minsec-id {} · {last} · {} open{} · {} accepted",
                env!("CARGO_PKG_VERSION"),
                open.len(),
                if sev.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", sev.join(", "))
                },
                state.open.len() - open.len()
            );
            if let Some(s) = &state.last_scan {
                for (id, e) in &s.errors {
                    println!("  {id}: {e}");
                }
            }
            match daemon {
                Ok(d) => {
                    let found: u64 = d.stats.findings.values().sum();
                    let events: u64 = d.stats.events.values().sum();
                    let attached = d.probes.iter().filter(|p| p.attached).count();
                    println!(
                        "daemon: up {} · {attached}/{} probes · {events} events · {found} findings · {} lost · {} KiB",
                        minsec_id_core::duration::format(Duration::from_secs(d.uptime)),
                        d.probes.len(),
                        d.dropped,
                        d.rss_kb
                    );
                    for p in d.probes.iter().filter(|p| !p.attached) {
                        println!("  probe {} not attached: {}", p.probe, p.error.as_deref().unwrap_or(""));
                    }
                }
                Err(e) => println!("daemon: {e}"),
            }
            Ok(0)
        }
        Cmd::Findings { all, severity } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let state = State::load(&cfg.state_file())?;
            let min: Severity = severity
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(anyhow::Error::msg)?
                .unwrap_or(Severity::Info);
            let mut list: Vec<&OpenFinding> = state
                .open
                .values()
                .filter(|o| (all || o.accepted.is_none()) && o.finding.severity >= min)
                .collect();
            list.sort_by(|a, b| {
                b.finding
                    .severity
                    .cmp(&a.finding.severity)
                    .then_with(|| a.finding.key().cmp(&b.finding.key()))
            });
            if cli.json {
                println!("{}", serde_json::to_string(&list)?);
                return Ok(0);
            }
            for o in list {
                let f = &o.finding;
                println!(
                    "{} {:<8} {:<32} {}{}",
                    f.fingerprint,
                    f.severity,
                    f.key(),
                    f.message,
                    o.accepted
                        .as_ref()
                        .map(|k| format!("  (accepted: {k})"))
                        .unwrap_or_default()
                );
            }
            Ok(0)
        }
        Cmd::Show { finding } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let state = State::load(&cfg.state_file())?;
            let o = lookup(&state, &finding)?;
            if cli.json {
                println!("{}", serde_json::to_string(o)?);
                return Ok(0);
            }
            let f = &o.finding;
            println!("{}  [{}] {}", f.key(), f.severity, f.message);
            println!("fingerprint {}", f.fingerprint);
            println!(
                "first seen {} ago · last seen {} ago",
                ago(o.first_seen),
                ago(o.last_seen)
            );
            if let Some(k) = &o.accepted {
                println!("accepted by {k}");
            }
            if !f.detail.is_null() {
                println!("{}", serde_json::to_string_pretty(&f.detail)?);
            }
            Ok(0)
        }
        Cmd::Accept { finding, reason } => {
            let key = if finding.contains(':') {
                finding
            } else {
                let cfg = Config::load_dir(&cli.config_dir)?;
                let state = State::load(&cfg.state_file())?;
                lookup(&state, &finding)?.finding.key()
            };
            let (id, subject) = key.split_once(':').expect("key has a colon");
            if check::producer(id).is_none() && monitor::rule_for(id).is_none() {
                anyhow::bail!("unknown finding id `{id}` (see `minsec-id checks`)");
            }
            if subject.is_empty() {
                anyhow::bail!("empty subject in `{key}` (use `{id}:*` to accept the whole check)");
            }
            let path = config::edit_dropin(&cli.config_dir, config::ACCEPT_FILE, |t| {
                let mut rule = toml::Table::new();
                if let Some(r) = reason {
                    rule.insert("reason".into(), toml::Value::String(r));
                }
                config::subtable(t, "accept")?.insert(key.clone(), toml::Value::Table(rule));
                Ok(())
            })?;
            finish(
                cli.json,
                &format!("accepted {key} ({}); applies from the next scan", path.display()),
            )
        }
        Cmd::Unaccept { key } => {
            let mut found = false;
            let path = config::edit_dropin(&cli.config_dir, config::ACCEPT_FILE, |t| {
                found = config::subtable(t, "accept")?.remove(&key).is_some();
                Ok(())
            })?;
            if !found {
                anyhow::bail!("no accept rule `{key}` in {}", path.display());
            }
            finish(
                cli.json,
                &format!("removed {key} ({}); applies from the next scan", path.display()),
            )
        }
        Cmd::Verify { target } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let ctx = check::Ctx::new(&host, &cfg, now());
            let r = check::verify(&ctx, &target)?;
            let code = if r.findings.is_empty() { 0 } else { EXIT_FINDINGS };
            if cli.json {
                println!("{}", serde_json::to_string(&r)?);
                return Ok(code);
            }
            for f in &r.findings {
                println!("{:<8} {:<20} {}", f.severity, f.check, f.message);
            }
            println!(
                "{}: {} file(s) of {} checked, {} hashed, {}",
                r.target,
                r.files,
                r.packages.join(", "),
                r.hashed,
                if r.findings.is_empty() {
                    "intact".to_string()
                } else {
                    format!("{} difference(s)", r.findings.len())
                }
            );
            Ok(code)
        }
        Cmd::Baseline { reset, checks } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            for id in &checks {
                if check::get(id).is_none() {
                    anyhow::bail!("unknown check `{id}` (see `minsec-id checks`)");
                }
            }
            if reset {
                let _lock = minsec_id_core::state::Lock::acquire(&cfg.paths.state_dir)?;
                let mut state = State::load(&cfg.state_file())?;
                let before = state.anchors.len();
                state.anchors.retain(|id, _| !checks.is_empty() && !checks.contains(id));
                state.save(&cfg.state_file())?;
                return finish(
                    cli.json,
                    &format!(
                        "reset {} baseline(s); the next scan records the current state (run `minsec-id scan --full` now)",
                        before - state.anchors.len()
                    ),
                );
            }
            let state = State::load(&cfg.state_file())?;
            let shown: Vec<(&String, usize)> = state
                .anchors
                .iter()
                .filter(|(id, m)| !m.is_empty() && (checks.is_empty() || checks.contains(id)))
                .map(|(id, m)| (id, m.len()))
                .collect();
            if cli.json {
                let v: std::collections::BTreeMap<&String, &std::collections::BTreeMap<String, String>> = state
                    .anchors
                    .iter()
                    .filter(|(id, _)| checks.is_empty() || checks.contains(id))
                    .collect();
                println!("{}", serde_json::to_string(&v)?);
                return Ok(0);
            }
            if shown.is_empty() {
                println!("no baselines recorded yet (they are recorded by the first scan)");
            }
            for (id, n) in shown {
                println!("{id:<20} {n} recorded item(s)");
            }
            Ok(0)
        }
        Cmd::Checks => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let list = inspect::checks(&cfg, &host);
            if cli.json {
                println!("{}", serde_json::to_string(&list)?);
                return Ok(0);
            }
            for c in list {
                println!(
                    "{} {:<20} {:<5} {}{}",
                    if c.enabled { "*" } else { " " },
                    c.id,
                    match c.cost {
                        check::Cost::Quick => "quick",
                        check::Cost::Full => "full",
                        check::Cost::Daemon => "daemon",
                    },
                    c.description,
                    c.unavailable
                        .map(|w| format!("  (unavailable: {w})"))
                        .unwrap_or_default()
                );
            }
            Ok(0)
        }
        Cmd::Enable { check } => set_enabled(&cli.config_dir, cli.json, &check, true),
        Cmd::Disable { check } => set_enabled(&cli.config_dir, cli.json, &check, false),
        Cmd::Inspect => match inspect::inspect(&cli.config_dir, &host, env!("CARGO_PKG_VERSION")) {
            Ok(i) => {
                if cli.json {
                    println!("{}", serde_json::to_string(&i)?);
                } else {
                    print_inspection(&i);
                }
                Ok(0)
            }
            Err(error) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": inspect::SCHEMA_VERSION,
                            "ok": false,
                            "error": format!("{error:#}"),
                        })
                    );
                }
                Err(error)
            }
        },
        Cmd::Check => {
            let result = Config::load_dir(&cli.config_dir);
            if cli.json {
                println!(
                    "{}",
                    match &result {
                        Ok(_) => serde_json::json!({"schema_version": inspect::SCHEMA_VERSION, "ok": true}),
                        Err(e) => serde_json::json!({
                            "schema_version": inspect::SCHEMA_VERSION,
                            "ok": false,
                            "error": format!("{e:#}"),
                        }),
                    }
                );
            }
            let cfg = result?;
            if !cli.json {
                let enabled = check::all()
                    .iter()
                    .filter(|c| cfg.check_enabled(c.id(), c.default_enabled()))
                    .count();
                println!(
                    "ok: {enabled} of {} checks enabled, {} accept rules",
                    check::all().len(),
                    cfg.accept.len()
                );
            }
            Ok(0)
        }
        Cmd::Daemon => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            daemon::run(cfg)?;
            Ok(0)
        }
        Cmd::Events { last } => {
            let cfg = Config::load_dir(&cli.config_dir)?;
            let all = EventLog::read_all(&cfg.events_file());
            for ev in all.iter().rev().take(last).rev() {
                println!("{}", serde_json::to_string(ev)?);
            }
            Ok(0)
        }
    }
}

/// Find an open finding by fingerprint or `check:subject`.
fn lookup<'a>(state: &'a State, s: &str) -> anyhow::Result<&'a OpenFinding> {
    state
        .open
        .get(s)
        .or_else(|| state.open.values().find(|o| o.finding.key() == s))
        .ok_or_else(|| anyhow::anyhow!("no open finding `{s}` (see `minsec-id findings --all`)"))
}

fn by_severity<'a>(it: impl Iterator<Item = &'a OpenFinding>) -> std::collections::BTreeMap<Severity, usize> {
    let mut m = std::collections::BTreeMap::new();
    for o in it {
        *m.entry(o.finding.severity).or_default() += 1;
    }
    m
}

fn ago(ts: u64) -> String {
    minsec_id_core::duration::format(Duration::from_secs(now().saturating_sub(ts)))
}

fn finish(json: bool, msg: &str) -> anyhow::Result<i32> {
    if json {
        println!("{}", serde_json::json!({"ok": true, "message": msg}));
    } else {
        println!("{msg}");
    }
    Ok(0)
}

/// The running daemon's status, or why there is none.
fn daemon_status(cfg: &Config) -> Result<control::Status, String> {
    let sock = &cfg.paths.socket;
    match control::call_with_timeout(sock, &control::Request::Status, Duration::from_secs(2)) {
        Ok(r) => r.status.ok_or_else(|| r.error.unwrap_or_else(|| "no status".into())),
        Err(e) => Err(match e.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
            Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => "not running".into(),
            Some(std::io::ErrorKind::PermissionDenied) => format!("{} is root's (run as root)", sock.display()),
            _ => format!("{e:#}"),
        }),
    }
}

fn set_enabled(config_dir: &std::path::Path, json: bool, id: &str, enabled: bool) -> anyhow::Result<i32> {
    if check::get(id).is_none() && monitor::rule(id).is_none() {
        anyhow::bail!("unknown check `{id}` (see `minsec-id checks`)");
    }
    let path = config::edit_dropin(config_dir, &format!("{id}.toml"), |t| {
        config::subtable(config::subtable(t, "checks")?, id)?.insert("enabled".into(), toml::Value::Boolean(enabled));
        Ok(())
    })?;
    finish(
        json,
        &format!(
            "{} {id} ({}); applies from the next {}",
            if enabled { "enabled" } else { "disabled" },
            path.display(),
            if monitor::rule(id).is_some() {
                "daemon restart"
            } else {
                "scan"
            }
        ),
    )
}

fn print_report(r: &scan::Report) {
    println!(
        "{} scan · {} checks · {} open ({} new) · {} resolved · {} accepted · {}ms",
        r.mode.as_str(),
        r.checks.len(),
        r.findings.len(),
        r.new,
        r.resolved,
        r.accepted,
        r.duration_ms
    );
    for c in r.checks.iter().filter(|c| c.status == "error") {
        println!("  {} failed: {}", c.id, c.error.as_deref().unwrap_or(""));
    }
    let unavailable = r.checks.iter().filter(|c| c.status == "unavailable").count();
    if unavailable > 0 {
        println!("  {unavailable} check(s) unavailable on this host (see `minsec-id checks`)");
    }
    for f in &r.findings {
        println!(
            "  {:<8} {:<32} {}{}",
            f.finding.severity,
            f.finding.key(),
            f.finding.message,
            if f.new { "  [new]" } else { "" }
        );
    }
}

/// One-screen summary of an inspection; `--json` has everything.
fn print_inspection(i: &inspect::Inspection) {
    let yn = |b: bool| if b { "yes" } else { "no" };
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
    println!(
        "minsec-id {} on {}",
        i.version,
        i.os.pretty_name.clone().unwrap_or_else(|| "unknown OS".into())
    );
    let k = &i.kernel;
    println!(
        "kernel {}{} · btf {} · bpf-lsm {} · ima {} · lockdown {} · secure boot {}",
        opt(&k.release),
        if k.supported {
            ""
        } else {
            " (unsupported: minsec-id needs 5.14 or newer)"
        },
        yn(k.btf),
        yn(k.bpf_lsm),
        yn(k.ima),
        opt(&k.lockdown),
        k.secure_boot.map(yn).unwrap_or("- (not UEFI)")
    );
    println!(
        "lsm {} · selinux {} · apparmor {}",
        if k.lsm.is_empty() { "-".into() } else { k.lsm.join(",") },
        opt(&k.selinux),
        yn(k.apparmor)
    );
    let p = &i.packages;
    let pms: Vec<&str> = [
        ("rpm", p.rpm),
        ("dpkg", p.dpkg),
        ("flatpak", p.flatpak),
        ("snap", p.snap),
    ]
    .iter()
    .filter(|(_, b)| *b)
    .map(|(n, _)| *n)
    .collect();
    println!(
        "packages {} · ostree {} · root fs {}",
        if pms.is_empty() { "none".into() } else { pms.join(",") },
        yn(i.image.ostree),
        opt(&i.image.root_fstype)
    );
    println!(
        "config {} (+{} drop-ins) · state {}",
        i.files
            .main
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| format!("{} (absent, defaults)", i.paths.main_config.display())),
        i.files.dropins.len(),
        i.paths.state_dir.display()
    );
    for c in &i.checks {
        println!(
            "  {} {:<20} {}",
            if c.enabled { "*" } else { " " },
            c.id,
            c.unavailable
                .as_deref()
                .map(|w| format!("unavailable: {w}"))
                .unwrap_or_else(|| "available".into())
        );
    }
}

fn init_logging(default: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MINSEC_ID_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time() // journald stamps for us
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
}
