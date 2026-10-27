//! `minsec-id-sync`: minsec-id's crowd client. Short-lived and
//! timer-driven; the scanner and the daemon have no network stack. It reads
//! the scanner's state.json and writes only its own `sync` directory.

mod cli;
mod client;
mod config;
mod findings;
mod hashcheck;
mod os;
mod store;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::Parser;
use cli::{Cli, Cmd};
use client::{Api, AGENT_VERSION};
use config::Config;
use minsec_proto::types::{EnrollRequest, POW_ALGO, PRODUCT_MINSEC_ID};
use store::Store;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("minsec-id-sync: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let cfg = match Config::load(&cli.config)? {
        Some(cfg) => cfg,
        None => {
            if matches!(cli.cmd, Cmd::Run) {
                // The opt-in switch is the config file; timers on
                // unconfigured systems stay silent.
                return Ok(());
            }
            anyhow::bail!(
                "the crowd is not configured: create {} (see sync.toml.example)",
                cli.config.display()
            );
        }
    };
    let store = Store::open(&cfg.state_dir)?;
    let mut state = store.load_state()?;
    let api = Api::new(&cfg.server);

    match cli.cmd {
        Cmd::Enroll => enroll(&cfg, &api, &store, &mut state, true)?,
        Cmd::Report => {
            let key = store.load_or_create_key()?;
            let out = findings::run(&cfg, &api, &store, &mut state, &key)?;
            println!("reported {} finding counts ({} accepted)", out.counts, out.accepted);
        }
        Cmd::Check => {
            let key = store.load_or_create_key()?;
            print_check(&hashcheck::run(&cfg, &api, &state, &key)?, true);
        }
        Cmd::Run => {
            enroll(&cfg, &api, &store, &mut state, false)?;
            let key = store.load_or_create_key()?;
            let mut failed = None;
            if cfg.findings {
                if let Err(e) = findings::run(&cfg, &api, &store, &mut state, &key) {
                    eprintln!("minsec-id-sync: report: {e:#}");
                    failed = Some(e);
                }
            }
            if cfg.hashcheck {
                match hashcheck::run(&cfg, &api, &state, &key) {
                    Ok(out) => print_check(&out, false),
                    Err(e) => {
                        eprintln!("minsec-id-sync: check: {e:#}");
                        failed = Some(e);
                    }
                }
            }
            if let Some(e) = failed {
                return Err(e);
            }
        }
        Cmd::Status => {
            let key = store.load_or_create_key()?;
            println!("server:   {}", cfg.server);
            println!("pubkey:   {}", B64.encode(key.verifying_key().to_bytes()));
            match &state.host_id {
                Some(id) => println!("host_id:  {id}"),
                None => println!("host_id:  (not enrolled)"),
            }
            if let Some(org) = &state.org {
                println!("org:      {org}");
                if let Some(label) = cfg.label() {
                    println!("label:    {label}");
                }
            }
            println!("seq:      {}", state.next_seq);
            let crowd = minsec_id_core::crowd::Crowd::load(&cfg.state_dir);
            let shared = crowd.answers.values().filter(|a| a.verdict == "shared").count();
            println!(
                "crowd:    {} answers ({shared} shared, {} rare or rejected)",
                crowd.answers.len(),
                crowd.answers.len() - shared
            );
            println!("findings: {}", if cfg.findings { "reported" } else { "not reported" });
            println!("checks:   {}", if cfg.hashcheck { "asked" } else { "not asked" });
        }
    }
    Ok(())
}

fn print_check(o: &hashcheck::Outcome, always: bool) {
    if o.sent == 0 && !always {
        return;
    }
    println!(
        "asked the crowd about {} modified files ({} shared, {} rare, {} rejected; {} answered earlier)",
        o.sent, o.shared, o.rare, o.rejected, o.cached
    );
}

/// Enroll as minsec-id, solving the proof-of-work challenge, unless
/// already enrolled. With `verbose` (interactive use) progress goes to
/// stdout. If the server knows the key but this host lost its host_id, the
/// key is rotated and enrollment retried once.
///
/// An install token added to a host enrolled anonymously joins it to the
/// organization: the host enrolls again with a new key, and the anonymous
/// enrollment is left to go quiet.
fn enroll(cfg: &Config, api: &Api, store: &Store, state: &mut store::State, verbose: bool) -> anyhow::Result<()> {
    let token = cfg.token();
    let joining = match (&state.host_id, &state.org, token) {
        (Some(id), None, Some(_)) if !state.token_enrolled => Some(id.clone()),
        (Some(id), _, _) => {
            if verbose {
                println!("already enrolled as {id}");
            }
            return Ok(());
        }
        _ => None,
    };
    let mut key = store.load_or_create_key()?;
    for attempt in 0..2 {
        // A bad token is refused here, before the anonymous identity is
        // given up.
        let ch = api.challenge(token)?;
        if let (Some(id), 0) = (&joining, attempt) {
            eprintln!("minsec-id-sync: install_token set; re-enrolling {id} into the organization with a new key");
            state.host_id = None;
            key = store.rotate_key()?;
        }
        if verbose {
            println!("solving {POW_ALGO} challenge (difficulty {})...", ch.difficulty);
        }
        let nonce = minsec_proto::pow::solve(&ch.challenge, ch.difficulty);
        let req = EnrollRequest {
            challenge: ch.challenge,
            pow_nonce: nonce,
            pubkey: B64.encode(key.verifying_key().to_bytes()),
            agent_version: AGENT_VERSION.to_string(),
            install_token: token.map(str::to_string),
            label: token.and_then(|_| cfg.label()),
            product: Some(PRODUCT_MINSEC_ID.into()),
        };
        match api.enroll(&req) {
            Ok(resp) => {
                state.host_id = Some(resp.host_id.clone());
                state.org = resp.org.clone();
                state.token_enrolled = token.is_some();
                state.min_report_interval = resp.min_report_interval;
                store.save_state(state)?;
                if token.is_some() && resp.org.is_none() {
                    eprintln!("minsec-id-sync: the server did not bind this host to an organization");
                }
                if verbose {
                    match &resp.org {
                        Some(org) => println!("enrolled as {} in {org}", resp.host_id),
                        None => println!("enrolled as {}", resp.host_id),
                    }
                }
                return Ok(());
            }
            Err(e) if e.code == "already_enrolled" && attempt == 0 => {
                eprintln!("minsec-id-sync: key already enrolled but host_id lost; generating a new key");
                key = store.rotate_key()?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("enrollment failed after key rotation")
}
