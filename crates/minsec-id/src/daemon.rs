//! `minsec-id daemon`: the eBPF monitor. One thread: the ring buffer, the
//! control socket, signals, and a housekeeping tick in one select loop, as
//! in minsec's daemon (crates/minsec/src/daemon.rs). Notify hooks run on
//! their own threads so a slow hook never stalls the ring buffer.

use minsec_id_bpf::{Event, Monitor};
use minsec_id_core::config::Config;
use minsec_id_core::control::{self, ProbeStatus, Request, Response, Status};
use minsec_id_core::events::{now, Event as LogEvent, EventLog};
use minsec_id_core::monitor::Engine;
use minsec_id_core::{dirty, sink, Finding, Host};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};

/// Notify hooks running at once; beyond this a finding's hook is skipped
/// (the finding is still logged and journaled).
const MAX_HOOKS: usize = 4;

pub fn run(cfg: Config) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async_main(cfg))
}

struct Sinks {
    log: EventLog,
    journal: Option<PathBuf>,
    hooks: Arc<AtomicUsize>,
}

impl Sinks {
    fn emit(&mut self, cfg: &Config, f: Finding) {
        self.log.append(&LogEvent::Finding {
            ts: now(),
            finding: f.clone(),
        });
        if f.severity < cfg.output.min_severity {
            return;
        }
        if let (true, Some(sock)) = (cfg.output.journal, &self.journal) {
            sink::journal_finding(sock, &f);
        }
        if let Some(cmd) = cfg.output.exec.clone() {
            if self.hooks.load(Ordering::Relaxed) >= MAX_HOOKS {
                tracing::warn!("{}: notify hook skipped, {MAX_HOOKS} already running", f.fingerprint);
                return;
            }
            let hooks = self.hooks.clone();
            hooks.fetch_add(1, Ordering::Relaxed);
            std::thread::spawn(move || {
                if let Err(e) = sink::exec_hook(&cmd, &f) {
                    tracing::warn!("{}: {e:#}", f.fingerprint);
                }
                hooks.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }
}

async fn async_main(cfg: Config) -> anyhow::Result<()> {
    let started = now();
    let config_dir = cfg.config_dir.clone();
    let state_dir = cfg.paths.state_dir.clone();
    std::fs::create_dir_all(&state_dir).map_err(|e| anyhow::anyhow!("{}: {e}", state_dir.display()))?;

    let mut engine = Engine::new(cfg, Host::default());
    engine.load_ownership();
    let probes = engine.probes();
    if probes.is_empty() {
        anyhow::bail!("every daemon rule is disabled; nothing to monitor");
    }
    let mut monitor = Monitor::start(&probes)?;
    let probe_status: Vec<ProbeStatus> = monitor
        .probes
        .iter()
        .map(|(p, r)| ProbeStatus {
            probe: format!("{p:?}").to_lowercase(),
            attached: r.is_ok(),
            error: r.as_ref().err().cloned(),
        })
        .collect();
    for p in probe_status.iter().filter(|p| !p.attached) {
        tracing::warn!("probe {} not attached: {}", p.probe, p.error.as_deref().unwrap_or(""));
    }
    if probe_status.iter().all(|p| !p.attached) {
        anyhow::bail!("no probe could be attached");
    }
    // SAFETY: the RingBuf owns its map descriptor and keeps it open, the
    // same one, until it is dropped with the AsyncFd.
    let mut ring = unsafe { AsyncFd::register_with_interest(monitor.events()?, tokio::io::Interest::READABLE) }
        .map_err(|e| anyhow::anyhow!("ring buffer: {e}"))?;

    let mut sinks = Sinks {
        log: EventLog::open(&engine.cfg().events_file()).unwrap_or_else(|e| {
            tracing::warn!("findings log unavailable ({e}); continuing without it");
            EventLog::sink()
        }),
        journal: Path::new(sink::JOURNAL_SOCKET)
            .exists()
            .then(|| sink::JOURNAL_SOCKET.into()),
        hooks: Arc::new(AtomicUsize::new(0)),
    };

    // Control socket.
    let sock = engine.cfg().paths.socket.clone();
    if let Some(dir) = sock.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| anyhow::anyhow!("bind {}: {e}", sock.display()))?;
    // Root only: status includes what the monitor has seen.
    let _ = std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<(Request, oneshot::Sender<Response>)>(16);
    tokio::task::spawn_local(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let ctl_tx = ctl_tx.clone();
            tokio::task::spawn_local(async move {
                let (r, mut w) = stream.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let resp = match serde_json::from_str::<Request>(&l) {
                        Ok(req) => {
                            let (otx, orx) = oneshot::channel();
                            if ctl_tx.send((req, otx)).await.is_err() {
                                break;
                            }
                            orx.await.unwrap_or_else(|_| Response::err("daemon stopping"))
                        }
                        Err(e) => Response::err(format!("bad request: {e}")),
                    };
                    let mut out = serde_json::to_string(&resp).unwrap_or_default();
                    out.push('\n');
                    if w.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut dropped_seen = 0u64;
    tracing::info!(
        socket = %sock.display(),
        "minsec-id daemon ready: {} of {} probes attached",
        probe_status.iter().filter(|p| p.attached).count(),
        probe_status.len()
    );

    let reload = |engine: &mut Engine| match Config::load_dir(&config_dir) {
        Ok(c) => {
            engine.reload(c);
            tracing::info!("configuration reloaded");
            Response::message("configuration reloaded (newly enabled rules need a restart)")
        }
        Err(e) => {
            tracing::warn!("reload: {e:#}");
            Response::err(format!("{e:#}"))
        }
    };

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = sighup.recv() => { reload(&mut engine); }
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let mut batch = Vec::new();
                while let Some(item) = guard.get_inner_mut().next() {
                    if let Some(ev) = Event::parse(&item) {
                        batch.push(ev);
                    }
                }
                guard.clear_ready();
                let t = now();
                for ev in batch {
                    let out = engine.handle(&ev, t);
                    if out.exec_ok {
                        monitor.exec_ok(ev.dev, ev.ino);
                    }
                    for f in out.findings {
                        sinks.emit(engine.cfg(), f);
                    }
                }
            }
            Some((req, reply)) = ctl_rx.recv() => {
                let resp = match req {
                    Request::Ping => Response::message("pong"),
                    Request::Reload => reload(&mut engine),
                    Request::Status => Response {
                        ok: true,
                        status: Some(Status {
                            version: env!("CARGO_PKG_VERSION").into(),
                            pid: std::process::id(),
                            uptime: now().saturating_sub(started),
                            probes: probe_status.clone(),
                            stats: engine.stats.clone(),
                            dropped: monitor.dropped(),
                            owned: engine.owned_count(),
                            rss_kb: control::rss_kb(),
                        }),
                        ..Default::default()
                    },
                };
                let _ = reply.send(resp);
            }
            _ = tick.tick() => {
                engine.prune(now());
                if let Err(e) = dirty::append(&state_dir, &engine.take_dirty()) {
                    tracing::warn!("dirty.list: {e}");
                }
                let dropped = monitor.dropped();
                if dropped > dropped_seen {
                    tracing::warn!("{} events lost: the ring buffer was full", dropped - dropped_seen);
                    dropped_seen = dropped;
                }
            }
        }
    }
    if let Err(e) = dirty::append(&state_dir, &engine.take_dirty()) {
        tracing::warn!("dirty.list: {e}");
    }
    let _ = std::fs::remove_file(&sock);
    tracing::info!("minsec-id daemon stopped");
    Ok(())
}
