//! `bpf-prog-unknown`: loaded eBPF programs of the tracing kinds a rootkit
//! uses (kprobe, tracepoint, fentry, LSM, …), enumerated with the `bpf`
//! syscall so the kernel, not a process listing, is the source of truth.
//! Networking and cgroup programs (firewalls, systemd's device and IP
//! filters) are not reported.

use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::procfs;
use std::collections::HashMap;

pub struct BpfProgs;

const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

/// Program types that observe or alter kernel behaviour.
pub(crate) const TRACING_TYPES: &[(u32, &str)] = &[
    (2, "kprobe"),
    (5, "tracepoint"),
    (7, "perf_event"),
    (17, "raw_tracepoint"),
    (24, "raw_tracepoint_writable"),
    (26, "tracing"),
    (28, "ext"),
    (29, "lsm"),
];

/// Programs the kernel or systemd load themselves (names are truncated to
/// 15 characters by the kernel). `msid_` is reserved for minsec-id's own.
pub(crate) const KNOWN: &[&str] = &["restrict_filesy", "dump_bpf_map", "dump_bpf_prog", "hid_tail_call"];

#[derive(Debug, Clone)]
pub(crate) struct ProgInfo {
    id: u32,
    kind: &'static str,
    tag: String,
    name: String,
    uid: u32,
}

#[repr(C)]
#[derive(Default)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
struct InfoAttr {
    fd: u32,
    info_len: u32,
    info: u64,
}

fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> std::io::Result<i64> {
    // SAFETY: attr is a valid, initialized bpf_attr prefix of the given size.
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *mut T, std::mem::size_of::<T>() as u32) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn programs() -> std::io::Result<Vec<ProgInfo>> {
    let mut out = Vec::new();
    let mut id = 0u32;
    loop {
        let mut a = IdAttr {
            id,
            ..Default::default()
        };
        match bpf(BPF_PROG_GET_NEXT_ID, &mut a) {
            Ok(_) => id = a.next_id,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
            Err(e) => return Err(e),
        }
        let mut f = IdAttr {
            id,
            ..Default::default()
        };
        let fd = match bpf(BPF_PROG_GET_FD_BY_ID, &mut f) {
            Ok(fd) => fd as i32,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue, // unloaded meanwhile
            Err(e) => return Err(e),
        };
        // bpf_prog_info, read by offset: type@0 id@4 tag@8 created_by_uid@48 name@64.
        let mut buf = [0u8; 256];
        let mut ia = InfoAttr {
            fd: fd as u32,
            info_len: buf.len() as u32,
            info: buf.as_mut_ptr() as u64,
        };
        let r = bpf(BPF_OBJ_GET_INFO_BY_FD, &mut ia);
        // SAFETY: fd came from the kernel above and is closed exactly once.
        unsafe { libc::close(fd) };
        if r.is_err() {
            continue;
        }
        let u32_at = |o: usize| u32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        let ty = u32_at(0);
        let Some((_, kind)) = TRACING_TYPES.iter().find(|(t, _)| *t == ty) else {
            continue;
        };
        let name_raw = &buf[64..80];
        let name_len = name_raw.iter().position(|b| *b == 0).unwrap_or(16);
        out.push(ProgInfo {
            id: u32_at(4),
            kind,
            tag: crate::digest::hex(&buf[8..16]),
            name: String::from_utf8_lossy(&name_raw[..name_len]).into_owned(),
            uid: u32_at(48),
        });
    }
    Ok(out)
}

/// prog id → processes holding an fd to it.
fn holders(host: &Host) -> HashMap<u32, Vec<serde_json::Value>> {
    let mut m: HashMap<u32, Vec<serde_json::Value>> = HashMap::new();
    for p in procfs::all(host) {
        for (fd, target) in procfs::fds(host, p.pid) {
            if target != "anon_inode:bpf-prog" {
                continue;
            }
            let info = std::fs::read_to_string(host.path(format!("/proc/{}/fdinfo/{fd}", p.pid))).unwrap_or_default();
            if let Some(id) = info
                .lines()
                .find_map(|l| l.strip_prefix("prog_id:"))
                .and_then(|v| v.trim().parse().ok())
            {
                m.entry(id)
                    .or_default()
                    .push(serde_json::json!({ "pid": p.pid, "comm": p.comm, "exe": p.exe }));
            }
        }
    }
    m
}

/// Whether a process is minsec-id itself (the daemon, or a scan).
fn is_minsec_id(holder: &serde_json::Value) -> bool {
    holder["exe"]
        .as_str()
        .map(|e| e.trim_end_matches(" (deleted)"))
        .is_some_and(|e| e.rsplit('/').next() == Some("minsec-id"))
}

/// Programs a systemd service loads and keeps open (systemd-nsresourced's
/// user namespace restrictions). Known only while systemd's own binaries are
/// all that hold them.
const SYSTEMD_HELD: &[&str] = &["userns_restrict"];

fn is_systemd(holder: &serde_json::Value) -> bool {
    holder["exe"]
        .as_str()
        .is_some_and(|e| e.starts_with("/usr/lib/systemd/") && !e.ends_with(" (deleted)"))
}

type Holders = HashMap<u32, Vec<serde_json::Value>>;

/// Kernel functions systemd's kprobe programs attach to (nsresourced's
/// `kprobe/free_user_ns`), by program name.
const SYSTEMD_KPROBES: &[(&str, &str)] = &[("userns_restrict", "free_user_ns")];

/// Functions hooked by kprobe that a systemd-held program explains: shown
/// by ftrace as kprobes, not BPF trampolines.
pub(crate) fn explained_kprobes(host: &Host) -> Vec<&'static str> {
    let Ok(progs) = programs() else {
        return Vec::new();
    };
    let wanted: Vec<&ProgInfo> = progs
        .iter()
        .filter(|p| p.kind == "kprobe" && SYSTEMD_KPROBES.iter().any(|(n, _)| *n == p.name))
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let held = holders(host);
    wanted
        .into_iter()
        .filter(|p| {
            held.get(&p.id)
                .is_some_and(|by| !by.is_empty() && by.iter().all(is_systemd))
        })
        .filter_map(|p| SYSTEMD_KPROBES.iter().find(|(n, _)| *n == p.name).map(|(_, f)| *f))
        .collect()
}

/// Tracing-kind programs nothing known explains, and who holds each
/// program. A `msid_` name is minsec-id's only if a minsec-id process
/// holds it: the prefix alone is no alibi.
pub(crate) fn unexplained(host: &Host) -> std::io::Result<(Vec<ProgInfo>, Holders)> {
    let progs: Vec<ProgInfo> = programs()?
        .into_iter()
        .filter(|p| !KNOWN.contains(&p.name.as_str()))
        .collect();
    if progs.is_empty() {
        return Ok((progs, HashMap::new()));
    }
    let held = holders(host);
    let unknown = progs
        .into_iter()
        .filter(|p| {
            let by = held.get(&p.id).map(Vec::as_slice).unwrap_or_default();
            if p.name.starts_with("msid_") {
                return by.is_empty() || !by.iter().all(is_minsec_id);
            }
            if SYSTEMD_HELD.contains(&p.name.as_str()) {
                return by.is_empty() || !by.iter().all(is_systemd);
            }
            true
        })
        .collect();
    Ok((unknown, held))
}

impl Check for BpfProgs {
    fn id(&self) -> &'static str {
        "bpf-prog-unknown"
    }

    fn description(&self) -> &'static str {
        "loaded eBPF tracing, kprobe, and LSM programs"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (host.root() != std::path::Path::new("/")).then(|| "only the running kernel can be asked".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let (unknown, held) = match unexplained(ctx.host) {
            Ok(u) => u,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                return Err(Unavailable("enumerating BPF programs needs CAP_SYS_ADMIN (run as root)".into()).into())
            }
            Err(e) => anyhow::bail!("bpf: {e}"),
        };
        Ok(unknown
            .into_iter()
            .map(|p| {
                let by = held.get(&p.id).cloned().unwrap_or_default();
                // Nothing holds it: pinned, or attached and abandoned by its loader.
                let orphan = by.is_empty();
                let subject = format!("{}/{}", p.kind, if p.name.is_empty() { "-" } else { &p.name });
                Finding::new(
                    self.id(),
                    if orphan { Severity::High } else { Severity::Medium },
                    &subject,
                    &p.tag,
                )
                .message(format!(
                    "{} BPF program {} (id {}){}",
                    p.kind,
                    if p.name.is_empty() { "(unnamed)" } else { &p.name },
                    p.id,
                    if orphan { " held by no process" } else { "" }
                ))
                .detail(serde_json::json!({ "id": p.id, "tag": p.tag, "uid": p.uid, "holders": by }))
            })
            .collect())
    }
}
