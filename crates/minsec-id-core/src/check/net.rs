//! Sockets.
//!
//! `net-listener` lists listening TCP and bound UDP sockets two ways, via
//! `sock_diag` netlink and via `/proc/net`, and reports sockets the second
//! view hides (`net-hidden`: rootkits filter `/proc/net/tcp`, rarely
//! netlink), and listeners whose process runs a binary no package owns
//! (`net-listener-unowned`).
//!
//! `net-raw-socket` reports packet and raw IP sockets, which see traffic
//! below the firewall, held by processes outside the usual set (DHCP
//! clients, network managers, capture tools). BPFDoor-style backdoors sit
//! on such a socket.

use super::proc_exe::suspicious_location;
use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::{Canon, Host};
use crate::procfs::{self, Proc};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct NetListeners;
pub struct NetRaw;

const TCP_LISTEN: u8 = 10;
const TCP_CLOSE: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Sock {
    pub proto: &'static str,
    pub port: u16,
    pub inode: u64,
}

/// `/proc/net/{tcp,tcp6,udp,udp6}` rows in the given state (hex `st`).
fn proc_net(host: &Host, file: &str, state: u8) -> Vec<(u16, u64)> {
    let Some(s) = host.read_opt(format!("/proc/net/{file}")) else {
        return Vec::new();
    };
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || u8::from_str_radix(f[3], 16).ok()? != state {
                return None;
            }
            let port = u16::from_str_radix(f[1].rsplit_once(':')?.1, 16).ok()?;
            Some((port, f[9].parse().ok()?))
        })
        .collect()
}

/// Inodes of every TCP and UDP socket in this network namespace.
pub(crate) fn inet_inodes(host: &Host) -> HashSet<u64> {
    let mut set = HashSet::new();
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        if let Some(s) = host.read_opt(format!("/proc/net/{file}")) {
            set.extend(
                s.lines()
                    .skip(1)
                    .filter_map(|l| l.split_whitespace().nth(9)?.parse::<u64>().ok())
                    .filter(|i| *i != 0),
            );
        }
    }
    set
}

fn proc_listeners(host: &Host) -> Vec<Sock> {
    let mut v = Vec::new();
    for (file, proto, state) in [
        ("tcp", "tcp", TCP_LISTEN),
        ("tcp6", "tcp6", TCP_LISTEN),
        ("udp", "udp", TCP_CLOSE),
        ("udp6", "udp6", TCP_CLOSE),
    ] {
        v.extend(
            proc_net(host, file, state)
                .into_iter()
                .map(|(port, inode)| Sock { proto, port, inode }),
        );
    }
    v
}

/// The same sockets from the kernel's `sock_diag` interface.
fn diag_listeners() -> std::io::Result<Vec<Sock>> {
    let mut v = Vec::new();
    for (family, proto, ipproto, state) in [
        (libc::AF_INET as u8, "tcp", libc::IPPROTO_TCP as u8, TCP_LISTEN),
        (libc::AF_INET6 as u8, "tcp6", libc::IPPROTO_TCP as u8, TCP_LISTEN),
        (libc::AF_INET as u8, "udp", libc::IPPROTO_UDP as u8, TCP_CLOSE),
        (libc::AF_INET6 as u8, "udp6", libc::IPPROTO_UDP as u8, TCP_CLOSE),
    ] {
        for (port, inode) in inet_diag(family, ipproto, 1u32 << state)? {
            v.push(Sock { proto, port, inode });
        }
    }
    Ok(v)
}

/// One `SOCK_DIAG_BY_FAMILY` dump: (local port, inode) per socket.
fn inet_diag(family: u8, protocol: u8, states: u32) -> std::io::Result<Vec<(u16, u64)>> {
    const NETLINK_SOCK_DIAG: i32 = 4;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    // SAFETY: plain socket creation; ownership moves into OwnedFd.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // nlmsghdr (16) + inet_diag_req_v2 (56).
    let mut req = [0u8; 72];
    req[0..4].copy_from_slice(&72u32.to_ne_bytes());
    req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    req[16] = family;
    req[17] = protocol;
    req[20..24].copy_from_slice(&states.to_ne_bytes());
    // SAFETY: sending a fully initialized buffer to the kernel.
    if unsafe { libc::send(fd.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: receiving into an owned buffer of the given length.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let mut off = 0usize;
        let n = n as usize;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > n {
                break;
            }
            match ty {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => {
                    let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                    if errno == 0 {
                        return Ok(out);
                    }
                    return Err(std::io::Error::from_raw_os_error(-errno));
                }
                SOCK_DIAG_BY_FAMILY if len >= 16 + 72 => {
                    // inet_diag_msg: id.sport at 4 (big-endian), inode at 68.
                    let m = &buf[off + 16..off + len];
                    let port = u16::from_be_bytes([m[4], m[5]]);
                    let inode = u32::from_ne_bytes(m[68..72].try_into().unwrap()) as u64;
                    out.push((port, inode));
                }
                _ => {}
            }
            off += (len + 3) & !3;
        }
    }
}

/// Socket inode → the first process holding it.
fn owners<'a>(host: &Host, procs: &'a [Proc]) -> HashMap<u64, &'a Proc> {
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();
    procfs::socket_owners(host, procs)
        .into_iter()
        .filter_map(|(ino, pids)| Some((ino, *pids.iter().find_map(|pid| by_pid.get(pid))?)))
        .collect()
}

impl Check for NetListeners {
    fn id(&self) -> &'static str {
        "net-listener"
    }

    fn description(&self) -> &'static str {
        "listening sockets hidden from /proc/net, or served by binaries no package owns"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["net-hidden", "net-listener-unowned"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (host.root() != std::path::Path::new("/")).then(|| "only the running kernel can be asked".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let mut out = Vec::new();

        let diag = diag_listeners().map_err(|e| anyhow::anyhow!("sock_diag: {e}"))?;
        let visible: HashSet<u64> = proc_listeners(host).into_iter().map(|s| s.inode).collect();
        let mut hidden: Vec<Sock> = diag.iter().filter(|s| !visible.contains(&s.inode)).cloned().collect();
        if !hidden.is_empty() {
            // Sockets come and go: recheck before calling one hidden.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let visible: HashSet<u64> = proc_listeners(host).into_iter().map(|s| s.inode).collect();
            let still: HashSet<u64> = diag_listeners()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.inode)
                .collect();
            hidden.retain(|s| still.contains(&s.inode) && !visible.contains(&s.inode));
        }
        let procs = procfs::all(host);
        let owner = owners(host, &procs);
        for s in &hidden {
            let p = owner.get(&s.inode);
            out.push(
                Finding::new("net-hidden", Severity::Critical, format!("{}/{}", s.proto, s.port), "")
                    .message(format!(
                        "{}/{} is listening but hidden from /proc/net{}",
                        s.proto,
                        s.port,
                        p.map(|p| format!(" (pid {} {})", p.pid, p.comm)).unwrap_or_default()
                    ))
                    .detail(serde_json::json!({ "inode": s.inode, "pid": p.map(|p| p.pid), "exe": p.and_then(|p| p.exe.clone()) })),
            );
        }

        let db = ctx.pkgdb()?;
        if db.is_empty() {
            return Ok(out);
        }
        let mut canon = Canon::new(host);
        // exe → (ports, example process)
        let mut unowned: BTreeMap<String, (Vec<String>, &Proc)> = BTreeMap::new();
        for s in &diag {
            let Some(p) = owner.get(&s.inode) else { continue }; // kernel sockets
            if !p.host_mnt_ns {
                continue;
            }
            let Some((exe, _)) = p.exe_path() else { continue };
            if exe.starts_with("/memfd:") || db.owns(&canon.path(exe)) {
                continue; // proc-exe reports memfds
            }
            let e = unowned.entry(exe.to_string()).or_insert((Vec::new(), p));
            let port = format!("{}/{}", s.proto, s.port);
            if !e.0.contains(&port) {
                e.0.push(port);
            }
        }
        for (exe, (mut ports, p)) in unowned {
            ports.sort();
            let local = exe.starts_with("/usr/local/") || exe.starts_with("/opt/");
            out.push(
                Finding::new(
                    "net-listener-unowned",
                    if local { Severity::Low } else { Severity::Medium },
                    &exe,
                    &ports.join(","),
                )
                .message(format!("{exe} (not from a package) listens on {}", ports.join(", ")))
                .detail(serde_json::json!({ "ports": ports, "pid": p.pid, "uid": p.uid })),
            );
        }
        Ok(out)
    }
}

/// Programs expected to hold packet or raw sockets.
const RAW_OK: &[&str] = &[
    "NetworkManager",
    "dhclient",
    "dhcpcd",
    "dhcpd",
    "dhcrelay",
    "dnsmasq",
    "systemd-networkd",
    "wpa_supplicant",
    "lldpd",
    "keepalived",
    "tcpdump",
    "dumpcap",
    "tshark",
    "arping",
    "ping",
    "radvd",
    "bird",
    "ospfd",
    "ospf6d",
    "isisd",
    "suricata",
    "snort",
    "zeek",
    "kea-dhcp4",
    "kea-dhcp6",
    "chronyd",
    "ntpd",
];

/// (kind, protocol, inode) of packet and raw sockets.
fn raw_sockets(host: &Host) -> Vec<(&'static str, String, u64)> {
    let mut v = Vec::new();
    if let Some(s) = host.read_opt("/proc/net/packet") {
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 9 {
                if let Ok(ino) = f[8].parse() {
                    v.push(("packet", f[3].to_string(), ino));
                }
            }
        }
    }
    for file in ["raw", "raw6"] {
        if let Some(s) = host.read_opt(format!("/proc/net/{file}")) {
            for l in s.lines().skip(1) {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() >= 10 {
                    let proto = f[1].rsplit_once(':').map(|(_, p)| p.to_string()).unwrap_or_default();
                    if let Ok(ino) = f[9].parse() {
                        v.push((if file == "raw" { "raw" } else { "raw6" }, proto, ino));
                    }
                }
            }
        }
    }
    v
}

impl Check for NetRaw {
    fn id(&self) -> &'static str {
        "net-raw-socket"
    }

    fn description(&self) -> &'static str {
        "packet and raw IP sockets held by unexpected processes"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/proc/net/packet")).then(|| "no /proc/net/packet".into())
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let socks = raw_sockets(host);
        if socks.is_empty() {
            return Ok(Vec::new());
        }
        let db = ctx.pkgdb()?;
        let procs = procfs::all(host);
        let owner = owners(host, &procs);
        let mut canon = Canon::new(host);
        // exe → (kinds, process)
        let mut by_exe: BTreeMap<String, (Vec<String>, &Proc)> = BTreeMap::new();
        for (kind, proto, ino) in socks {
            let Some(p) = owner.get(&ino) else { continue };
            let exe = p.exe.clone().unwrap_or_else(|| format!("[{}]", p.comm));
            let e = by_exe.entry(exe).or_insert((Vec::new(), p));
            let k = format!("{kind}:{proto}");
            if !e.0.contains(&k) {
                e.0.push(k);
            }
        }
        let mut out = Vec::new();
        for (exe, (kinds, p)) in by_exe {
            let (path, deleted) = p.exe_path().unwrap_or((&exe, false));
            let base = path.rsplit('/').next().unwrap_or(path);
            let bad_location = deleted || path.starts_with("/memfd:") || suspicious_location(path, p.host_mnt_ns);
            let owned = p.host_mnt_ns && !db.is_empty() && db.owns(&canon.path(path));
            let severity = if bad_location || (p.host_mnt_ns && !db.is_empty() && !owned) {
                Severity::High
            } else if RAW_OK.contains(&base) || RAW_OK.contains(&p.comm.as_str()) || !p.host_mnt_ns {
                continue;
            } else {
                Severity::Low
            };
            out.push(
                Finding::new(self.id(), severity, &exe, &kinds.join(","))
                    .message(format!(
                        "{} (pid {}) holds {} socket(s): {}",
                        exe,
                        p.pid,
                        if kinds.iter().any(|k| k.starts_with("packet")) {
                            "packet"
                        } else {
                            "raw"
                        },
                        kinds.join(", ")
                    ))
                    .detail(serde_json::json!({ "pid": p.pid, "uid": p.uid, "sockets": kinds, "owned": owned })),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netlink_agrees_with_proc_for_our_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let diag = diag_listeners().unwrap();
        let ours: Vec<&Sock> = diag.iter().filter(|s| s.proto == "tcp" && s.port == port).collect();
        assert_eq!(ours.len(), 1, "{diag:?}");
        let host = Host::default();
        assert!(proc_listeners(&host).iter().any(|s| s.inode == ours[0].inode));
        assert!(inet_inodes(&host).contains(&ours[0].inode));
    }
}
