//! minsec-id's eBPF programs and their loader.
//!
//! The programs are C (bpf/*.bpf.c), compiled by build.rs with clang
//! against the minimal CO-RE declarations in bpf/vmlinux.h, embedded here,
//! and loaded with aya. Two objects:
//!
//! - `monitor`: the daemon's probes. Each sends compact records through one
//!   ring buffer; userspace (`minsec_id_core::monitor`) turns them into
//!   findings.
//! - `iter`: a task iterator the scanner uses to list every process the
//!   kernel has, independently of `/proc`.

use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, FEntry, Iter, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use std::io::Read;

static MONITOR: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/monitor.o"));
static ITER: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/iter.o"));

/// Ring buffer records, exactly as bpf/event.h lays them out.
pub mod raw {
    pub const PATH_LEN: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Event {
        pub kind: u32,
        pub flags: u32,
        pub pid: u32,
        pub tid: u32,
        pub ppid: u32,
        pub uid: u32,
        pub euid: u32,
        pub dev: u32,
        pub ino: u64,
        pub mntns: u64,
        pub arg0: u64,
        pub arg1: u64,
        pub comm: [u8; 16],
        pub pcomm: [u8; 16],
        pub name: [u8; 64],
        pub path: [u8; PATH_LEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TaskRec {
        pub tgid: u32,
        pub ppid: u32,
        pub flags: u32,
        pub comm: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Conf {
        pub root_dentry: u64,
        pub learn: u32,
        pub pad: u32,
    }
    // SAFETY: plain old data with no padding holes the kernel would read.
    unsafe impl aya::Pod for Conf {}

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InoKey {
        pub ino: u64,
        pub dev: u32,
        pub pad: u32,
    }
    // SAFETY: as above; `pad` is always zero, matching the BPF side's key.
    unsafe impl aya::Pod for InoKey {}

    pub const LEARN_SB: u32 = 1;
    pub const LEARN_ROOT: u32 = 2;
}

/// Event flags (bpf/event.h `enum flag`).
pub mod flags {
    /// exec: the file had no links left when it was executed.
    pub const DELETED: u32 = 1 << 0;
    /// exec: the file is on tmpfs or ramfs.
    pub const TMPFS: u32 = 1 << 1;
    /// exec: fd 0 is a TCP or UDP socket.
    pub const STDIN_INET: u32 = 1 << 2;
    /// exec: fd 1 is a TCP or UDP socket.
    pub const STDOUT_INET: u32 = 1 << 3;
    /// exec: `path` is the execve argument, not a resolved path.
    pub const PATH_RAW: u32 = 1 << 4;
    /// The task's root directory is the host's: not a container or chroot.
    pub const HOST_ROOT: u32 = 1 << 5;
    /// write: the open created the file.
    pub const CREATED: u32 = 1 << 6;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A program started. `path` is the program (or script) executed.
    Exec,
    /// A watched file opened for writing. `arg0` is the open's f_mode.
    Write,
    /// A kernel module loaded: `name`; `arg0` is 1 if its signature
    /// verified, 0 if not, 2 if the kernel does not say; `arg1` its taints.
    Module,
    /// kexec: `arg0` is 0 for kexec_load, 1 for kexec_file_load; `arg1` the flags.
    Kexec,
    /// A tracing-kind BPF program load: `arg0` the program type, `arg1` the
    /// expected attach type, `name` the program name.
    Bpf,
    /// uid 0 gained outside a setuid exec: `arg0` the new euid, `arg1` the new uid.
    Creds,
    /// `arg0` the ptrace request (0xffffffff: process_vm_writev), `arg1` the target pid.
    Ptrace,
    /// /dev/mem, /dev/port, or /proc/kcore opened: `arg0` the device, `arg1` the f_mode.
    DevMem,
}

impl Kind {
    fn from_raw(k: u32) -> Option<Self> {
        Some(match k {
            1 => Kind::Exec,
            2 => Kind::Write,
            3 => Kind::Module,
            4 => Kind::Kexec,
            5 => Kind::Bpf,
            6 => Kind::Creds,
            7 => Kind::Ptrace,
            8 => Kind::DevMem,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Exec => "exec",
            Kind::Write => "write",
            Kind::Module => "module",
            Kind::Kexec => "kexec",
            Kind::Bpf => "bpf",
            Kind::Creds => "creds",
            Kind::Ptrace => "ptrace",
            Kind::DevMem => "devmem",
        }
    }
}

/// A decoded ring buffer record. Pids are as the host sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    pub flags: u32,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub euid: u32,
    pub dev: u32,
    pub ino: u64,
    pub mntns: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub comm: String,
    /// The parent's comm.
    pub pcomm: String,
    pub name: String,
    pub path: String,
}

fn cstr(b: &[u8]) -> String {
    let n = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}

impl Event {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < std::mem::size_of::<raw::Event>() {
            return None;
        }
        // SAFETY: the length is checked; raw::Event is plain old data, read unaligned.
        let r: raw::Event = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const raw::Event) };
        Some(Event {
            kind: Kind::from_raw(r.kind)?,
            flags: r.flags,
            pid: r.pid,
            tid: r.tid,
            ppid: r.ppid,
            uid: r.uid,
            euid: r.euid,
            dev: r.dev,
            ino: r.ino,
            mntns: r.mntns,
            arg0: r.arg0,
            arg1: r.arg1,
            comm: cstr(&r.comm),
            pcomm: cstr(&r.pcomm),
            name: cstr(&r.name),
            path: cstr(&r.path),
        })
    }

    pub fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// A blank event of `kind`, for tests and synthetic input.
    pub fn new(kind: Kind) -> Self {
        Event {
            kind,
            flags: 0,
            pid: 0,
            tid: 0,
            ppid: 0,
            uid: 0,
            euid: 0,
            dev: 0,
            ino: 0,
            mntns: 0,
            arg0: 0,
            arg1: 0,
            comm: String::new(),
            pcomm: String::new(),
            name: String::new(),
            path: String::new(),
        }
    }
}

/// A group of programs that feeds one kind of event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Probe {
    Exec,
    Write,
    DevMem,
    Module,
    Kexec,
    Bpf,
    Creds,
    Ptrace,
}

enum Attach {
    FEntry(&'static str),
    TpBtf(&'static str),
    Syscall(&'static str),
}

impl Probe {
    pub const ALL: &'static [Probe] = &[
        Probe::Exec,
        Probe::Write,
        Probe::DevMem,
        Probe::Module,
        Probe::Kexec,
        Probe::Bpf,
        Probe::Creds,
        Probe::Ptrace,
    ];

    fn programs(&self) -> &'static [&'static str] {
        match self {
            Probe::Exec => &["msid_open", "msid_exec", "msid_execve", "msid_execveat"],
            Probe::Write | Probe::DevMem => &["msid_open"],
            Probe::Module => &["msid_mod"],
            Probe::Kexec => &["msid_kexec", "msid_kexecf"],
            Probe::Bpf => &["msid_bpf"],
            Probe::Creds => &["msid_bprm", "msid_creds"],
            Probe::Ptrace => &["msid_ptrace", "msid_vmw"],
        }
    }

    /// Bit in the BPF side's `rules` mask, for probes sharing `msid_open`.
    fn mask(&self) -> u32 {
        match self {
            Probe::Exec => 1,
            Probe::Write => 2,
            Probe::DevMem => 4,
            _ => 0,
        }
    }
}

fn attach_point(prog: &str) -> Attach {
    match prog {
        "msid_open" => Attach::FEntry("security_file_open"),
        "msid_bprm" => Attach::FEntry("security_bprm_committing_creds"),
        "msid_creds" => Attach::FEntry("commit_creds"),
        "msid_exec" => Attach::TpBtf("sched_process_exec"),
        "msid_mod" => Attach::TpBtf("module_load"),
        "msid_execve" => Attach::Syscall("sys_enter_execve"),
        "msid_execveat" => Attach::Syscall("sys_enter_execveat"),
        "msid_kexec" => Attach::Syscall("sys_enter_kexec_load"),
        "msid_kexecf" => Attach::Syscall("sys_enter_kexec_file_load"),
        "msid_bpf" => Attach::Syscall("sys_enter_bpf"),
        "msid_ptrace" => Attach::Syscall("sys_enter_ptrace"),
        "msid_vmw" => Attach::Syscall("sys_enter_process_vm_writev"),
        _ => unreachable!("unknown program {prog}"),
    }
}

/// Directories whose filesystems' writes are watched (by superblock, so
/// any path to the same filesystem counts).
const WATCHED_DIRS: &[&str] = &["/", "/usr", "/etc", "/boot", "/boot/efi", "/efi", "/var/spool/cron"];

/// The loaded monitor. Dropping it detaches everything.
pub struct Monitor {
    ebpf: Ebpf,
    exec_ok: Option<HashMap<MapData, raw::InoKey, u8>>,
    /// Per probe: attached, or why not.
    pub probes: Vec<(Probe, Result<(), String>)>,
}

impl Monitor {
    /// Load the monitor and attach the programs `want` needs. A probe that
    /// cannot attach (a tracepoint the kernel lacks) is reported in
    /// `probes`, not an error; failing to load at all is.
    pub fn start(want: &[Probe]) -> anyhow::Result<Self> {
        if let Some(why) = unavailable() {
            anyhow::bail!("{why}");
        }
        let btf = Btf::from_sys_fs().map_err(|e| anyhow::anyhow!("kernel BTF (/sys/kernel/btf/vmlinux): {e}"))?;
        let mask: u32 = want.iter().map(Probe::mask).fold(0, |a, b| a | b);
        let tgid = std::process::id();
        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .override_global("self_tgid", &tgid, true)
            .override_global("rules", &mask, true)
            .load(MONITOR)
            .map_err(|e| anyhow::anyhow!("loading BPF programs: {e}"))?;

        let mut done: std::collections::HashMap<&str, Result<(), String>> = Default::default();
        let mut probes = Vec::new();
        for p in want {
            let mut status = Ok(());
            for prog in p.programs() {
                let r = done
                    .entry(prog)
                    .or_insert_with(|| attach(&mut ebpf, prog, &btf).map_err(|e| format!("{prog}: {e:#}")));
                if let (Ok(()), Err(e)) = (&status, r) {
                    status = Err(e.clone());
                }
            }
            probes.push((*p, status));
        }
        drop(btf);
        let mut m = Monitor {
            exec_ok: None,
            probes,
            ebpf,
        };
        if matches!(done.get("msid_open"), Some(Ok(()))) {
            m.learn()?;
        }
        if want.contains(&Probe::Exec) {
            m.exec_ok = m.ebpf.take_map("exec_ok").map(HashMap::try_from).transpose()?;
        }
        // Parsing the kernel's BTF is the daemon's largest allocation.
        // SAFETY: malloc_trim only returns free heap pages to the kernel.
        unsafe { libc::malloc_trim(0) };
        Ok(m)
    }

    /// Teach the BPF side the host's root directory and the superblocks to
    /// watch, by opening them: `msid_open` records what this process opens
    /// while `learn` is set. Pid 1's view is used, not this process's,
    /// which may be in a sandboxed mount namespace.
    fn learn(&mut self) -> anyhow::Result<()> {
        let mut conf: Array<&mut MapData, raw::Conf> = Array::try_from(
            self.ebpf
                .map_mut("conf")
                .ok_or_else(|| anyhow::anyhow!("no conf map"))?,
        )?;
        let mut set = |learn: u32| {
            conf.set(
                0,
                raw::Conf {
                    learn,
                    ..conf.get(&0, 0).unwrap_or_default()
                },
                0,
            )
        };
        set(raw::LEARN_ROOT)?;
        let root = std::fs::File::open("/proc/1/root");
        set(raw::LEARN_SB)?;
        for d in WATCHED_DIRS {
            let _ = std::fs::File::open(format!("/proc/1/root{d}"));
        }
        set(0)?;
        root.map_err(|e| anyhow::anyhow!("/proc/1/root: {e}"))?;
        Ok(())
    }

    /// The ring buffer, to poll. Call once.
    pub fn events(&mut self) -> anyhow::Result<RingBuf<MapData>> {
        let m = self
            .ebpf
            .take_map("events")
            .ok_or_else(|| anyhow::anyhow!("events ring buffer already taken"))?;
        Ok(RingBuf::try_from(m)?)
    }

    /// Stop sending execs of this file (until something opens it for writing).
    pub fn exec_ok(&mut self, dev: u32, ino: u64) {
        if let Some(m) = self.exec_ok.as_mut() {
            let _ = m.insert(raw::InoKey { ino, dev, pad: 0 }, 1, 0);
        }
    }

    /// Records lost because the ring buffer was full.
    pub fn dropped(&self) -> u64 {
        let Some(m) = self.ebpf.map("dropped") else { return 0 };
        let Ok(a) = PerCpuArray::<&MapData, u64>::try_from(m) else {
            return 0;
        };
        a.get(&0, 0).map(|v| v.iter().sum()).unwrap_or(0)
    }
}

fn attach(ebpf: &mut Ebpf, prog: &str, btf: &Btf) -> anyhow::Result<()> {
    let p = ebpf
        .program_mut(prog)
        .ok_or_else(|| anyhow::anyhow!("program missing from object"))?;
    match attach_point(prog) {
        Attach::FEntry(f) => {
            let p: &mut FEntry = p.try_into()?;
            p.load(f, btf)?;
            p.attach()?;
        }
        Attach::TpBtf(t) => {
            let p: &mut BtfTracePoint = p.try_into()?;
            p.load(t, btf)?;
            p.attach()?;
        }
        Attach::Syscall(t) => {
            let p: &mut TracePoint = p.try_into()?;
            p.load()?;
            p.attach("syscalls", t)?;
        }
    }
    Ok(())
}

/// Why this process cannot load the programs, if it cannot: no BTF, or
/// neither CAP_SYS_ADMIN nor CAP_BPF with CAP_PERFMON (an unprivileged user,
/// or a container).
pub fn unavailable() -> Option<String> {
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Some("the kernel has no BTF (/sys/kernel/btf/vmlinux)".into());
    }
    let caps = std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())?;
    let has = |cap: u32| caps & (1u64 << cap) != 0;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    (!(has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))))
        .then(|| "loading BPF programs needs CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN (run as root)".into())
}

/// A process (thread group leader) as the kernel's task list has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub pid: u32,
    pub ppid: u32,
    /// `task_struct.flags` (PF_KTHREAD = 0x0020_0000).
    pub flags: u32,
    pub comm: String,
}

pub const PF_KTHREAD: u32 = 0x0020_0000;

/// Every process, from a BPF task iterator: the kernel's own list, which
/// hiding a pid from `/proc` does not change.
pub fn tasks() -> anyhow::Result<Vec<Task>> {
    let btf = Btf::from_sys_fs().map_err(|e| anyhow::anyhow!("kernel BTF: {e}"))?;
    let mut ebpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load(ITER)
        .map_err(|e| anyhow::anyhow!("loading BPF iterator: {e}"))?;
    let p: &mut Iter = ebpf
        .program_mut("msid_tasks")
        .ok_or_else(|| anyhow::anyhow!("iterator missing from object"))?
        .try_into()?;
    p.load("task", &btf)?;
    drop(btf);
    let id = p.attach()?;
    let mut file = p.take_link(id)?.into_file()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let n = std::mem::size_of::<raw::TaskRec>();
    let out = buf
        .chunks_exact(n)
        .map(|c| {
            // SAFETY: each chunk is exactly one raw::TaskRec, plain old data.
            let r: raw::TaskRec = unsafe { std::ptr::read_unaligned(c.as_ptr() as *const raw::TaskRec) };
            Task {
                pid: r.tgid,
                ppid: r.ppid,
                flags: r.flags,
                comm: cstr(&r.comm),
            }
        })
        .collect();
    // SAFETY: as in Monitor::start.
    unsafe { libc::malloc_trim(0) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_c() {
        assert_eq!(std::mem::size_of::<raw::Event>(), 416);
        assert_eq!(std::mem::size_of::<raw::TaskRec>(), 28);
        assert_eq!(std::mem::size_of::<raw::Conf>(), 16);
        assert_eq!(std::mem::size_of::<raw::InoKey>(), 16);
    }

    #[test]
    fn parses_a_record() {
        let mut r: raw::Event = unsafe { std::mem::zeroed() };
        r.kind = 1;
        r.pid = 42;
        r.flags = flags::DELETED | flags::HOST_ROOT;
        r.comm[..4].copy_from_slice(b"bash");
        r.path[..7].copy_from_slice(b"/tmp/x\0");
        // SAFETY: viewing a POD struct as bytes.
        let b = unsafe {
            std::slice::from_raw_parts(&r as *const raw::Event as *const u8, std::mem::size_of::<raw::Event>())
        };
        let e = Event::parse(b).unwrap();
        assert_eq!(e.kind, Kind::Exec);
        assert_eq!((e.pid, e.comm.as_str(), e.path.as_str()), (42, "bash", "/tmp/x"));
        assert!(e.has(flags::DELETED) && !e.has(flags::TMPFS));
        assert!(Event::parse(&b[..100]).is_none());
    }

    #[test]
    fn objects_are_embedded() {
        assert_eq!(&MONITOR[..4], b"\x7fELF");
        assert_eq!(&ITER[..4], b"\x7fELF");
    }
}
