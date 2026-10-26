//! `ftrace-hooks`: kernel functions with ftrace callbacks attached, from
//! tracefs's `enabled_functions`. Rootkits hook syscalls and `filldir` this
//! way; so do BPF trampolines, kprobes, live patches, and an admin running a
//! tracer, which are reported at lower severity and grouped by owner. BPF
//! trampolines are not reported at all when every loaded tracing program is
//! known (systemd's, minsec-id's own), nor kprobes that systemd's own
//! programs attach.

use super::{Anchors, Check, Cost, Ctx, Unavailable};
use crate::finding::{fingerprint, Finding, Severity};
use crate::host::Host;
use std::collections::BTreeMap;

pub struct Ftrace;

const PATHS: &[&str] = &[
    "/sys/kernel/tracing/enabled_functions",
    "/sys/kernel/debug/tracing/enabled_functions",
];

/// Who attached a hook, from the rest of its `enabled_functions` line.
fn owner(rest: &str) -> (String, Severity) {
    if rest.contains("bpf_trampoline") || rest.contains("direct-->") || rest.contains("direct:") {
        return ("bpf".into(), Severity::Low);
    }
    if rest.contains("klp_") || rest.contains("livepatch") {
        return ("livepatch".into(), Severity::Info);
    }
    if rest.contains("kprobe_ftrace_handler") || rest.contains("kprobe") {
        return ("kprobe".into(), Severity::Low);
    }
    // A callback in a module is listed as `func [module]`.
    if let Some(m) = rest
        .rsplit_once('[')
        .and_then(|(_, m)| m.strip_suffix(']').or_else(|| m.split(']').next()))
    {
        if !m.is_empty() && !m.starts_with("__builtin") {
            return (format!("module:{m}"), Severity::High);
        }
    }
    ("tracer".into(), Severity::Low)
}

/// owner → (severity, hooked functions).
fn parse(s: &str) -> BTreeMap<String, (Severity, Vec<String>)> {
    // An entry is a `func (count) flags …` line plus indented continuations.
    let mut entries: Vec<(String, String)> = Vec::new();
    for l in s.lines() {
        if l.starts_with(char::is_whitespace) {
            if let Some(last) = entries.last_mut() {
                last.1.push(' ');
                last.1.push_str(l.trim());
            }
            continue;
        }
        if let Some((func, rest)) = l.split_once(char::is_whitespace) {
            entries.push((func.to_string(), rest.to_string()));
        }
    }
    let mut m: BTreeMap<String, (Severity, Vec<String>)> = BTreeMap::new();
    for (func, rest) in entries {
        let (o, sev) = owner(&rest);
        m.entry(o).or_insert((sev, Vec::new())).1.push(func);
    }
    m
}

impl Check for Ftrace {
    fn id(&self) -> &'static str {
        "ftrace-hooks"
    }

    fn description(&self) -> &'static str {
        "kernel functions hooked through ftrace, grouped by owner"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, _: &Host) -> Option<String> {
        None
    }

    fn run(&self, ctx: &Ctx, _: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let Some(text) = PATHS
            .iter()
            .find_map(|p| std::fs::read_to_string(ctx.host.path(p)).ok())
        else {
            return Err(Unavailable("tracefs is not mounted or not readable".into()).into());
        };
        // BPF trampolines are explained when every loaded tracing program
        // is (bpf-prog-unknown reports the ones that are not).
        let live = ctx.host.root() == std::path::Path::new("/");
        let bpf_explained = live && super::bpf_progs::unexplained(ctx.host).is_ok_and(|(u, _)| u.is_empty());
        // Kprobes systemd's own BPF programs attach (nsresourced's).
        let kprobes = if live {
            super::bpf_progs::explained_kprobes(ctx.host)
        } else {
            Vec::new()
        };
        Ok(parse(&text)
            .into_iter()
            .filter(|(o, _)| !(o == "bpf" && bpf_explained))
            .filter_map(|(o, (sev, funcs))| {
                let funcs: Vec<String> = if o == "kprobe" {
                    funcs.into_iter().filter(|f| !kprobes.contains(&f.as_str())).collect()
                } else {
                    funcs
                };
                (!funcs.is_empty()).then_some((o, (sev, funcs)))
            })
            .map(|(o, (sev, mut funcs))| {
                funcs.sort();
                let salient = fingerprint(&funcs.iter().map(String::as_str).collect::<Vec<_>>());
                let shown: Vec<&str> = funcs.iter().take(8).map(String::as_str).collect();
                Finding::new(self.id(), sev, &o, &salient)
                    .message(format!(
                        "{} kernel function(s) hooked by {o}: {}{}",
                        funcs.len(),
                        shown.join(", "),
                        if funcs.len() > shown.len() { ", …" } else { "" }
                    ))
                    .detail(serde_json::json!({ "functions": funcs }))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_by_owner() {
        let s = "__x64_sys_getdents64 (1) R   \ttramp: 0xffffffffc0001000 (fh_ftrace_thunk [rk]) ->ftrace_ops_assist_func+0x0/0xf0\n\
security_file_open (1) R  D   \ttramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20)\n\tdirect-->bpf_trampoline_6442+0x0/0x80\n\
do_sys_openat2 (1) R I    \ttramp: 0xffffffffc0002000 (kprobe_ftrace_handler+0x0/0x1e0) ->kprobe_ftrace_handler+0x0/0x1e0\n";
        let m = parse(s);
        assert_eq!(m["module:rk"].0, Severity::High);
        assert_eq!(m["module:rk"].1, vec!["__x64_sys_getdents64"]);
        assert!(m.contains_key("kprobe"));
        assert_eq!(m["bpf"].1, vec!["security_file_open"]);
        // The trampoline continuation line names no function of its own.
        assert!(m.values().all(|(_, f)| !f.iter().any(|x| x.is_empty())));
    }
}
