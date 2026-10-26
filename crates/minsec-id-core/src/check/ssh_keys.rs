//! `ssh-key-new`: SSH keys authorized for any account, by fingerprint,
//! against the baseline; and `AuthorizedKeysCommand`, which hands key
//! decisions to a program, appearing or changing.

use super::{Anchors, Check, Cost, Ctx};
use crate::digest::{self, Algo};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::users;
use base64::Engine;

pub struct SshKeys;

const DEFAULT_FILES: &[&str] = &[".ssh/authorized_keys", ".ssh/authorized_keys2"];

/// `AuthorizedKeysFile` and `AuthorizedKeysCommand` from sshd's config
/// (main file and drop-ins; first value wins, as in sshd).
fn sshd_settings(host: &Host) -> (Vec<String>, Option<String>) {
    let mut files = vec!["/etc/ssh/sshd_config".to_string()];
    files.extend(
        host.list_dir("/etc/ssh/sshd_config.d")
            .into_iter()
            .filter(|n| n.ends_with(".conf"))
            .map(|n| format!("/etc/ssh/sshd_config.d/{n}")),
    );
    // Drop-ins are included from the top of the main file on current distros.
    files.rotate_left(1);
    let (mut akf, mut akc) = (None, None);
    for f in files {
        let Some(s) = host.read_opt(&f) else { continue };
        for l in s.lines().map(str::trim) {
            if l.starts_with('#') {
                continue;
            }
            let (k, v) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
            match k.to_ascii_lowercase().as_str() {
                "match" => break, // per-match settings are not modelled
                "authorizedkeysfile" if akf.is_none() => {
                    akf = Some(v.split_whitespace().map(String::from).collect::<Vec<_>>())
                }
                "authorizedkeyscommand" if akc.is_none() => akc = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    let akc = akc.filter(|c| !c.is_empty() && c != "none");
    (
        akf.unwrap_or_else(|| DEFAULT_FILES.iter().map(|s| s.to_string()).collect()),
        akc,
    )
}

/// Expand `%h`, `%u`, `%%`; relative paths are relative to the home.
fn expand(pattern: &str, u: &users::User) -> String {
    let p = pattern
        .replace("%%", "\0")
        .replace("%h", &u.home)
        .replace("%u", &u.name)
        .replace('\0', "%");
    if p.starts_with('/') {
        p
    } else {
        format!("{}/{p}", u.home.trim_end_matches('/'))
    }
}

/// (fingerprint `SHA256:…`, key type, comment) per key line.
pub(crate) fn keys(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim) {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // Options may precede the key; find the type token followed by base64.
        let toks: Vec<&str> = l.split_whitespace().collect();
        for (i, t) in toks.iter().enumerate() {
            let typed = t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-");
            let Some(b64) = toks.get(i + 1).filter(|_| typed) else {
                continue;
            };
            let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                continue;
            };
            let sha = digest::bytes(Algo::Sha256, &blob);
            let fp = format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha)
            );
            out.push((fp, t.to_string(), toks[i + 2..].join(" ")));
            break;
        }
    }
    out
}

impl Check for SshKeys {
    fn id(&self) -> &'static str {
        "ssh-key-new"
    }

    fn description(&self) -> &'static str {
        "SSH keys authorized for any account, and AuthorizedKeysCommand, against the baseline"
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/etc/passwd")).then(|| "no /etc/passwd".into())
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let (patterns, command) = sshd_settings(host);
        let mut out = Vec::new();
        if let Some(old) = anchors.observe("sshd:AuthorizedKeysCommand", command.as_deref().unwrap_or("")) {
            out.push(
                Finding::new(
                    self.id(),
                    Severity::High,
                    "AuthorizedKeysCommand",
                    command.as_deref().unwrap_or(""),
                )
                .message(format!(
                    "sshd AuthorizedKeysCommand is now {}",
                    command.as_deref().unwrap_or("unset")
                ))
                .detail(serde_json::json!({ "command": command, "baseline": old })),
            );
        }
        let mut seen = std::collections::HashSet::new();
        for u in users::passwd(host)
            .into_iter()
            .filter(|u| u.home.starts_with('/') && u.home != "/")
        {
            for pat in &patterns {
                let path = expand(pat, &u);
                if !seen.insert((u.name.clone(), path.clone())) {
                    continue;
                }
                let Some(text) = host.read_opt(&path) else { continue };
                for (fp, ty, comment) in keys(&text) {
                    let subject = format!("{}:{fp}", u.name);
                    if anchors.observe(&subject, &ty).is_some() {
                        out.push(
                            Finding::new(self.id(), Severity::High, &subject, "")
                                .message(format!("new SSH key for {}: {ty} {fp} {comment}", u.name))
                                .detail(serde_json::json!({ "file": path, "type": ty, "comment": comment })),
                        );
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_match_ssh_keygen() {
        let line =
            "command=\"x\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPs70L5+d7gOW/qivX21bhnl/o6qyNdUxrwM1kBN/DI me@host";
        let k = keys(line);
        assert_eq!(k.len(), 1);
        // As printed by `ssh-keygen -lf`.
        assert_eq!(k[0].0, "SHA256:deQTfFy07C1Q909kEIyhwZbrv8WYHzIocYaP3HRF2FA");
        assert_eq!(k[0].1, "ssh-ed25519");
        assert_eq!(k[0].2, "me@host");
    }

    #[test]
    fn expands_patterns() {
        let u = users::User {
            name: "bob".into(),
            passwd: "x".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/bob".into(),
            shell: "/bin/bash".into(),
        };
        assert_eq!(expand(".ssh/authorized_keys", &u), "/home/bob/.ssh/authorized_keys");
        assert_eq!(expand("/etc/ssh/keys/%u", &u), "/etc/ssh/keys/bob");
    }
}
