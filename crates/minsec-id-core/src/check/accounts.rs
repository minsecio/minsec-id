//! `accounts`: local accounts and sudo rules.
//!
//! Always reported: a second uid-0 account (`account-uid0`), and accounts
//! with an empty password (`account-password-empty`). Against the
//! baseline: new login-capable accounts or changed uids (`account-new`), and
//! new `NOPASSWD` sudo rules (`sudo-nopasswd`).

use super::{Anchors, Check, Cost, Ctx};
use crate::finding::{Finding, Severity};
use crate::host::Host;
use crate::users;

pub struct Accounts;

/// `NOPASSWD` rules from sudoers and its drop-in directory, with line
/// continuations joined and whitespace normalized.
fn nopasswd_rules(host: &Host) -> Vec<(String, String)> {
    let mut files = vec!["/etc/sudoers".to_string()];
    // sudo skips drop-ins containing '.' or ending in '~'.
    files.extend(
        host.list_dir("/etc/sudoers.d")
            .into_iter()
            .filter(|n| !n.contains('.') && !n.ends_with('~'))
            .map(|n| format!("/etc/sudoers.d/{n}")),
    );
    let mut out = Vec::new();
    for f in files {
        let Some(s) = host.read_opt(&f) else { continue };
        let joined = s.replace("\\\n", " ");
        for l in joined.lines().map(str::trim) {
            if l.starts_with('#') && !l.starts_with("#include") || !l.contains("NOPASSWD") {
                continue;
            }
            out.push((f.clone(), l.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    out
}

impl Check for Accounts {
    fn id(&self) -> &'static str {
        "accounts"
    }

    fn description(&self) -> &'static str {
        "extra uid-0 accounts, empty passwords, new login accounts, new NOPASSWD sudo rules"
    }

    fn emits(&self) -> &'static [&'static str] {
        &["account-uid0", "account-password-empty", "account-new", "sudo-nopasswd"]
    }

    fn cost(&self) -> Cost {
        Cost::Quick
    }

    fn unavailable(&self, host: &Host) -> Option<String> {
        (!host.exists("/etc/passwd")).then(|| "no /etc/passwd".into())
    }

    fn run(&self, ctx: &Ctx, anchors: &mut Anchors) -> anyhow::Result<Vec<Finding>> {
        let host = ctx.host;
        let mut out = Vec::new();
        let accounts = users::passwd(host);
        for u in &accounts {
            if u.uid == 0 && u.name != "root" {
                out.push(
                    Finding::new("account-uid0", Severity::Critical, &u.name, "")
                        .message(format!("account {} has uid 0", u.name))
                        .detail(serde_json::json!({ "shell": u.shell, "home": u.home })),
                );
            }
            if u.passwd.is_empty() {
                out.push(
                    Finding::new("account-password-empty", Severity::High, &u.name, "passwd")
                        .message(format!("account {} has an empty password in /etc/passwd", u.name)),
                );
            }
            if u.can_login() {
                if let Some(old) = anchors.observe(&format!("user:{}", u.name), &u.uid.to_string()) {
                    out.push(
                        Finding::new("account-new", Severity::Medium, &u.name, &u.uid.to_string())
                            .message(match &old {
                                Some(o) => format!("account {} changed uid from {o} to {}", u.name, u.uid),
                                None => format!("login account {} (uid {}) was added", u.name, u.uid),
                            })
                            .detail(serde_json::json!({ "uid": u.uid, "shell": u.shell, "home": u.home, "baseline_uid": old })),
                    );
                }
            }
        }
        for (name, hash) in users::shadow(host) {
            let login = accounts.iter().any(|u| u.name == name && u.can_login());
            if hash.is_empty() && login {
                out.push(
                    Finding::new("account-password-empty", Severity::High, &name, "shadow")
                        .message(format!("account {name} can log in with an empty password")),
                );
            }
        }
        for (file, rule) in nopasswd_rules(host) {
            if anchors.observe(&format!("nopasswd:{rule}"), &file).is_some() {
                out.push(
                    Finding::new("sudo-nopasswd", Severity::High, &rule, "")
                        .message(format!("new passwordless sudo rule in {file}: {rule}"))
                        .detail(serde_json::json!({ "file": file })),
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nopasswd() {
        let root = std::env::temp_dir().join(format!("minsec-id-sudo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        std::fs::write(
            root.join("etc/sudoers"),
            "# NOPASSWD in a comment\n%wheel ALL=(ALL) ALL\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/sudoers.d/cloud"),
            "ec2-user  ALL=(ALL) \\\n NOPASSWD: ALL\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/sudoers.d/skip.bak"), "x ALL=(ALL) NOPASSWD: ALL\n").unwrap();
        let rules = nopasswd_rules(&Host::with_root(&root));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].1, "ec2-user ALL=(ALL) NOPASSWD: ALL");
        std::fs::remove_dir_all(root).unwrap();
    }
}
