//! Local accounts from `/etc/passwd` and `/etc/shadow`.

use crate::host::Host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    /// The passwd file's password field (`x` when the hash is in shadow).
    pub passwd: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

impl User {
    /// Whether the shell admits interactive logins.
    pub fn can_login(&self) -> bool {
        !(self.shell.is_empty()
            || self.shell.ends_with("/nologin")
            || self.shell.ends_with("/false")
            || self.shell.ends_with("/sync")
            || self.shell.ends_with("/shutdown")
            || self.shell.ends_with("/halt"))
    }
}

pub fn passwd(host: &Host) -> Vec<User> {
    let s = std::fs::read_to_string(host.path("/etc/passwd")).unwrap_or_default();
    s.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('+') && !l.starts_with('-'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(User {
                name: f[0].into(),
                passwd: f[1].into(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].into(),
                shell: f[6].into(),
            })
        })
        .collect()
}

/// (user, password hash field) from `/etc/shadow`; empty if unreadable.
pub fn shadow(host: &Host) -> Vec<(String, String)> {
    let s = std::fs::read_to_string(host.path("/etc/shadow")).unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            Some((f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect()
}

/// Accounts whose home directories hold per-user persistence and keys:
/// root and every account that can log in.
pub fn with_homes(host: &Host) -> Vec<User> {
    passwd(host)
        .into_iter()
        .filter(|u| (u.uid == 0 || u.can_login()) && u.home.starts_with('/') && u.home != "/")
        .filter(|u| host.exists(&u.home))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_shells() {
        let u = |shell: &str| User {
            name: "x".into(),
            passwd: "x".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/x".into(),
            shell: shell.into(),
        };
        assert!(u("/bin/bash").can_login());
        assert!(!u("/usr/sbin/nologin").can_login());
        assert!(!u("/bin/false").can_login());
        assert!(!u("").can_login());
    }
}
