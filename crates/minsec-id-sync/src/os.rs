//! The distribution release from os-release: `ID` and `VERSION_ID`, the
//! only things about the host a findings report names.

use minsec_proto::types::OsInfo;

pub fn release() -> OsInfo {
    ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| parse(&s))
        .unwrap_or_else(|| parse(""))
}

pub fn parse(s: &str) -> OsInfo {
    let field = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
            .unwrap_or_default()
    };
    // Only plain identifiers: anything else would be free text.
    let id = field("ID");
    let id_ok = (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    let version = field("VERSION_ID");
    let version_ok = version.len() <= 32
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b));
    OsInfo {
        id: if id_ok { id } else { "unknown".into() },
        version_id: if version_ok { version } else { String::new() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_sanitizes() {
        let o = parse("NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\nID_LIKE=\"rhel\"\n");
        assert_eq!((o.id.as_str(), o.version_id.as_str()), ("fedora", "44"));
        let o = parse("ID=\"ubuntu\"\nVERSION_ID=\"24.04\"\n");
        assert_eq!((o.id.as_str(), o.version_id.as_str()), ("ubuntu", "24.04"));
        let o = parse("ID=debian\n");
        assert_eq!((o.id.as_str(), o.version_id.as_str()), ("debian", ""));
        let o = parse("ID=\"My Distro\"\nVERSION_ID=\"1 beta\"\n");
        assert_eq!((o.id.as_str(), o.version_id.as_str()), ("unknown", ""));
        assert_eq!(parse("").id, "unknown");
    }
}
