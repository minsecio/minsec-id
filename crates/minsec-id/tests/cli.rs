use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// A temporary config dir whose state lives inside it, with the journal off.
fn temp_config() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("minsec-id-cli-{}-{unique}-{sequence}", std::process::id()));
    std::fs::create_dir_all(dir.join("conf.d")).unwrap();
    std::fs::write(
        dir.join("minsec-id.toml"),
        format!(
            "[output]\njournal = false\n[paths]\nstate_dir = \"{}\"\n",
            dir.join("state").display()
        ),
    )
    .unwrap();
    dir
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn run(config: &Path, root: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_minsec-id"))
        .args(["--config-dir", config.to_str().unwrap(), "--root"])
        .arg(fixture(root))
        .args(args)
        .output()
        .unwrap()
}

fn json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn subjects(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["subject"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn clean_host_exits_zero() {
    let dir = temp_config();
    let o = run(&dir, "clean", &["--json", "scan"]);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    let r = json(&o);
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["ok"], true);
    assert_eq!(r["checks"][0]["id"], "kernel-tainted");
    assert_eq!(r["checks"][0]["status"], "ok");
    assert!(r["findings"].as_array().unwrap().is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tainted_host_reports_once_then_accepts_and_resolves() {
    let dir = temp_config();

    // First scan: P, O, E are open and new; E names the modules.
    let o = run(&dir, "tainted", &["--json", "scan"]);
    assert_eq!(o.status.code(), Some(2));
    let r = json(&o);
    assert_eq!(subjects(&r), vec!["E", "O", "P"]); // most severe first
    assert_eq!(r["new"], 3);
    let e = &r["findings"][0];
    assert_eq!(e["severity"], "high");
    assert_eq!(e["detail"]["modules"], serde_json::json!(["acme_rk", "nvidia"]));

    // Second scan: still open, nothing new, nothing re-logged.
    let r = json(&run(&dir, "tainted", &["--json", "scan"]));
    assert_eq!(r["new"], 0);
    assert_eq!(r["findings"].as_array().unwrap().len(), 3);
    let events = String::from_utf8(run(&dir, "tainted", &["events"]).stdout).unwrap();
    assert_eq!(events.matches("\"kind\":\"finding\"").count(), 3, "{events}");

    // Accept P by key; it leaves the open list but stays in `findings --all`.
    let o = run(&dir, "tainted", &["accept", "kernel-tainted:P", "--reason", "nvidia"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = json(&run(&dir, "tainted", &["--json", "scan"]));
    assert_eq!(subjects(&r), vec!["E", "O"]);
    assert_eq!(r["accepted"], 1);
    let all = json(&run(&dir, "tainted", &["--json", "findings", "--all"]));
    assert_eq!(all.as_array().unwrap().len(), 3);

    // Removing the accept rule reports P again.
    assert!(run(&dir, "tainted", &["unaccept", "kernel-tainted:P"]).status.success());
    let r = json(&run(&dir, "tainted", &["--json", "scan"]));
    assert_eq!(r["new"], 1);

    // The same state against a clean kernel resolves everything.
    let o = run(&dir, "clean", &["--json", "scan"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["resolved"], 3);
    let status = json(&run(&dir, "clean", &["--json", "status"]));
    assert_eq!(status["open"], 0);
    assert_eq!(status["last_scan"]["mode"], "quick");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn severity_override_and_disable() {
    let dir = temp_config();
    std::fs::write(
        dir.join("conf.d/sev.toml"),
        "[checks.kernel-tainted]\nseverity = \"critical\"\n",
    )
    .unwrap();
    let r = json(&run(&dir, "tainted", &["--json", "scan"]));
    assert!(r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["severity"] == "critical"));

    assert!(run(&dir, "tainted", &["disable", "kernel-tainted"]).status.success());
    let o = run(&dir, "tainted", &["--json", "scan"]);
    let r = json(&o);
    assert!(r["checks"].as_array().unwrap().is_empty());
    // Disabling a check drops its open findings.
    assert_eq!(o.status.code(), Some(0));
    assert!(r["findings"].as_array().unwrap().is_empty());
    // --check runs a disabled check explicitly.
    let r = json(&run(&dir, "tainted", &["--json", "scan", "--check", "kernel-tainted"]));
    assert_eq!(r["checks"].as_array().unwrap().len(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn inspect_and_check() {
    let dir = temp_config();
    let o = run(&dir, "tainted", &["--json", "inspect"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let i = json(&o);
    assert_eq!(i["schema_version"], 1);
    assert_eq!(i["os"]["id"], "almalinux");
    assert_eq!(i["kernel"]["supported"], true);
    assert_eq!(i["checks"][0]["available"], true);

    assert!(run(&dir, "clean", &["check"]).status.success());
    std::fs::write(dir.join("conf.d/bad.toml"), "[checks.no-such-check]\nenabled = true\n").unwrap();
    let o = run(&dir, "clean", &["--json", "check"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["ok"], false);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unknown_names_are_errors() {
    let dir = temp_config();
    assert_eq!(run(&dir, "clean", &["scan", "--check", "nope"]).status.code(), Some(1));
    assert_eq!(run(&dir, "clean", &["accept", "nope:x"]).status.code(), Some(1));
    assert_eq!(run(&dir, "clean", &["enable", "nope"]).status.code(), Some(1));
    std::fs::remove_dir_all(dir).unwrap();
}
