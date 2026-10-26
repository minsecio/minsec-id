//! Compile the BPF programs in bpf/ with clang. There is no fallback and no
//! feature to turn this off: a build without clang fails here, with a
//! message saying so, rather than producing a daemon that cannot monitor.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    println!("cargo:rerun-if-env-changed=CLANG");
    for h in ["vmlinux.h", "helpers.h", "event.h"] {
        println!("cargo:rerun-if-changed=bpf/{h}");
    }
    for name in ["monitor", "iter"] {
        let src = format!("bpf/{name}.bpf.c");
        println!("cargo:rerun-if-changed={src}");
        let obj = out.join(format!("{name}.o"));
        let status = Command::new(&clang)
            .args(["-O2", "-g", "-Wall", "-Werror", "-target", "bpf", "-mcpu=v3", "-c", &src, "-o"])
            .arg(&obj)
            .status()
            .unwrap_or_else(|e| {
                panic!("cannot run `{clang}` ({e}): clang is required to build minsec-id's BPF programs (set CLANG to use another)")
            });
        assert!(status.success(), "{clang} failed to compile {src}");
    }
}
