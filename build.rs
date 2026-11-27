//! Build script: stamp the git short SHA into the binary so builds are
//! identifiable. `tetron version`/`--version` surfaces it.
//!
//! Falls back to `unknown` when git is unavailable (e.g. a source tarball build
//! outside a checkout), so the build never fails for lack of a `.git` dir.

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=TETRON_GIT_SHA={sha}");

    // WIN-002: Windows defaults the main thread to a 1 MiB stack, which the clap
    // command tree overflows in debug builds before argument parsing. Reserve
    // 8 MiB (the Linux/macOS default) for the tetron binary on Windows only.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let arg = if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            "/STACK:8388608"
        } else {
            "-Wl,--stack,8388608"
        };
        println!("cargo:rustc-link-arg-bin=tetron={arg}");
    }

    // Rebuild when HEAD moves so the stamp stays current. `.git/HEAD` covers
    // commits/checkouts; the packed-refs/refs paths cover branch updates.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");
}
