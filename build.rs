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

    // WIN-085: embed wintun.dll into the Windows binary when the build names
    // one (the release packaging sets TETRON_WINTUN_DLL to the pinned,
    // hash-checked official DLL). Without it nothing is embedded.
    println!("cargo:rustc-check-cfg=cfg(tetron_embedded_wintun)");
    println!("cargo:rerun-if-env-changed=TETRON_WINTUN_DLL");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && let Some(dll) = std::env::var_os("TETRON_WINTUN_DLL")
    {
        let dll = std::path::PathBuf::from(dll);
        assert!(
            dll.is_absolute() && dll.is_file(),
            "TETRON_WINTUN_DLL must be an absolute path to wintun.dll, got {}",
            dll.display()
        );
        println!("cargo:rerun-if-changed={}", dll.display());
        println!("cargo:rustc-env=TETRON_WINTUN_DLL_PATH={}", dll.display());
        println!("cargo:rustc-cfg=tetron_embedded_wintun");
    }

    // Rebuild when HEAD moves so the stamp stays current. `.git/HEAD` covers
    // commits/checkouts; the packed-refs/refs paths cover branch updates.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");
}
