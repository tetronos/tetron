from libspec import Requirement

# ==========================================================================
# Windows port (WIN-*)
#
# Target: Windows 10 and later, x86_64 only. Windows 7/8 are out of scope:
# Rust's tier-1 `*-pc-windows-*` targets require Windows 10, and the
# `*-win7-windows-*` targets are tier 3 (nightly + build-std, no CI).
#
# The port lands in phases. This module starts with the compile gate
# (WIN-001..003): the workspace builds for Windows, every Windows arm that is
# not implemented yet fails with an explicit error, and no Linux/macOS code
# path changes. Later phases (caller identity, config ACLs, named-pipe IPC,
# Wintun TUN, Windows service, packaging) add their own WIN-0x0 blocks.
#
# DEPENDENCY ORDERING (commit in this order):
#   WIN-001 first: nothing else in this module builds for Windows without it.
#   WIN-002 and WIN-003 each need WIN-001 (a Windows binary must link before
#     its stack reserve or console setup can matter). 002 and 003 are
#     independent of each other.
# ==========================================================================


class WindowsCompileGate(Requirement):
    """REQUIREMENT-ID: WIN-001

    The whole workspace (`tetron`, `tetron-proto`, every target: lib, bin,
    tests, benches) type-checks and builds for `x86_64-pc-windows-msvc` and
    `x86_64-pc-windows-gnu`, with clippy clean under the same flags the Linux
    gate uses.

    - Every Unix-only item is gated with `#[cfg(unix)]` (or a narrower
      `target_os` gate), never deleted or rewritten: on Linux and macOS the
      compiled code is unchanged.
    - Where a Windows arm is not implemented yet, it returns an error whose
      message says the operation is not yet supported on Windows. It never
      panics, never silently succeeds, and never falls through to a Unix path.
      A daemon started on Windows exits with that error instead of running
      half-configured.
    - `tetron-proto`'s IPC stream type is `UnixStream` on Unix (unchanged, so
      `tetron-webui`/`tetron-systray` see no type change) and a named-pipe
      client on Windows, where `connect()` returns the not-yet-supported
      error until the named-pipe transport lands.
    - `hostname` has a real Windows arm (`GetComputerNameExW` with
      `ComputerNamePhysicalDnsHostname`), since it is used for display only
      and is cheap to do correctly now.
    - The privilege check behind `require_root`/`check_root` has a Windows arm
      that reports "requires an elevated (Administrator) terminal" until the
      token-elevation check lands; it does not read `geteuid`.
    - `reconcile.py` does not gain a Windows cross-check (mingw is not a
      reasonable gate dependency); CI's Windows job is the Windows gate.

    No dependency on other WIN requirements.
    """
    req_id = "WIN-001"


class WindowsMainThreadStack(Requirement):
    """REQUIREMENT-ID: WIN-002

    The `tetron` binary links with an 8 MiB main-thread stack reserve on
    Windows only, emitted from `build.rs` as a per-binary link argument
    (`/STACK:8388608` for the msvc linker, `-Wl,--stack,8388608` for mingw).
    Windows' 1 MiB default overflows on the clap command tree in debug builds
    before argument parsing (`STATUS_STACK_OVERFLOW`, `0xC00000FD`); Linux and
    macOS default to 8 MiB already.

    - Not emitted for non-Windows targets; the Linux and macOS link lines are
      unchanged.
    - A Windows-only integration test reads `SizeOfStackReserve` from the PE
      optional header of the built `tetron.exe` and asserts it is at least
      8 MiB.

    Depends on WIN-001. Independent of WIN-003.
    """
    req_id = "WIN-002"


class WindowsConsoleAnsi(Requirement):
    """REQUIREMENT-ID: WIN-003

    The console tracing layer emits ANSI escape sequences, and Windows
    consoles show them as raw text unless virtual-terminal processing is
    enabled for the process. On Windows, `main` calls
    `enable_ansi_support::enable_ansi_support()` (already a declared
    Windows-only dependency) before tracing is initialised; if that fails
    (redirected output, a console without VT support), the console layer is
    built with ANSI off. clap's own colored help already handles the Windows
    console through `anstream` and is not affected.

    - No change on Linux/macOS: the call and the fallback are `#[cfg(windows)]`.
    - The fallback decision is a pure function (`console_ansi(is_windows:
      bool, vt_ok: bool) -> bool`) unit-tested on every platform.

    Depends on WIN-001. Independent of WIN-002.
    """
    req_id = "WIN-003"
