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
#   WIN-010 needs WIN-001 (the Windows variant must compile) and nothing else.
#     It changes no behavior; the named-pipe server (later) constructs the
#     Windows variant.
#   WIN-020..025 (config tree and protected files) need WIN-001. Commit order:
#     WIN-025 (token helpers + elevation check) first, since WIN-021 and
#     WIN-022 decide the trusted owner from the current token; then WIN-020
#     (location), WIN-021 (protected directory), WIN-022 (protected writes),
#     WIN-023 and WIN-024 (audits that pin down existing behavior).
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


class IpcCaller(Requirement):
    """REQUIREMENT-ID: WIN-010

    The daemon's IPC authorization works on a platform-neutral caller identity
    instead of a raw Unix `(uid, gid)`, so the Windows named-pipe server can
    plug into the same checks.

    - `enum Caller` (daemon module) with `Unix { uid, gid }` and
      `Windows { sid, is_local_system, is_elevated_admin }`. Both variants
      exist on every platform (plain data), so the Windows rules are
      unit-tested on Linux; only the code that builds a `Caller` from an OS
      handle is platform-gated.
    - `Caller::is_privileged()`: Unix uid 0; Windows LocalSystem or an
      elevated Administrator token.
    - `Caller::is_operator(operator_uid: Option<u32>)`: Unix uid equals the
      configured operator UID; always false for Windows until a Windows
      operator account exists (no `set-operator` on Windows yet).
    - Both are pure (the operator UID is passed in, not loaded).
    - `check_authorized(req, Option<&Caller>)` and `handle_request(req,
      Option<Caller>)` replace the `(uid, gid)` parameters. AUTHZ-001's rules
      are unchanged: reads open to everyone; privileged callers may do
      anything; `SetOperator` only for privileged callers; otherwise the
      caller must be the operator; an unknown caller (`None`) is never
      privileged and never the operator.
    - The IPC-ADMISSION-002 reserved-slot check uses the same two methods, so
      "who may use the reserve" can not drift from "who may mutate".
    - The Unix accept loop reads `SO_PEERCRED` once per connection, builds the
      `Caller`, and passes it to the handler (previously read twice).
    - Unix behavior is identical: the existing AUTHZ and admission tests pass
      unchanged in substance; a table-driven test covers every rule over both
      variants and `None`.

    Depends on WIN-001.
    """
    req_id = "WIN-010"


class WindowsTokenIdentity(Requirement):
    """REQUIREMENT-ID: WIN-025

    A Windows-only `windows_identity` module answers two questions about the
    current process token:
    `current_user_sid() -> Option<String>` (string SID of the token user) and
    `is_current_process_elevated_admin() -> bool` (the token is a member of
    `BUILTIN\\Administrators` with that group enabled, i.e. elevated, checked
    with `CheckTokenMembership` on an identification-level duplicate).

    - The privilege check behind `require_root`/`check_root` gets its real
      Windows arm: LocalSystem (`S-1-5-18`) or an elevated Administrator
      passes; anything else fails with "requires an elevated (Administrator)
      terminal". This replaces WIN-001's unconditional refusal.
    - Every Win32 handle and buffer is released on every path (owned-handle
      guards, `LocalFree`); a failed call is "not privileged", never a panic.
    - Windows-only tests: the SID is a non-empty `S-1-` string; the elevation
      answer matches `whoami /groups` reporting the High Mandatory Level.

    Depends on WIN-001.
    """
    req_id = "WIN-025"


class WindowsConfigLocation(Requirement):
    """REQUIREMENT-ID: WIN-020

    On Windows, `config::config_dir()` resolves to `%ProgramData%\\tetron`
    (from the `PROGRAMDATA` environment variable, fallback
    `C:\\ProgramData\\tetron`), machine-wide like `/etc/tetron`. The previous
    non-Linux fallback (`dirs::config_dir()`, the roaming profile) names
    `C:\\Windows\\System32\\config\\systemprofile` for a LocalSystem service and
    the user's own `%APPDATA%` for the CLI, so the two would never meet.

    - `logdir::log_dir()` on Windows is `%ProgramData%\\tetron\\logs`, inside the
      protected tree (WIN-021), so logs inherit its ACL.
    - `TETRON_CONFIG_DIR` and `TETRON_LOG_DIR` (PORTABILITY-003) still
      override first, and the override target gets the same protection.
    - Linux, macOS and Android paths are unchanged.

    Depends on WIN-001.
    """
    req_id = "WIN-020"

