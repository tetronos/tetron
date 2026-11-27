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
#   WIN-030..035 (named-pipe IPC) need WIN-010 (Caller), WIN-021 (trusted
#     owners) and WIN-025 (token helpers). Order: WIN-030 (generic framing,
#     pipe name), WIN-031 (client), WIN-032 (server + pipe ACL), WIN-033
#     (caller identity), WIN-034 (admission), WIN-035 (addon check, no code).
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


class WindowsProtectedConfigDir(Requirement):
    """REQUIREMENT-ID: WIN-021

    The config directory (and any subdirectory `ensure_dir` creates) is a
    protected tree: owner LocalSystem or `BUILTIN\\Administrators`, protected
    DACL (inherits nothing) granting full control to exactly `SYSTEM` and
    `Administrators`, both inheritable to children (`OICI`). Everything created
    inside (network configs, invites, blobs, logs) inherits that ACL, so no
    file under the tree is readable by a standard user. This is the Windows
    counterpart of `/etc/tetron` being `0750 root:tetron` with `0640`/`0600`
    files: there is no `tetron` group on Windows, so non-secret files are not
    opened to `Authenticated Users` either (reads go through IPC).

    - A missing directory is created with that security descriptor in the
      same `CreateDirectoryW` call (no window with an inherited ACL). Missing
      parent directories are created the same way, recursively, never with
      `create_dir_all`, and the log directory (created at tracing start-up,
      before any config access, and by the panic hook) goes through the same
      call (`config::create_private_dir`). Otherwise the first `create_dir_all`
      of `logs` would create the config root with `ProgramData`'s inherited
      ACL, and a standard user could plant files there before the protected
      DACL is applied; re-applying the DACL later does not change their owner.
    - An existing directory must already be owned by `SYSTEM` or
      `Administrators`. Any other owner is refused with an error naming the
      path and owner, and is never taken over: `%ProgramData%` lets standard
      users create subfolders, so a pre-created `tetron` folder is a squatter
      that may hold planted files (a known `secret_key`). The operator must
      remove it.
    - An existing, trusted-owned directory gets its protected DACL re-applied
      by handle when the process is privileged (the counterpart of the Unix
      `chmod 0750` on every `ensure_dir`), then read back and verified.
    - A reparse point (symlink, junction, mount point) at the path is refused;
      the security handle is opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
    - A non-privileged process (a standard-user CLI) does not attempt the
      repair: `ensure_dir` succeeds without changing anything, and the
      following read fails with access denied, as `/etc/tetron` does for a
      user outside the `tetron` group.
    - Pure policy (`owner_decision(existing_owner, current) -> Ok/Err`, the
      SDDL strings) is unit-tested on every platform; Windows-only tests create
      a directory, read back owner and DACL with `GetSecurityInfo`, and check a
      squatted (user-owned) directory is refused.

    Depends on WIN-020 and WIN-025.
    """
    req_id = "WIN-021"


class WindowsProtectedConfigWrite(Requirement):
    """REQUIREMENT-ID: WIN-022

    `config::write_file` works on Windows for secret and non-secret files and
    removes WIN-001's refusal.

    - The staging file is created with `CreateFileW(CREATE_NEW,
      FILE_FLAG_OPEN_REPARSE_POINT)` and the protected file security
      descriptor (`SYSTEM` + `Administrators` only, protected) passed at
      creation, so the bytes never exist under an inherited ACL. Its name
      carries a random 128-bit nonce, so an existing name is a hard error, not
      a file to reuse.
    - After writing, the staging file is flushed through its own write handle
      (WIN-023), its owner and DACL are read back and verified, then it is
      renamed over the destination.
    - An existing destination must be a regular file, not a reparse point, and
      owned by `SYSTEM` or `Administrators`; otherwise the write is refused and
      the staging file removed.
    - Secret and non-secret files get the same ACL on Windows (see WIN-021);
      the `secret` flag keeps its Unix meaning.
    - `restrict_perms` on Windows re-applies the protected file DACL by handle
      to an existing file (used for append-mode files).
    - The config storage and headless daemon tests that WIN-001's refusal
      failed on Windows (22) pass there; Windows-only tests read back the
      written file's owner and DACL.

    Depends on WIN-021.
    """
    req_id = "WIN-022"


class WindowsSyncThroughWriteHandle(Requirement):
    """REQUIREMENT-ID: WIN-023

    Every `sync_all`/`sync_data` on Windows goes through a handle opened for
    writing: `FlushFileBuffers` on a read-only handle returns
    `ERROR_ACCESS_DENIED`, and a no-op save that treats that error as a change
    republishes every few seconds. Audit result
    at the time of writing: the only call is the staging file's own write
    handle in `write_file`; no-op saves in `config::update_network` return
    before any file is opened. New sync calls keep to this rule.

    Depends on WIN-022.
    """
    req_id = "WIN-023"


class WindowsNoUnixOwnership(Requirement):
    """REQUIREMENT-ID: WIN-024

    Unix ownership and mode handling (`chown` to root, the `tetron` group,
    `0750`/`0640`/`0600`) does not run on Windows; the ACLs of WIN-021/022
    carry access instead. On Linux and macOS nothing changes.

    Depends on WIN-022.
    """
    req_id = "WIN-024"


class WindowsTrustedConfigRead(Requirement):
    """REQUIREMENT-ID: WIN-026

    On Windows every read of a file in the config tree that tetron trusts
    (`secret_key`, `collision_index`, `settings.toml`, `networks/*.toml`, the
    peer address cache) goes through `config::read_config_file`, which opens
    the file without following a reparse point, checks on that same handle
    that it is a regular file owned by `SYSTEM` or `Administrators`, and only
    then reads from the handle. A file with any other owner is an error, never
    loaded: a key or network config a standard user planted, by whatever gap
    in the tree's protection, must not become the node's identity or a trusted
    network. Defence in depth behind WIN-021.

    - Linux and macOS read as before (`std::fs::read`).
    - Windows-only test: a trusted file reads back; a user-owned file is
      refused.

    Depends on WIN-021.
    """
    req_id = "WIN-026"


class IpcGenericFraming(Requirement):
    """REQUIREMENT-ID: WIN-030

    `tetron-proto`'s `framed`, `send` and `recv` are generic over any
    `AsyncRead + AsyncWrite + Unpin` stream, so the daemon can frame a
    `NamedPipeServer` (a different type from the client's `NamedPipeClient`)
    with the same codec. `IpcFramed` stays the client alias
    (`Framed<IpcStream, MsgpackCodec<IpcMessage>>`), so `tetron-webui` and
    `tetron-systray` (which call `connect`/`send`/`recv`/`framed`) compile
    unchanged. The wire format (4-byte BE length + msgpack) is unchanged.

    - `socket_path()` on Windows is the pipe name `\\\\.\\pipe\\tetron`;
      `TETRON_SOCKET_PATH` (PORTABILITY-003) overrides it with another pipe
      name, on every platform as before.

    Depends on WIN-001.
    """
    req_id = "WIN-030"


class NamedPipeClient(Requirement):
    """REQUIREMENT-ID: WIN-031

    `tetron_proto::ipc::connect()` on Windows opens the pipe with exactly
    `GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES` (what WIN-032
    grants Authenticated Users), overlapped, at `SECURITY_IDENTIFICATION`
    quality of service (the daemon may identify the caller, never act as
    them).

    - `ERROR_PIPE_BUSY` (every instance taken) is retried every 50 ms for up
      to 5 s, then reported; a missing pipe reports that the daemon is not
      running.
    - Before anything is sent, the client reads the pipe object's owner
      (`GetSecurityInfo(SE_KERNEL_OBJECT)`, which needs only the
      `READ_CONTROL` its `GENERIC_READ` carries) and refuses the pipe unless
      the owner is `SYSTEM` or `Administrators`. Any process may create a
      pipe under a free name, so while the daemon is stopped a standard user
      could otherwise sit on `\\\\.\\pipe\\tetron` and collect requests
      (invite secrets in `Join`). A standard user's token can not stamp either
      owner. Reading the server process's token instead would fail for a
      standard user against a LocalSystem service.
    - The owner policy is the same pure `TrustedOwner::from_sid` the config
      tree uses (WIN-021), unit-tested everywhere.

    Depends on WIN-030 and WIN-021.
    """
    req_id = "WIN-031"

