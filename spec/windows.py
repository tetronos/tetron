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
#   WIN-040..049 (Wintun TUN) need WIN-001 and run under WIN-025's
#     privilege. Order: WIN-040 (adapter: create, identity, addresses,
#     MTU, metric, stale addresses = WIN-041/042/045/048 in the same
#     function), WIN-044 (standby), WIN-043 (interface enumeration),
#     WIN-047 (firewall), WIN-046/049 (verifications).
#   WIN-050..056 (Windows service) need WIN-025, WIN-032 (IPC, which the
#     installer waits on) and WIN-040. Order: WIN-050 (SCM entry), WIN-056
#     (install location), WIN-051/052 (install and lifecycle commands,
#     failure actions), WIN-053/054 (privilege and logs, mostly in place),
#     WIN-055 (uninstall).
#   WIN-080..083 (packaging) need WIN-056 (`tetron install` places the
#     files). Order: WIN-080/081 (release artifact), WIN-082 (install.ps1),
#     WIN-083 (version sites, a check).
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


class NamedPipeServer(Requirement):
    """REQUIREMENT-ID: WIN-032

    The daemon serves IPC on the named pipe with the Unix server's semantics:
    the same accept loop duties (shutdown, coordinator promotion,
    left-network events), the same per-request handling.

    - The first instance is created with `first_pipe_instance(true)`, so a
      name already taken (another daemon, or a squatter) is a start-up error
      instead of a shared pipe. `reject_remote_clients(true)` on every
      instance. The name stays held for the daemon's whole life, since once
      every instance is closed it is free and a standard user could create
      the first instance with their own descriptor: two instances listen at
      once, a connected one is handed off only while the other slot (or its
      fresh replacement) listens, and an instance whose connect fails (a
      client can force that by opening and closing at once) is dropped only
      after a replacement exists, otherwise disconnected and kept. The one
      remaining gap needs instance creation itself to fail twice in a row with
      no client connected, which a standard user can not cause.
    - Pipe security descriptor: owner stamped `SYSTEM` (service) or
      `Administrators` (elevated foreground daemon), so WIN-031's check has a
      value that does not move with local policy; protected DACL: `SYSTEM`
      and `Administrators` `GENERIC_ALL`; Authenticated Users
      `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES`
      (`0x0012018B`). That is the Windows spelling of the Unix socket's
      `0666`: reaching the daemon is not authority, every mutating request is
      authorized per caller (AUTHZ-001, WIN-010). It deliberately omits
      `GENERIC_WRITE`, whose `FILE_APPEND_DATA` bit is
      `FILE_CREATE_PIPE_INSTANCE` on a pipe: with it, any user could add
      their own server instance to `\\\\.\\pipe\\tetron`, which shares
      the first instance's descriptor and so passes WIN-031's owner check,
      and receive other users' requests.
    - A failed `connect` or instance creation pauses with the
      IPC-ADMISSION-003 backoff (a gated `select!` branch, never an inline
      sleep) and recreates the pending instance.
    - Tests (Windows): a client round-trips a request; a standard user can
      not create an instance of the daemon's pipe, and can not take the name
      by racing open/close against first-instance creation (both checked
      live on the test VM with a standard account).

    Depends on WIN-030, WIN-021 and WIN-025.
    """
    req_id = "WIN-032"


class NamedPipeCallerIdentity(Requirement):
    """REQUIREMENT-ID: WIN-033

    After the first request frame has been read, the handler identifies the
    client with `ImpersonateNamedPipeClient` + `OpenThreadToken`, builds
    `Caller::Windows { sid, is_local_system, is_elevated_admin }`
    (LocalSystem by SID compare, elevation by `CheckTokenMembership` on the
    client token), and reverts with `RevertToSelf` before returning, inside
    the same synchronous call: nothing awaits while the thread impersonates.
    Identifying before the client has written fails intermittently
    (`ERROR_CANNOT_IMPERSONATE`), hence after the read. If identification
    fails the caller is unknown (`None`), which is never privileged.

    Depends on WIN-032 and WIN-010.
    """
    req_id = "WIN-033"


class NamedPipeAdmission(Requirement):
    """REQUIREMENT-ID: WIN-034

    IPC-ADMISSION-001..003 apply unchanged in meaning on Windows: the
    first-request read and the reply write are bounded by
    `ipc.request-timeout`/`ipc.response-timeout`; concurrent handlers are
    capped by `IpcSlots`, with the reserve open to privileged callers
    (`Caller::is_privileged`, WIN-010); an over-cap client gets the
    pre-encoded "daemon busy" frame through one non-blocking `try_write` and
    the instance is dropped, with no task spawned.

    - The reserve decision needs the caller before any request is read. Only
      when the general pool is full, the daemon attempts
      `ImpersonateNamedPipeClient` right after connect; if that fails (the
      client has not written yet) the caller is treated as unknown and turned
      away busy. tetron's own client writes immediately after connecting, so
      an administrator retrying still gets in.

    Depends on WIN-032 and WIN-033.
    """
    req_id = "WIN-034"


class NamedPipeAddonCheck(Requirement):
    """REQUIREMENT-ID: WIN-035

    `tetron-webui` and `tetron-systray` depend on `tetron-proto`. WIN-030 is
    a type-level change (generic `framed`/`send`/`recv`), source-compatible
    for callers that use `connect`/`send`/`recv`/`framed`/`IpcFramed`. Both
    addon repos are checked (build against the branch) before merge, and
    `cargo update -p tetron-proto` is run there when this ships; nothing on
    the wire changes. No code in this repo.

    Depends on WIN-030.
    """
    req_id = "WIN-035"


class WintunAdapter(Requirement):
    """REQUIREMENT-ID: WIN-040

    `tun::create` on Windows creates (or reopens) one Wintun adapter per
    network through the `tun` crate.

    - Never sets `destination`: on Windows the `tun` crate turns an IPv4
      destination into a `0.0.0.0/0` route through the adapter, which would
      pull all of the host's IPv4 traffic into the mesh. The overlay subnet
      route comes from the address and netmask (on-link), nothing else.
    - Adapter name `tetron-<12 hex>` and adapter GUID are derived from the
      network's IPv6 /56 prefix (bytes 1..7 of the node's overlay IPv6, which
      `derive_ipv6` takes from `blake3(network key)`): stable per network, so
      a restart reuses the adapter and Windows reuses its network profile
      instead of accumulating "Network 2, 3, ...". Pure
      `adapter_identity(v6)`, unit-tested everywhere.
    - `wintun.dll` is loaded by absolute path from the directory of
      `tetron.exe`, never by bare name (a service's working directory is
      `System32`; a bare name is a DLL-planting risk). A missing DLL is an
      error naming the expected path.
    - The returned name is the adapter name, used by every later call.

    Depends on WIN-001 and WIN-025.
    """
    req_id = "WIN-040"


class WintunAddresses(Requirement):
    """REQUIREMENT-ID: WIN-041

    The adapter gets the node's overlay IPv4 address with the network's
    netmask, and its overlay IPv6 address with on-link prefix length
    `IPV6_NETWORK_PREFIX_LEN` (/56), both through IP Helper
    (`CreateUnicastIpAddressEntry` on the adapter LUID, DAD state preferred),
    never `netsh` or PowerShell. Windows derives the on-link /24 and /56
    routes from those prefix lengths, the IPV6-003 per-network route,
    so `route_peer_range` has nothing left to add on Windows and is a no-op
    there (deviation from a separate `CreateIpForwardEntry2` route, which
    would duplicate the on-link one).

    Depends on WIN-040.
    """
    req_id = "WIN-041"


class WintunMtu(Requirement):
    """REQUIREMENT-ID: WIN-042

    MTU 1280 (`TUN_MTU`) on the adapter's IPv4 and IPv6 subinterfaces, set
    through the `tun` crate's `mtu`, which sets both families. Checked live:
    both subinterfaces report 1280, and a 1280-byte ICMP echo and a bulk TCP
    transfer cross the mesh both ways.

    Depends on WIN-040.
    """
    req_id = "WIN-042"


class WindowsLocalInterfaces(Requirement):
    """REQUIREMENT-ID: WIN-043

    `local_ipv4_interfaces()` on Windows enumerates every IPv4 unicast
    address with its on-link prefix (`GetUnicastIpAddressTable`) and its
    interface alias, skipping loopback, the same set the Linux arm returns,
    so the SUBNET-012/SUBNET-COLLISION-002 guards work on Windows instead of
    silently passing. A failed enumeration returns empty (the documented
    fail-open), as on the other platforms.

    Depends on WIN-001.
    """
    req_id = "WIN-043"


class WindowsStandbyKeepsSession(Requirement):
    """REQUIREMENT-ID: WIN-044

    Standby does not disable the Wintun adapter: disabling it ends the Wintun
    session and the reader task with it, so resume would have no data plane.
    On Windows `set_link_up`/`set_link_down` are no-ops that succeed;
    forwarding is already gated per network by the network's `active` flag
    in both directions (PORTABILITY-005), which is what standby means.
    Linux and macOS are unchanged.

    Depends on WIN-040.
    """
    req_id = "WIN-044"


class WintunTeardownAndStale(Requirement):
    """REQUIREMENT-ID: WIN-045

    - Teardown (`tun::delete`, MULTISEG-003): the adapter is closed when the
      network's TUN tasks end and the device halves drop; closing an adapter
      this process created removes it. `delete` itself only removes the
      network's firewall rules (WIN-047) and succeeds.
    - A reused adapter (left by a crash, reopened by name) is cleaned: every
      unicast address on it other than the node's own two is deleted before
      the addresses are assigned, so an old subnet or address can not
      linger.

    Depends on WIN-040.
    """
    req_id = "WIN-045"


class WindowsSelfLoopback(Requirement):
    """REQUIREMENT-ID: WIN-046

    `route_self_loopback` needs nothing on Windows: Windows answers traffic
    to its own unicast addresses locally. Verified live: pinging the node's
    own overlay IPv4 and IPv6 answers.

    Depends on WIN-041.
    """
    req_id = "WIN-046"


class WintunFirewallEcho(Requirement):
    """REQUIREMENT-ID: WIN-047

    Wintun adapters land on the Public firewall profile, so inbound traffic
    on the overlay is blocked by default. tetron adds exactly two inbound
    allow rules per network, ICMPv4 echo request and ICMPv6 echo request,
    each scoped to the node's own overlay address of that network
    (`localip`), named `tetron <adapter> ICMPv4/ICMPv6 echo`, so `ping`
    across the mesh works. All other inbound stays under the user's own
    firewall policy; the adapter's profile is not changed. Rules are
    re-created idempotently (delete by name, then add) at adapter creation
    and deleted in `tun::delete`. `netsh` is run by its absolute path under
    `%SystemRoot%\\System32`, with a bounded wait; a failure is a warning,
    never fatal (the mesh still works, only inbound ping does not).

    Depends on WIN-040.
    """
    req_id = "WIN-047"


class WintunInterfaceMetric(Requirement):
    """REQUIREMENT-ID: WIN-048

    The adapter gets an explicit interface metric (both families) through the
    `tun` crate's `metric`, so an overlay prefix never competes on equal
    terms with a physical route. Only the overlay prefixes route through the
    adapter (WIN-040, WIN-041); checked live: no `0.0.0.0/0` or `::/0` route
    references a tetron adapter.

    Depends on WIN-040.
    """
    req_id = "WIN-048"


class WintunPathCandidates(Requirement):
    """REQUIREMENT-ID: WIN-049

    Check (no code unless it fails): a peer advertising its own Wintun
    overlay address as a direct-path candidate is the PATH-DIAG-007 case;
    PATH-BLEED-001's status-layer filter (`ipv6_in_network`/`ip_in_subnet`
    on the network's own ranges) is platform-neutral and must hide it in
    `tetron status` on Windows too. Verified live once two nodes are
    joined. Suppressing such a candidate at the transport layer on Windows
    is separate, open work (the Windows counterpart of
    SELFCAPTURE-ROUTE-001).

    Depends on WIN-040.
    """
    req_id = "WIN-049"


class WindowsServiceEntry(Requirement):
    """REQUIREMENT-ID: WIN-050

    `tetron daemon` keeps running in the foreground (Ctrl+C shuts it down).
    `tetron daemon --service` (hidden flag) runs under the Service Control
    Manager: the dispatcher thread registers a control handler, reports
    `Running`, runs the daemon on its own tokio runtime with a fresh shutdown
    token, maps SCM Stop and Shutdown to cancelling that token (reporting
    `StopPending` with a wait hint), and reports `Stopped` with exit code 0,
    or a service-specific exit code 1 when the daemon (or anything after
    the handler registered, such as starting the runtime) failed, so the
    failure actions (WIN-052) apply and the SCM never sees a service stuck
    starting. Started outside the SCM the flag is
    an error, not a foreground run. `--service` is refused off Windows.

    Depends on WIN-025.
    """
    req_id = "WIN-050"


class WindowsServiceRegistration(Requirement):
    """REQUIREMENT-ID: WIN-051

    `tetron install` (elevated) registers service `tetron`: own process,
    LocalSystem, automatic start with delayed start (the network stack is up
    first), command line `"<install dir>\\tetron.exe" daemon --service` with
    the executable path quoted (an unquoted path with spaces is a privilege
    escalation). An existing service is stopped and its configuration
    updated, as `install` refreshes on Linux. Then it starts the service,
    waits for the daemon to answer IPC, and sends `Resume`, as on Linux.

    - `tetron start` / `stop` / `restart` drive the same service and wait for
      the target state (stop) or for IPC (start, restart).
    - Each command opens the service manager and the service with only the
      access rights it needs (connect/create; start, stop, query, change
      configuration, delete as applicable).
    - `--config-dir`, `--log-dir` and `--socket-path` are refused on Windows
      with a message (a service environment block is not implemented).

    Depends on WIN-050 and WIN-056.
    """
    req_id = "WIN-051"


class WindowsServiceFailureActions(Requirement):
    """REQUIREMENT-ID: WIN-052

    The service restarts after a failure: restart after 5 s, then 10 s, then
    30 s for every later failure, counters reset after a day, and the actions
    also apply when the service stops with an error exit code (not only on a
    crash). This is the Windows half of the fail-fast model: the daemon's
    panic hook aborts and relies on the service manager to bring it back.

    Depends on WIN-051.
    """
    req_id = "WIN-052"


class WindowsServicePrivilege(Requirement):
    """REQUIREMENT-ID: WIN-053

    The service commands require an elevated Administrator (WIN-025's
    `require_root`/`check_root`), and their messages name an elevated
    terminal, not `sudo`: every "run this with administrator rights" hint
    goes through `admin_command(args)`, which yields `sudo tetron <args>` on
    Unix (text unchanged) and `tetron <args> (from an elevated terminal)` on
    Windows. Granting operator access to the invoking user after
    install (`$SUDO_USER` on Unix) does nothing on Windows: Windows has no
    operator account yet.

    Depends on WIN-025.
    """
    req_id = "WIN-053"


class WindowsServiceLogs(Requirement):
    """REQUIREMENT-ID: WIN-054

    Under the service the rolling file logs, the panic log and live log-level
    reload (LOG-004) work unchanged under `%ProgramData%\\tetron\\logs`.
    When the service never becomes reachable, the installer prints the tail
    of the newest log file there, as Linux prints the journal.

    Depends on WIN-050 and WIN-020.
    """
    req_id = "WIN-054"


class WindowsServiceUninstall(Requirement):
    """REQUIREMENT-ID: WIN-055

    `tetron uninstall` (elevated) stops and deletes the service (its Wintun
    adapters close with the daemon) and deletes every tetron ICMP echo
    firewall rule (WIN-047). `%ProgramData%\\tetron` (identity, networks,
    logs) is kept and its path printed, as on Linux and macOS. The installed
    program files are removed, except the running executable when uninstall
    runs from the install directory itself; its path is printed then. The
    rule and file cleanup also runs when the service is already gone, so a
    second uninstall from another copy removes what the first left.

    Depends on WIN-051.
    """
    req_id = "WIN-055"


class WindowsServiceInstallLocation(Requirement):
    """REQUIREMENT-ID: WIN-056

    The service never runs an executable a standard user can replace: it
    runs as LocalSystem, so an `.exe` (or the `wintun.dll` beside it) in a
    user-writable folder such as Downloads would be a privilege escalation.
    `tetron install` copies `tetron.exe` and `wintun.dll` into
    `%ProgramFiles%\\tetron`, whose inherited ACL lets only Administrators
    and SYSTEM write, and registers that copy. When `install` already runs
    from there, nothing is copied. A missing `wintun.dll` beside the running
    `tetron.exe` is an install error.

    Depends on WIN-040.
    """
    req_id = "WIN-056"


class WindowsReleaseArtifact(Requirement):
    """REQUIREMENT-ID: WIN-080

    `release.yml` and `nightly.yml` build `x86_64-pc-windows-msvc` on a
    Windows runner (`cargo build --release --locked`, same features as the
    other release builds) and publish `tetron-x86_64-windows.zip` holding
    `tetron.exe`, `wintun.dll` (amd64), `LICENSE`, and Wintun's own license,
    plus `tetron-x86_64-windows.zip.sha256`.

    - The job runs only when the repository variable `WINDOWS_RELEASE` is
      `true`, so turning Windows releases on is a deliberate act, not a side
      effect of the next tag.
    - The zip's `tetron.exe` answers `--version` on the runner before
      upload.

    Depends on WIN-001 and WIN-081.
    """
    req_id = "WIN-080"


class WintunRedistribution(Requirement):
    """REQUIREMENT-ID: WIN-081

    `wintun.dll` is the prebuilt, signed DLL from the official Wintun
    distribution, redistributed unmodified under its own license, never built
    from source. The release job downloads one pinned version and fails
    unless the archive's SHA-256 equals the pinned value; it ships Wintun's
    license file from the same archive beside the DLL.

    Depends on nothing.
    """
    req_id = "WIN-081"


class WindowsInstallScript(Requirement):
    """REQUIREMENT-ID: WIN-082

    `contrib/install-tetron.ps1`, served by Pages as `install.ps1` beside
    `install.sh`, installs tetron on Windows from an elevated PowerShell:
    it downloads the release zip and its `.sha256` (latest release, or a
    `-Version` tag), refuses to continue unless the hashes match, extracts to
    a fresh temporary folder, runs `tetron.exe install` from there (which
    copies into `%ProgramFiles%\\tetron` and starts the service, WIN-051 and
    WIN-056), adds `%ProgramFiles%\\tetron` to the machine `PATH` if absent,
    and removes the temporary folder. It refuses to run unelevated. It is a
    public trust artifact: every step is commented for a reader deciding
    whether to run it, and the comments describe only what the script does.

    Depends on WIN-080 and WIN-056.
    """
    req_id = "WIN-082"


class WindowsVersionSites(Requirement):
    """REQUIREMENT-ID: WIN-083

    Windows packaging adds no version site: the zip carries the version only
    through the tag and the binary itself, so `contrib/bump-version.sh` and
    CON-REL01 are unchanged.

    Depends on WIN-080.
    """
    req_id = "WIN-083"


class WindowsSelfInstallingExe(Requirement):
    """REQUIREMENT-ID: WIN-085

    The Windows release asset `tetron-x86_64-windows.exe` installs itself:
    one file, no separate `wintun.dll`.

    - `build.rs` embeds `wintun.dll` into the Windows binary when the build
      environment names it (`TETRON_WINTUN_DLL`, an absolute path); the
      release packaging sets it to the pinned, hash-checked official DLL
      (WIN-081). Without the variable nothing is embedded and behaviour is
      unchanged (the DLL must sit beside `tetron.exe`).
    - `tetron install` writes the embedded DLL, unmodified, beside the
      installed `tetron.exe` in `%ProgramFiles%\\tetron` when no `wintun.dll`
      sits beside the running executable (WIN-056 otherwise copies that one).
    - Double-click from Explorer: started with no arguments in a console that
      belongs to tetron alone (`GetConsoleProcessList` returns 1), tetron
      explains that it will install the `tetron` Windows service, asks for
      confirmation, and runs `install` elevated through one UAC prompt
      (relaunching itself with the `runas` verb when not already elevated),
      then waits for Enter so the window does not close on its own. Started
      from a terminal, nothing changes (no arguments prints the usual help).
      The executable is not marked as requiring administrator rights, which
      would raise UAC for every command.
    - Releases publish the `.exe` (and its `.sha256`) beside the zip, and
      `install.ps1` downloads the `.exe` instead of the zip. Wintun's license
      text is still published with the release (WIN-081).

    Depends on WIN-056, WIN-080, WIN-081, WIN-082.
    """
    req_id = "WIN-085"


class WindowsInstallOnPath(Requirement):
    """REQUIREMENT-ID: WIN-086

    `tetron install` puts `%ProgramFiles%\\tetron` on the machine `PATH`, so
    `tetron` works in any new terminal after any install path (double-click,
    terminal, `install.ps1`); `tetron uninstall` removes that entry.

    - The value is edited in the registry
      (`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`,
      `Path`) as raw text: its type (normally `REG_EXPAND_SZ`) and every
      unexpanded entry such as `%SystemRoot%\\system32` are kept exactly.
      .NET's `[Environment]::SetEnvironmentVariable(..., "Machine")` is not
      used: it reads the value expanded and writes it back as `REG_SZ`, which
      silently turns every `%...%` entry into a fixed path (seen on a real
      Windows 10 machine).
    - The entry is added only when absent (case-insensitive, trailing
      backslash ignored) and removed exactly, other entries untouched; pure
      list helpers are unit-tested everywhere.
    - Running programs are told the environment changed
      (`WM_SETTINGCHANGE` "Environment", bounded wait), so new terminals
      opened from Explorer see it; terminals already open keep their PATH.
    - `install.ps1` no longer edits PATH itself.
    - Failure to update PATH is a warning, never a failed install.

    Depends on WIN-056, WIN-085.
    """
    req_id = "WIN-086"
