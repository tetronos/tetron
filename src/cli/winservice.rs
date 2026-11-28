//! The Windows service (WIN-050..056): the Service Control Manager entry point
//! for `tetron daemon --service`, and the install / start / stop / restart /
//! uninstall commands that drive service `tetron`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub(crate) const SERVICE_NAME: &str = "tetron";
const DISPLAY_NAME: &str = "tetron mesh VPN";
/// How long to wait for the service to reach a state before giving up.
const STATE_WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// WIN-050: running under the SCM
// ---------------------------------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

/// The status handle, so the control handler can report `StopPending`.
static STATUS: OnceLock<service_control_handler::ServiceStatusHandle> = OnceLock::new();

/// Hand this thread to the SCM dispatcher; returns when the service stopped.
/// Fails at once when the process was not started by the SCM.
pub(crate) fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("`tetron daemon --service` only runs as the tetron Windows service; use `tetron daemon` in a terminal")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "Windows service failed");
    }
}

fn status(state: ServiceState, exit: ServiceExitCode, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: exit,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let token = CancellationToken::new();
    let stop = token.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(h) = STATUS.get() {
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                    STATE_WAIT,
                ));
            }
            stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler)
        .context("registering the service control handler")?;
    let _ = STATUS.set(handle);
    // Every path after registration ends in a reported `Stopped`, so the SCM
    // never sees a service stuck starting; an error exit lets WIN-052 restart.
    let result = run_registered(handle, token);
    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "daemon exited with an error");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    handle.set_service_status(status(ServiceState::Stopped, exit, Duration::ZERO))?;
    Ok(())
}

/// Report `Running` and run the daemon until its token is cancelled.
fn run_registered(
    handle: service_control_handler::ServiceStatusHandle,
    token: CancellationToken,
) -> Result<()> {
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceExitCode::Win32(0),
        Duration::ZERO,
    ))?;
    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    let result = runtime.block_on(async {
        let stats = std::sync::Arc::new(tetron::stats::ForwardMetrics::default());
        stats.spawn_logger(token.clone());
        tetron::daemon::run_daemon(token, stats).await
    });
    runtime.shutdown_timeout(Duration::from_secs(10));
    result
}

// ---------------------------------------------------------------------------
// WIN-056: install location
// ---------------------------------------------------------------------------

/// `%ProgramFiles%\tetron`: only Administrators and SYSTEM may write there.
fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("tetron")
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `wintun.dll` embedded at build time (WIN-085), when the build named one.
#[cfg(tetron_embedded_wintun)]
const EMBEDDED_WINTUN: Option<&[u8]> = Some(include_bytes!(env!("TETRON_WINTUN_DLL_PATH")));
#[cfg(not(tetron_embedded_wintun))]
const EMBEDDED_WINTUN: Option<&[u8]> = None;

/// Where the installed `wintun.dll` comes from: the file beside the running
/// executable, or the copy embedded in it (WIN-085).
enum WintunSource {
    File(PathBuf),
    Embedded(&'static [u8]),
}

fn wintun_source(src_dir: &Path) -> Result<WintunSource> {
    let dll = src_dir.join("wintun.dll");
    if dll.is_file() {
        return Ok(WintunSource::File(dll));
    }
    EMBEDDED_WINTUN
        .map(WintunSource::Embedded)
        .with_context(|| {
            format!(
                "{} is missing; put the amd64 wintun.dll from wintun.net next to tetron.exe",
                dll.display()
            )
        })
}

fn place_wintun(source: &WintunSource, dest: &Path) -> Result<()> {
    match source {
        WintunSource::File(f) if same_dir(f, dest) => Ok(()),
        WintunSource::File(f) => std::fs::copy(f, dest).map(drop),
        WintunSource::Embedded(bytes) => std::fs::write(dest, bytes),
    }
    .with_context(|| format!("placing wintun.dll at {}", dest.display()))
}

/// Copy `tetron.exe` into the install directory and place `wintun.dll` beside
/// it (copied from beside the running executable, or written from the copy
/// embedded in it). Returns the executable the service must run.
fn install_files() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating tetron.exe")?;
    let src = exe.parent().context("tetron.exe has no directory")?;
    let wintun = wintun_source(src)?;
    let dir = install_dir();
    let target = dir.join("tetron.exe");
    let dll = dir.join("wintun.dll");
    if same_dir(src, &dir) {
        place_wintun(&wintun, &dll)?;
        return Ok(target);
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::copy(&exe, &target).with_context(|| format!("copying to {}", target.display()))?;
    place_wintun(&wintun, &dll)?;
    println!("installed tetron.exe and wintun.dll in {}", dir.display());
    Ok(target)
}

// ---------------------------------------------------------------------------
// WIN-086: the install directory on the machine PATH
// ---------------------------------------------------------------------------

const ENVIRONMENT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// An open registry key, closed on drop.
struct RegKey(windows_sys::Win32::System::Registry::HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: a key this guard opened and owns.
        unsafe { windows_sys::Win32::System::Registry::RegCloseKey(self.0) };
    }
}

fn open_environment_key() -> Result<RegKey> {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, RegOpenKeyExW,
    };
    let mut key = std::ptr::null_mut();
    // SAFETY: the subkey name is NUL-terminated; `key` is an out-pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(ENVIRONMENT_KEY).as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut key,
        )
    };
    anyhow::ensure!(
        status == 0,
        "opening the machine environment key failed (Win32 error {status})"
    );
    Ok(RegKey(key))
}

/// The machine `Path` value as stored (unexpanded) and its registry type.
fn read_machine_path(key: &RegKey) -> Result<(String, u32)> {
    use windows_sys::Win32::System::Registry::RegQueryValueExW;
    let name = wide("Path");
    let (mut kind, mut bytes) = (0u32, 0u32);
    // SAFETY: size query with a null buffer.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    anyhow::ensure!(
        status == 0,
        "reading the machine Path failed (Win32 error {status})"
    );
    let mut buf = vec![0u16; (bytes as usize).div_ceil(2)];
    // SAFETY: `buf` holds at least `bytes` writable bytes.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            buf.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    anyhow::ensure!(
        status == 0,
        "reading the machine Path failed (Win32 error {status})"
    );
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok((String::from_utf16_lossy(&buf[..end]), kind))
}

/// Write the machine `Path` back with the same registry type, then tell
/// running programs the environment changed (bounded wait).
fn write_machine_path(key: &RegKey, value: &str, kind: u32) -> Result<()> {
    use windows_sys::Win32::System::Registry::RegSetValueExW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    let data = wide(value);
    // SAFETY: `data` is NUL-terminated UTF-16; the length includes the NUL.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            wide("Path").as_ptr(),
            0,
            kind,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    anyhow::ensure!(
        status == 0,
        "writing the machine Path failed (Win32 error {status})"
    );
    let env = wide("Environment");
    let mut result = 0usize;
    // SAFETY: a broadcast with a NUL-terminated string parameter; the
    // timeout bounds the wait on programs that do not respond.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        )
    };
    Ok(())
}

/// Put the install directory on the machine PATH (WIN-086).
fn add_install_dir_to_path() -> Result<()> {
    let key = open_environment_key()?;
    let (current, kind) = read_machine_path(&key)?;
    let dir = install_dir();
    if let Some(updated) = super::service::path_list_with(&current, &dir.to_string_lossy()) {
        write_machine_path(&key, &updated, kind)?;
        println!(
            "added {} to the machine PATH (open a new terminal to use `tetron`)",
            dir.display()
        );
    }
    Ok(())
}

/// Take the install directory off the machine PATH (WIN-086).
fn remove_install_dir_from_path() -> Result<()> {
    let key = open_environment_key()?;
    let (current, kind) = read_machine_path(&key)?;
    if let Some(updated) =
        super::service::path_list_without(&current, &install_dir().to_string_lossy())
    {
        write_machine_path(&key, &updated, kind)?;
        println!("removed {} from the machine PATH", install_dir().display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WIN-085: double-click install
// ---------------------------------------------------------------------------

/// Started from Explorer: the console window belongs to this process alone.
/// A terminal (cmd, PowerShell, Windows Terminal) is another process on the
/// same console.
pub(crate) fn launched_by_double_click() -> bool {
    let mut pids = [0u32; 4];
    // SAFETY: `pids` is writable for the length passed.
    let n = unsafe {
        windows_sys::Win32::System::Console::GetConsoleProcessList(
            pids.as_mut_ptr(),
            pids.len() as u32,
        )
    };
    n == 1
}

fn wait_for_enter(prompt: &str) {
    println!("{prompt}");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// The double-click flow: explain, confirm, then run `install` elevated (one
/// UAC prompt) in its own window, which pauses before closing.
pub(crate) fn double_click_install() -> Result<()> {
    println!(
        "tetron {}\n\nThis installs tetron as a Windows service: it copies tetron.exe and\n\
         wintun.dll into {} and starts the service, which runs at\n\
         boot. Windows asks for administrator approval.\n",
        super::service::FULL_VERSION,
        install_dir().display()
    );
    print!("Install now? [Y/n] ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    if answer.trim().eq_ignore_ascii_case("n") {
        wait_for_enter("Not installed. Press Enter to close.");
        return Ok(());
    }
    let exe = std::env::current_exe().context("locating tetron.exe")?;
    match run_elevated(&exe, "install --pause") {
        Ok(0) => println!("Installed. Open a new terminal and run: tetron status"),
        Ok(code) => println!("The install window reported a failure (exit code {code})."),
        Err(e) => println!("Could not start the installer: {e:#}"),
    }
    wait_for_enter("Press Enter to close.");
    Ok(())
}

/// Run `exe args` with the `runas` verb (UAC prompt) and wait for it; returns
/// its exit code. Declining the prompt is an error.
fn run_elevated(exe: &Path, args: &str) -> Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let wide = |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(Some(0)).collect() };
    let verb = wide(OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let params = wide(OsStr::new(args));
    // SAFETY: a zeroed SHELLEXECUTEINFOW is valid; the string pointers below
    // outlive the call.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` is fully initialized for ShellExecuteExW.
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("administrator approval was declined or the installer did not start");
    }
    let mut code = 1u32;
    // SAFETY: `hProcess` is a process handle owned here, closed once below.
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    Ok(code)
}

// ---------------------------------------------------------------------------
// WIN-051/052: registration and lifecycle
// ---------------------------------------------------------------------------

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).context("opening the service manager")
}

/// The service with `access`, or `None` when it is not installed.
fn open(access: ServiceAccess) -> Result<Option<windows_service::service::Service>> {
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    match manager(ServiceManagerAccess::CONNECT)?.open_service(SERVICE_NAME, access) {
        Ok(s) => Ok(Some(s)),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            Ok(None)
        }
        Err(e) => Err(e).context("opening service tetron"),
    }
}

pub(crate) fn service_exists() -> bool {
    matches!(open(ServiceAccess::QUERY_STATUS), Ok(Some(_)))
}

fn info(exe: &Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        // Quoted by the crate whenever the path contains a space.
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![OsString::from("daemon"), OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    }
}

/// Restart on failure: 5 s, 10 s, then 30 s; counters reset after a day; also
/// when the service stops with an error exit code (WIN-052).
fn failure_actions() -> ServiceFailureActions {
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(10), restart(30)]),
    }
}

fn wait_for_state(service: &windows_service::service::Service, want: ServiceState) -> Result<()> {
    let deadline = std::time::Instant::now() + STATE_WAIT;
    loop {
        let state = service.query_status()?.current_state;
        if state == want {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("service tetron is {state:?}, not {want:?}, after {STATE_WAIT:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn stop_and_wait(service: &windows_service::service::Service) -> Result<()> {
    if service.query_status()?.current_state != ServiceState::Stopped {
        // Already stopping is fine; the wait below covers it.
        let _ = service.stop();
        wait_for_state(service, ServiceState::Stopped)?;
    }
    Ok(())
}

/// Install or refresh the service and start it (WIN-051, WIN-052, WIN-056).
/// The caller then waits for IPC and activates the VPN, as on Linux.
pub(crate) fn install_and_start() -> Result<()> {
    let existing = open(
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::STOP
            | ServiceAccess::START
            | ServiceAccess::CHANGE_CONFIG,
    )?;
    // The running service holds its executable open; stop it before copying.
    if let Some(s) = &existing {
        stop_and_wait(s)?;
    }
    let exe = install_files()?;
    if let Err(e) = add_install_dir_to_path() {
        eprintln!("warning: could not add tetron to the machine PATH: {e:#}");
    }
    let service = match existing {
        Some(s) => {
            s.change_config(&info(&exe))
                .context("updating service tetron")?;
            println!("updated Windows service 'tetron'");
            s
        }
        None => {
            let s = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?
                .create_service(
                    &info(&exe),
                    ServiceAccess::QUERY_STATUS
                        | ServiceAccess::START
                        | ServiceAccess::CHANGE_CONFIG,
                )
                .context("creating service tetron")?;
            println!("created Windows service 'tetron' (LocalSystem, automatic start)");
            s
        }
    };
    service.set_delayed_auto_start(true)?;
    service.update_failure_actions(failure_actions())?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service
        .start(&[] as &[&OsStr])
        .context("starting service tetron")?;
    Ok(())
}

pub(crate) fn start() -> Result<()> {
    let s = open(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?
        .context("tetron service is not installed. Run: tetron install")?;
    if s.query_status()?.current_state != ServiceState::Running {
        s.start(&[] as &[&OsStr])
            .context("starting service tetron")?;
    }
    Ok(())
}

pub(crate) fn stop() -> Result<()> {
    let s = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?
        .context("tetron service is not installed. Nothing to stop.")?;
    stop_and_wait(&s)
}

pub(crate) fn restart() -> Result<()> {
    let s = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START)?
        .context("tetron service is not installed. Run: tetron install")?;
    stop_and_wait(&s)?;
    s.start(&[] as &[&OsStr])
        .context("starting service tetron")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// WIN-055: uninstall
// ---------------------------------------------------------------------------

pub(crate) fn uninstall() -> Result<()> {
    // A missing service still gets the cleanup below: an earlier uninstall
    // run from the installed executable leaves that file behind.
    match open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)? {
        Some(s) => {
            stop_and_wait(&s)?;
            s.delete().context("deleting service tetron")?;
            drop(s);
            println!("Removed Windows service 'tetron'.");
        }
        None => println!("Service not installed."),
    }
    if let Err(e) = tetron::tun::remove_all_echo_rules() {
        eprintln!("warning: could not remove tetron firewall rules: {e:#}");
    }
    if let Err(e) = remove_install_dir_from_path() {
        eprintln!("warning: could not remove tetron from the machine PATH: {e:#}");
    }

    let dir = install_dir();
    let running = std::env::current_exe().ok();
    for name in ["tetron.exe", "wintun.dll"] {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        let is_running = running.as_deref().is_some_and(|r| same_dir(r, &path));
        if is_running {
            println!(
                "{} is the running program; delete it after this command exits.",
                path.display()
            );
        } else if let Err(e) = std::fs::remove_file(&path) {
            eprintln!("warning: could not remove {}: {e}", path.display());
        }
    }
    let _ = std::fs::remove_dir(&dir); // only succeeds once empty

    let config = tetron::config::config_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| r"%ProgramData%\tetron".to_string());
    println!(
        "Kept: the node identity, settings and logs in {config} (removing tetron never deletes \
         them; without the identity this node drops out of its networks). To delete them, from \
         an elevated terminal: Remove-Item -Recurse -Force '{config}'"
    );
    Ok(())
}

/// The last lines of the newest daemon log, for an install whose daemon never
/// answered (WIN-054).
pub(crate) fn print_log_tail() {
    let dir = tetron::logdir::log_dir();
    let newest = std::fs::read_dir(&dir).ok().and_then(|entries| {
        entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("tetron.log"))
            .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
    });
    let Some(entry) = newest else {
        eprintln!("\n(no daemon log in {})", dir.display());
        return;
    };
    match std::fs::read_to_string(entry.path()) {
        Ok(text) => {
            eprintln!("\nLast lines of {}:", entry.path().display());
            let lines: Vec<&str> = text.lines().rev().take(15).collect();
            for line in lines.into_iter().rev() {
                eprintln!("  {line}");
            }
        }
        Err(e) => eprintln!("\n(could not read {}: {e})", entry.path().display()),
    }
}
