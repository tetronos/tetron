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

/// Copy `tetron.exe` and `wintun.dll` from beside the running executable into
/// the install directory, unless they already run from there. Returns the
/// executable the service must run.
fn install_files() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating tetron.exe")?;
    let src = exe.parent().context("tetron.exe has no directory")?;
    let dll = src.join("wintun.dll");
    anyhow::ensure!(
        dll.is_file(),
        "{} is missing; put the amd64 wintun.dll from wintun.net next to tetron.exe",
        dll.display()
    );
    let dir = install_dir();
    let target = dir.join("tetron.exe");
    if same_dir(src, &dir) {
        return Ok(target);
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::copy(&exe, &target).with_context(|| format!("copying to {}", target.display()))?;
    std::fs::copy(&dll, dir.join("wintun.dll"))
        .with_context(|| format!("copying wintun.dll to {}", dir.display()))?;
    println!("installed tetron.exe and wintun.dll in {}", dir.display());
    Ok(target)
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
