//! The tetron path `tetron install` writes into the service unit or launchd
//! plist (PACKAGING-018), and the NixOS check (PACKAGING-019).
//!
//! The running binary is the right path for a package or a copied binary.
//! For a Nix install it is not: the running file is
//! `/nix/store/<hash>-tetron-<ver>/bin/.tetron-wrapped`, the wrapper's inner
//! binary (without the wrapper's PATH to iproute2) at a versioned path that
//! garbage collection removes after an upgrade. A profile link that resolves
//! into the store (`~/.nix-profile/bin/tetron`) stays valid across upgrades.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The Nix store.
pub(crate) const NIX_STORE: &str = "/nix/store";

/// Present on every NixOS system.
pub(crate) const NIXOS_MARKER: &str = "/etc/NIXOS";

/// The inner binary a Nix wrapper (makeWrapper) runs.
const WRAPPED: &str = ".tetron-wrapped";

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// A profile link to tetron: absolute, outside `store`, executable, and
/// resolving into `store`.
fn profile_link(c: &Path, store: &Path) -> bool {
    c.is_absolute()
        && !c.starts_with(store)
        && is_executable(c)
        && std::fs::canonicalize(c).is_ok_and(|t| t.starts_with(store))
}

/// How the exec path was chosen, for the install message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExecSource {
    /// `$TETRON_EXE`.
    Env,
    /// argv[0], a profile link into the store.
    Argv0,
    /// A profile link found on PATH.
    Path,
    /// The running binary (or the wrapper next to it), not in a store.
    Running,
    /// The running binary is in the store and no profile link was found:
    /// the unit breaks after a Nix upgrade and garbage collection.
    StoreOnly,
}

/// The stable exec path (PACKAGING-018) from its inputs: `env` is
/// `$TETRON_EXE`, `argv0` the invoked name, `running` the running binary
/// (" (deleted)" already stripped), `path` the `PATH` value, `store` the
/// store directory.
pub(crate) fn stable_exec_path(
    env: Option<&OsStr>,
    argv0: Option<&OsStr>,
    running: &Path,
    path: Option<&OsStr>,
    store: &Path,
) -> (PathBuf, ExecSource) {
    if let Some(e) = env
        .map(PathBuf::from)
        .filter(|e| e.is_absolute() && is_executable(e))
    {
        return (e, ExecSource::Env);
    }
    let real = std::fs::canonicalize(running).unwrap_or_else(|_| running.to_path_buf());
    let from_store = real.starts_with(store);
    if from_store {
        if let Some(a) = argv0.map(PathBuf::from).filter(|a| profile_link(a, store)) {
            return (a, ExecSource::Argv0);
        }
        let on_path = path
            .into_iter()
            .flat_map(std::env::split_paths)
            .map(|d| d.join("tetron"))
            .find(|c| profile_link(c, store));
        if let Some(p) = on_path {
            return (p, ExecSource::Path);
        }
    }
    let unwrapped = match running.file_name() {
        Some(n) if n == WRAPPED => running
            .parent()
            .map(|d| d.join("tetron"))
            .filter(|w| is_executable(w))
            .unwrap_or_else(|| running.to_path_buf()),
        _ => running.to_path_buf(),
    };
    let source = if from_store {
        ExecSource::StoreOnly
    } else {
        ExecSource::Running
    };
    (unwrapped, source)
}

/// What `tetron install` or `tetron uninstall` (`verb`) says on NixOS, where
/// the service is part of the system configuration and /etc/systemd/system
/// is read-only (PACKAGING-019). None elsewhere.
pub(crate) fn nixos_message(on_nixos: bool, verb: &str) -> Option<String> {
    on_nixos.then(|| {
        format!(
            "On NixOS the tetron daemon is part of the system configuration: \
             services.tetron.enable = true; (module from github:tetronos/tetron-nixos), \
             then nixos-rebuild switch. tetron {verb} changes nothing here."
        )
    })
}

/// The warning `tetron install` prints when it writes a store path.
pub(crate) fn store_only_warning(exe: &Path) -> String {
    format!(
        "warning: the service runs {}, a Nix store path that a Nix upgrade and garbage \
         collection remove. Run `sudo $(command -v tetron) install` again after upgrading, \
         or set TETRON_EXE to a stable path.",
        exe.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tetron-exe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn exe(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A fake store with a wrapped tetron, a profile link to it, and an
    /// unrelated tetron elsewhere.
    struct Fixture {
        root: PathBuf,
        store: PathBuf,
        pkg: PathBuf,
        profile: PathBuf,
        other: PathBuf,
    }

    fn fixture(name: &str) -> Fixture {
        let root = tmp(name);
        let store = root.join("store");
        let pkg = store.join("abc-tetron-0.15.7/bin");
        exe(&pkg.join(".tetron-wrapped"));
        exe(&pkg.join("tetron"));
        let profile = root.join("profile/bin");
        std::fs::create_dir_all(&profile).unwrap();
        std::os::unix::fs::symlink(pkg.join("tetron"), profile.join("tetron")).unwrap();
        let other = root.join("other/bin");
        exe(&other.join("tetron"));
        Fixture {
            root,
            store,
            pkg,
            profile,
            other,
        }
    }

    #[test]
    fn nix_install_prefers_argv0_profile_link() {
        let f = fixture("argv0");
        let running = f.pkg.join(".tetron-wrapped");
        let link = f.profile.join("tetron");
        let (p, s) = stable_exec_path(None, Some(link.as_os_str()), &running, None, &f.store);
        assert_eq!((p, s), (link, ExecSource::Argv0));
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn nix_install_finds_profile_link_on_path_skipping_others() {
        let f = fixture("path");
        let running = f.pkg.join(".tetron-wrapped");
        let path =
            std::env::join_paths([f.other.clone(), f.pkg.clone(), f.profile.clone()]).unwrap();
        // argv[0] a bare name (PATH lookup by the shell): not a profile link.
        let (p, s) = stable_exec_path(
            None,
            Some(OsStr::new("tetron")),
            &running,
            Some(&path),
            &f.store,
        );
        assert_eq!((p, s), (f.profile.join("tetron"), ExecSource::Path));
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn env_wins_and_relative_env_is_ignored() {
        let f = fixture("env");
        let running = f.pkg.join(".tetron-wrapped");
        let e = f.other.join("tetron");
        let (p, s) = stable_exec_path(Some(e.as_os_str()), None, &running, None, &f.store);
        assert_eq!((p, s), (e, ExecSource::Env));
        let (_, s) = stable_exec_path(Some(OsStr::new("tetron")), None, &running, None, &f.store);
        assert_eq!(s, ExecSource::StoreOnly);
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn store_only_uses_the_wrapper_never_the_wrapped_binary() {
        let f = fixture("storeonly");
        let running = f.pkg.join(".tetron-wrapped");
        let path = std::env::join_paths([f.other.clone()]).unwrap();
        let (p, s) = stable_exec_path(None, None, &running, Some(&path), &f.store);
        assert_eq!((p, s), (f.pkg.join("tetron"), ExecSource::StoreOnly));
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn outside_a_store_is_the_running_binary_unchanged() {
        let f = fixture("plain");
        let running = f.other.join("tetron");
        let link = f.profile.join("tetron");
        let (p, s) = stable_exec_path(None, Some(link.as_os_str()), &running, None, &f.store);
        assert_eq!(
            (p, s),
            (running, ExecSource::Running),
            "argv[0] only matters for a store install"
        );
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn nixos_message_only_on_nixos() {
        assert_eq!(nixos_message(false, "install"), None);
        let m = nixos_message(true, "uninstall").unwrap();
        assert!(
            m.contains("services.tetron.enable = true;")
                && m.contains("tetron uninstall changes nothing")
        );
    }
}
