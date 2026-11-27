//! The protected config tree on Windows (WIN-021, WIN-022).
//!
//! Everything under `%ProgramData%\tetron` is owned by `SYSTEM` or
//! `Administrators` and carries a protected DACL that grants full control to
//! exactly those two principals: the Windows counterpart of `/etc/tetron`
//! being root-owned with `0750`/`0640`/`0600` modes.
//!
//! The policy (SDDL strings, which owners are trusted, what a correct
//! descriptor reads back as) is plain Rust compiled on every platform so its
//! tests run everywhere; the Win32 calls are Windows-only.

use std::path::Path;

use anyhow::Result;

/// File DACL: protected (inherits nothing), full control for `SYSTEM` and
/// `BUILTIN\Administrators`, nobody else.
const PROTECTED_FILE_DACL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
/// Directory DACL: the same two principals, inherited by every child object
/// and container (`OICI`), so files created inside start protected.
const PROTECTED_DIR_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The only principals trusted to own anything in the config tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedOwner {
    LocalSystem,
    Administrators,
}

impl TrustedOwner {
    /// The SDDL alias, for an `O:` owner field.
    fn alias(self) -> &'static str {
        match self {
            Self::LocalSystem => "SY",
            Self::Administrators => "BA",
        }
    }

    /// A trusted owner from its string SID; any other SID is untrusted.
    pub fn from_sid(sid: &str) -> Option<Self> {
        match sid {
            "S-1-5-18" => Some(Self::LocalSystem),
            "S-1-5-32-544" => Some(Self::Administrators),
            _ => None,
        }
    }
}

/// The full security descriptor, owner plus protected DACL, given to an object
/// at creation.
fn protected_sddl(owner: TrustedOwner, directory: bool) -> String {
    let dacl = if directory {
        PROTECTED_DIR_DACL
    } else {
        PROTECTED_FILE_DACL
    };
    format!("O:{}{dacl}", owner.alias())
}

/// An existing object in the config tree must already be owned by a trusted
/// principal. It is never taken over: `%ProgramData%` lets a standard user
/// create folders, so a `tetron` folder someone else owns may hold planted
/// files, such as a `secret_key` they know.
fn check_trusted_owner(path: &Path, owner_sid: &str) -> Result<TrustedOwner> {
    TrustedOwner::from_sid(owner_sid).ok_or_else(|| {
        anyhow::anyhow!(
            "{} is owned by {owner_sid}, not SYSTEM or Administrators; refusing to use it. \
             It may have been created by another user to plant files. Remove it from an \
             elevated terminal and start tetron again.",
            path.display()
        )
    })
}

/// Check a descriptor read back from an object (owner and DACL, rendered as
/// SDDL) is exactly the protected one: a trusted owner, a protected DACL, and
/// only the two trusted allow ACEs (inheritable for a directory).
fn verify_sddl(path: &Path, actual: &str, directory: bool) -> Result<()> {
    let p = path.display();
    anyhow::ensure!(
        actual.starts_with("O:SY") || actual.starts_with("O:BA"),
        "{p}: owner is not SYSTEM or Administrators: {actual}"
    );
    anyhow::ensure!(
        actual.contains("D:P"),
        "{p}: DACL is not protected: {actual}"
    );
    anyhow::ensure!(
        actual.matches('(').count() == 2 && actual.matches("(A;").count() == 2,
        "{p}: DACL has unexpected entries: {actual}"
    );
    anyhow::ensure!(
        actual.contains(";;;SY)") && actual.contains(";;;BA)"),
        "{p}: DACL lacks SYSTEM or Administrators: {actual}"
    );
    if directory {
        anyhow::ensure!(
            actual.matches("(A;OICI;").count() == 2,
            "{p}: directory entries are not inherited by children: {actual}"
        );
    }
    Ok(())
}

#[cfg(windows)]
pub use win::{ensure_protected_dir, protect_existing_file, write_protected_file};

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::Write;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use anyhow::Context;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
        LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
        WRITE_DAC,
    };

    use crate::windows_identity::{LOCAL_SYSTEM_SID, current_user_sid, sid_to_string};

    /// The owner this process stamps on objects it creates: LocalSystem for the
    /// service, Administrators for an elevated terminal, `None` otherwise.
    fn current_owner() -> Option<TrustedOwner> {
        if current_user_sid().as_deref() == Some(LOCAL_SYSTEM_SID) {
            Some(TrustedOwner::LocalSystem)
        } else if crate::windows_identity::is_current_process_elevated_admin() {
            Some(TrustedOwner::Administrators)
        } else {
            None
        }
    }

    /// A security descriptor built from SDDL, freed on drop.
    pub(super) struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl OwnedSecurityDescriptor {
        pub(super) fn from_sddl(sddl: &str) -> Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sd = std::ptr::null_mut();
            // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd
            // descriptor that this wrapper frees.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            anyhow::ensure!(
                ok != 0 && !sd.is_null(),
                "invalid security descriptor {sddl}"
            );
            Ok(Self(sd))
        }

        fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }

        fn dacl(&self) -> Result<*mut ACL> {
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl = std::ptr::null_mut();
            // SAFETY: `self.0` is a valid descriptor; the out-pointers are
            // writable. The DACL points into the descriptor, which outlives it.
            let ok = unsafe {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)
            };
            anyhow::ensure!(ok != 0 && present != 0, "security descriptor has no DACL");
            Ok(dacl)
        }
    }

    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_reparse_point(attributes: u32) -> bool {
        attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Open `path` itself (never a reparse target) for reading or changing its
    /// security descriptor.
    fn open_for_security(path: &Path, directory: bool, change: bool) -> Result<File> {
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        let access = READ_CONTROL | if change { WRITE_DAC } else { 0 };
        // SAFETY: `wide` is NUL-terminated; a null security-attributes pointer
        // and template handle are allowed for OPEN_EXISTING.
        let handle = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("opening {} to check its owner", path.display()));
        }
        // SAFETY: a valid handle that nothing else owns.
        let file = unsafe { File::from_raw_handle(handle) };
        let meta = file
            .metadata()
            .with_context(|| format!("inspecting {}", path.display()))?;
        anyhow::ensure!(
            !is_reparse_point(meta.file_attributes()),
            "refusing reparse point (link or junction) at {}",
            path.display()
        );
        anyhow::ensure!(
            meta.is_dir() == directory,
            "{} is not a {}",
            path.display(),
            if directory {
                "directory"
            } else {
                "regular file"
            }
        );
        Ok(file)
    }

    /// Owner SID and owner+DACL SDDL of an open object.
    fn read_security(file: &File, path: &Path) -> Result<(String, String)> {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut owner = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        // SAFETY: an open handle with READ_CONTROL; owner/DACL pointers point
        // into `sd`, which is freed below after their last use.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                info,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        anyhow::ensure!(
            status == 0 && !sd.is_null(),
            "reading the security of {} failed (Win32 error {status})",
            path.display()
        );
        let owner_sid = sid_to_string(owner);
        let mut text = std::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: `sd` is valid; `text` receives a LocalAlloc'd string.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, &mut text, &mut len)
        };
        let sddl = (ok != 0 && !text.is_null()).then(|| {
            // SAFETY: `len` includes the terminator; the rest is initialized.
            let chars = unsafe { std::slice::from_raw_parts(text, len.saturating_sub(1) as usize) };
            OsString::from_wide(chars).to_string_lossy().into_owned()
        });
        // SAFETY: both were LocalAlloc'd by the calls above.
        unsafe {
            if !text.is_null() {
                LocalFree(text.cast());
            }
            LocalFree(sd);
        }
        let owner_sid =
            owner_sid.with_context(|| format!("{} has no readable owner", path.display()))?;
        let sddl = sddl.with_context(|| format!("rendering the ACL of {}", path.display()))?;
        Ok((owner_sid, sddl))
    }

    /// Replace the DACL of an open object with the protected one, then read it
    /// back and verify it.
    fn apply_protected_dacl(file: &File, path: &Path, directory: bool) -> Result<()> {
        // The owner in this descriptor is not applied, only its DACL.
        let sd = OwnedSecurityDescriptor::from_sddl(&protected_sddl(
            TrustedOwner::LocalSystem,
            directory,
        ))?;
        // SAFETY: an open handle with WRITE_DAC; the DACL lives in `sd`.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sd.dacl()?,
                std::ptr::null(),
            )
        };
        anyhow::ensure!(
            status == 0,
            "protecting {} failed (Win32 error {status})",
            path.display()
        );
        let (_, sddl) = read_security(file, path)?;
        verify_sddl(path, &sddl, directory)
    }

    /// Make sure `dir` exists as a protected directory (WIN-021).
    ///
    /// Missing: created with the protected descriptor in the same call, which
    /// needs a privileged process. Existing: must be owned by `SYSTEM` or
    /// `Administrators` (never taken over), and gets its protected DACL
    /// re-applied when this process is privileged. A non-privileged process
    /// leaves an existing directory alone; its reads then fail with access
    /// denied, as a non-root reader of `/etc/tetron` does.
    pub fn ensure_protected_dir(dir: &Path) -> Result<()> {
        let owner = current_owner();
        match std::fs::symlink_metadata(dir) {
            Ok(meta) => anyhow::ensure!(
                !is_reparse_point(meta.file_attributes()),
                "refusing reparse point (link or junction) at {}",
                dir.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let owner = owner.with_context(|| {
                    format!(
                        "creating {} requires an elevated (Administrator) terminal",
                        dir.display()
                    )
                })?;
                if let Some(parent) = dir.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                let mut sd = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, true))?;
                let attrs = sd.attributes();
                // SAFETY: `wide` is NUL-terminated; `attrs` points at `sd`,
                // which outlives the call.
                let ok = unsafe { CreateDirectoryW(wide(dir).as_ptr(), &attrs) };
                // SAFETY: reads this thread's last error, no preconditions.
                if ok == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("creating {}", dir.display()));
                }
            }
            Err(e) => {
                return Err(e).with_context(|| format!("inspecting {}", dir.display()));
            }
        }
        if owner.is_none() {
            return Ok(());
        }
        let handle = open_for_security(dir, true, true)?;
        let (owner_sid, _) = read_security(&handle, dir)?;
        check_trusted_owner(dir, &owner_sid)?;
        apply_protected_dacl(&handle, dir, true)
    }

    /// Create a new file with the protected descriptor set at creation, never
    /// following a reparse point and never reusing an existing name.
    fn create_protected_new_file(path: &Path) -> Result<File> {
        let owner = current_owner().with_context(|| {
            format!(
                "writing {} requires an elevated (Administrator) terminal",
                path.display()
            )
        })?;
        let mut sd = OwnedSecurityDescriptor::from_sddl(&protected_sddl(owner, false))?;
        let attrs = sd.attributes();
        // SAFETY: `wide` is NUL-terminated; `attrs` points at `sd`, which
        // outlives the call.
        let handle = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("creating {}", path.display()));
        }
        // SAFETY: a valid handle that nothing else owns.
        let file = unsafe { File::from_raw_handle(handle) };
        let (_, sddl) = read_security(&file, path)?;
        verify_sddl(path, &sddl, false)?;
        Ok(file)
    }

    /// An existing file about to be replaced must be a regular file owned by a
    /// trusted principal.
    fn check_existing_destination(path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                anyhow::ensure!(
                    !is_reparse_point(meta.file_attributes()),
                    "refusing reparse point (link or junction) at {}",
                    path.display()
                );
                let handle = open_for_security(path, false, false)?;
                let (owner_sid, _) = read_security(&handle, path)?;
                check_trusted_owner(path, &owner_sid).map(drop)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("inspecting {}", path.display())),
        }
    }

    /// The Windows `write_file` (WIN-022): stage under a random name with the
    /// protected descriptor set at creation, flush through that write handle
    /// (WIN-023), check what is being replaced, then rename over it.
    pub fn write_protected_file(path: &Path, bytes: &[u8]) -> Result<()> {
        let dir = path.parent().context("config path has no parent")?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config");
        let tmp = dir.join(format!(
            ".{name}.tmp.{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        let result = (|| {
            let mut file = create_protected_new_file(&tmp)?;
            file.write_all(bytes)
                .with_context(|| format!("writing {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("flushing {}", tmp.display()))?;
            drop(file);
            check_existing_destination(path)?;
            std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Re-apply the protected file DACL to an existing file (append-mode files
    /// that never go through [`write_protected_file`]). Its owner must already
    /// be trusted.
    pub fn protect_existing_file(path: &Path) -> Result<()> {
        let handle = open_for_security(path, false, true)?;
        let (owner_sid, _) = read_security(&handle, path)?;
        check_trusted_owner(path, &owner_sid)?;
        apply_protected_dacl(&handle, path, false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Owner SID and SDDL of an existing path, opened without changing it.
        fn security_of(path: &Path, directory: bool) -> (String, String) {
            let handle = open_for_security(path, directory, false).unwrap();
            read_security(&handle, path).unwrap()
        }

        /// Give `path` the current user as owner, the way a standard user's
        /// pre-created folder looks.
        fn make_user_owned(path: &Path, directory: bool) {
            let sid = current_user_sid().unwrap();
            let sd = OwnedSecurityDescriptor::from_sddl(&format!("O:{sid}")).unwrap();
            let mut owner = std::ptr::null_mut();
            let mut defaulted = 0;
            // SAFETY: `sd` is valid; the owner pointer lives inside it.
            unsafe {
                windows_sys::Win32::Security::GetSecurityDescriptorOwner(
                    sd.0,
                    &mut owner,
                    &mut defaulted,
                )
            };
            let flags = FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                };
            // SAFETY: as in open_for_security, with WRITE_OWNER.
            let handle = unsafe {
                CreateFileW(
                    wide(path).as_ptr(),
                    windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    flags,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE);
            // SAFETY: a valid handle that nothing else owns.
            let file = unsafe { File::from_raw_handle(handle) };
            // SAFETY: an open handle with WRITE_OWNER; `owner` lives in `sd`.
            let status = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    owner,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(status, 0, "setting the test owner failed");
        }

        #[test]
        fn new_directory_and_file_are_protected() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("tetron");
            ensure_protected_dir(&dir).unwrap();
            let (_, sddl) = security_of(&dir, true);
            verify_sddl(&dir, &sddl, true).unwrap();

            let file = dir.join("secret_key");
            write_protected_file(&file, b"one").unwrap();
            write_protected_file(&file, b"two").unwrap();
            assert_eq!(std::fs::read(&file).unwrap(), b"two");
            let (_, sddl) = security_of(&file, false);
            verify_sddl(&file, &sddl, false).unwrap();
            // No staging file is left behind.
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        }

        #[test]
        fn existing_trusted_directory_gets_its_acl_repaired() {
            // tempdir's own ACL is inherited from the user profile.
            let tmp = tempfile::tempdir().unwrap();
            ensure_protected_dir(tmp.path()).unwrap();
            let (_, sddl) = security_of(tmp.path(), true);
            verify_sddl(tmp.path(), &sddl, true).unwrap();
        }

        #[test]
        fn squatted_directory_is_refused_and_left_alone() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("tetron");
            std::fs::create_dir(&dir).unwrap();
            make_user_owned(&dir, true);
            let before = security_of(&dir, true);
            let err = ensure_protected_dir(&dir).unwrap_err().to_string();
            assert!(err.contains("not SYSTEM or Administrators"), "{err}");
            assert_eq!(
                security_of(&dir, true),
                before,
                "a squatted folder must not be changed"
            );
        }

        #[test]
        fn untrusted_destination_file_is_not_replaced() {
            let tmp = tempfile::tempdir().unwrap();
            let file = tmp.path().join("secret_key");
            std::fs::write(&file, b"planted").unwrap();
            make_user_owned(&file, false);
            let err = write_protected_file(&file, b"ours")
                .unwrap_err()
                .to_string();
            assert!(err.contains("not SYSTEM or Administrators"), "{err}");
            assert_eq!(std::fs::read(&file).unwrap(), b"planted");
            assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
        }

        #[test]
        fn junction_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let target = tmp.path().join("elsewhere");
            std::fs::create_dir(&target).unwrap();
            let link = tmp.path().join("tetron");
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .output()
                .unwrap()
                .status;
            assert!(status.success(), "mklink /J failed");
            let err = ensure_protected_dir(&link).unwrap_err().to_string();
            assert!(err.contains("reparse point"), "{err}");
        }

        #[test]
        fn existing_file_acl_is_repaired_in_place() {
            let tmp = tempfile::tempdir().unwrap();
            let file = tmp.path().join("audit.log");
            std::fs::write(&file, b"line\n").unwrap();
            protect_existing_file(&file).unwrap();
            let (_, sddl) = security_of(&file, false);
            verify_sddl(&file, &sddl, false).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_name_only_the_trusted_principals() {
        for (owner, prefix) in [
            (TrustedOwner::LocalSystem, "O:SYD:P"),
            (TrustedOwner::Administrators, "O:BAD:P"),
        ] {
            for directory in [false, true] {
                let sddl = protected_sddl(owner, directory);
                assert!(sddl.starts_with(prefix), "{sddl}");
                assert_eq!(sddl.matches("(A;").count(), 2, "{sddl}");
                assert!(!sddl.contains(";;;BU)") && !sddl.contains(";;;AU)"));
                assert!(!sddl.contains(";;;WD)"));
                assert_eq!(sddl.contains("OICI"), directory, "{sddl}");
            }
        }
    }

    #[test]
    fn only_system_and_administrators_are_trusted_owners() {
        assert_eq!(
            TrustedOwner::from_sid("S-1-5-18"),
            Some(TrustedOwner::LocalSystem)
        );
        assert_eq!(
            TrustedOwner::from_sid("S-1-5-32-544"),
            Some(TrustedOwner::Administrators)
        );
        for sid in ["S-1-5-21-1-2-3-1001", "S-1-5-32-545", "S-1-1-0", ""] {
            assert_eq!(TrustedOwner::from_sid(sid), None, "{sid}");
        }
        let p = Path::new(r"C:\ProgramData\tetron");
        assert!(check_trusted_owner(p, "S-1-5-32-544").is_ok());
        let err = check_trusted_owner(p, "S-1-5-21-1-2-3-1001")
            .unwrap_err()
            .to_string();
        assert!(err.contains("S-1-5-21-1-2-3-1001") && err.contains("Remove it"));
    }

    #[test]
    fn verification_accepts_only_the_protected_descriptor() {
        let p = Path::new("x");
        verify_sddl(p, "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)", false).unwrap();
        verify_sddl(p, "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true).unwrap();
        for (bad, directory) in [
            // untrusted owner
            ("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)(A;;FA;;;BA)", false),
            // inherits from the parent
            ("O:SYD:AI(A;;FA;;;SY)(A;;FA;;;BA)", false),
            // a third entry, even an inherited one
            ("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;ID;FR;;;BU)", false),
            // a deny entry is still an extra entry
            ("O:SYD:P(D;;FA;;;BU)(A;;FA;;;SY)", false),
            // missing Administrators
            ("O:SYD:P(A;;FA;;;SY)(A;;FA;;;SY)", false),
            // directory entries that do not reach children
            ("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)", true),
        ] {
            assert!(verify_sddl(p, bad, directory).is_err(), "accepted {bad}");
        }
    }
}
