#![cfg(windows)]

//! Current-process token identity on Windows (WIN-025): who this process runs
//! as, and whether it holds the privileges the Unix build gets from uid 0.
//!
//! Also identifies a named-pipe client for the IPC server (WIN-033).

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation,
    LookupAccountNameW, LookupAccountSidW, PSID, RevertToSelf, SecurityIdentification,
    TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// String SID of the LocalSystem account, the identity of a Windows service.
pub use tetron_proto::ipc::LOCAL_SYSTEM_SID;

/// A token handle closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful Open/Duplicate call and is
        // owned by this guard alone.
        unsafe { CloseHandle(self.0) };
    }
}

fn process_token(access: u32) -> Option<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
    // `token` is a writable out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 || token.is_null()
    {
        return None;
    }
    Some(OwnedHandle(token))
}

/// Render a SID as its `S-1-...` string form.
pub(crate) fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut text = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID owned by the caller; `text` is an
    // out-pointer that receives a LocalAlloc'd string on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: on success `text` is NUL-terminated.
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: `len` u16s up to the terminator are initialized.
    let value = OsString::from_wide(unsafe { std::slice::from_raw_parts(text, len) })
        .to_string_lossy()
        .into_owned();
    // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe { LocalFree(text.cast()) };
    Some(value)
}

fn token_sid(token: HANDLE) -> Option<String> {
    let mut bytes = 0u32;
    // SAFETY: a size query with a null buffer; it fails by design and only
    // writes the required size into `bytes`.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes);
    }
    if bytes < std::mem::size_of::<TOKEN_USER>() as u32 {
        return None;
    }
    // u64 words keep the buffer aligned for TOKEN_USER.
    let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `bytes` writable bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with an initialized TOKEN_USER whose
    // SID points into the same buffer, which outlives this use.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(user.User.Sid)
}

/// Whether `token` (an impersonation-level token) has `BUILTIN\Administrators`
/// enabled. A filtered (non-elevated) token carries the group deny-only, which
/// `CheckTokenMembership` reports as not a member.
fn token_is_admin(token: HANDLE) -> bool {
    let mut size = 0u32;
    // SAFETY: size query with a null buffer.
    unsafe {
        let _ = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return false;
    }
    let mut sid = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `sid` holds at least `size` writable bytes.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return false;
    }
    let mut is_member = 0;
    // SAFETY: `token` is an open impersonation token, `sid` a valid SID.
    let ok = unsafe { CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut is_member) };
    ok != 0 && is_member != 0
}

/// String SID of the user this process runs as.
pub fn current_user_sid() -> Option<String> {
    process_token(TOKEN_QUERY).and_then(|token| token_sid(token.0))
}

/// Whether this process runs with an elevated Administrators token.
pub fn is_current_process_elevated_admin() -> bool {
    let Some(token) = process_token(TOKEN_DUPLICATE) else {
        return false;
    };
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: `token` is open with TOKEN_DUPLICATE; `duplicate` is an
    // out-pointer for the new handle.
    if unsafe { DuplicateToken(token.0, SecurityIdentification, &mut duplicate) } == 0
        || duplicate.is_null()
    {
        return false;
    }
    let duplicate = OwnedHandle(duplicate);
    token_is_admin(duplicate.0)
}

/// The Windows counterpart of `geteuid() == 0`: LocalSystem or an elevated
/// Administrator.
pub fn is_privileged_process() -> bool {
    current_user_sid().as_deref() == Some(LOCAL_SYSTEM_SID) || is_current_process_elevated_admin()
}

/// Who is on the other end of a named pipe (WIN-033).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeClientIdentity {
    pub sid: String,
    pub is_local_system: bool,
    pub is_elevated_admin: bool,
}

/// Reverts the thread's impersonation on drop, on every path.
struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: no preconditions; ends this thread's impersonation.
        unsafe { RevertToSelf() };
    }
}

/// Identify the client of a connected named-pipe server instance (WIN-033).
///
/// Impersonates the client, reads its thread token, and reverts before
/// returning, all in this synchronous call: nothing awaits while the thread
/// carries another identity. Call it after the client has written: Windows
/// identifies from the last message read, and before the first write it fails
/// intermittently (`ERROR_CANNOT_IMPERSONATE`).
pub fn named_pipe_client_identity(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<PipeClientIdentity> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: the handle of a live server instance, borrowed for this call.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        // SAFETY: reads this thread's last error.
        anyhow::bail!("cannot identify the pipe client (Win32 error {})", unsafe {
            GetLastError()
        });
    }
    let _revert = ImpersonationGuard;
    let mut token = std::ptr::null_mut();
    // SAFETY: open the impersonation token just placed on this thread, checked
    // against the process's own access (OpenAsSelf = 1).
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0
        || token.is_null()
    {
        // SAFETY: reads this thread's last error.
        anyhow::bail!(
            "cannot open the pipe client token (Win32 error {})",
            unsafe { GetLastError() }
        );
    }
    let token = OwnedHandle(token);
    let sid = token_sid(token.0).context("pipe client token has no user SID")?;
    Ok(PipeClientIdentity {
        is_local_system: sid == LOCAL_SYSTEM_SID,
        is_elevated_admin: token_is_admin(token.0),
        sid,
    })
}

/// `SID_NAME_USE` of a user account.
const SID_TYPE_USER: i32 = 1;

/// What a `SID_NAME_USE` value names, for error messages.
fn sid_type_name(kind: i32) -> &'static str {
    match kind {
        1 => "a user account",
        2 => "a group",
        3 => "a domain",
        4 => "a local group",
        5 => "a well-known group or principal",
        6 => "a deleted account",
        9 => "a computer account",
        10 => "an integrity label",
        11 => "a logon session",
        _ => "not an account",
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `DOMAIN\name` and the `SID_NAME_USE` of a SID, via `LookupAccountSidW`.
fn lookup_sid(sid: PSID) -> Result<(String, i32)> {
    let (mut name_len, mut domain_len, mut kind) = (0u32, 0u32, 0i32);
    // SAFETY: a size query with null buffers; it fails by design and writes
    // the required lengths.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    if name_len == 0 {
        // SAFETY: reads this thread's last error.
        let code = unsafe { GetLastError() };
        anyhow::bail!("no account has this SID (Win32 error {code})");
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: the buffers hold the lengths the size query reported.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        // SAFETY: reads this thread's last error.
        let code = unsafe { GetLastError() };
        anyhow::bail!("looking up the account failed (Win32 error {code})");
    }
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    let full = if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    };
    Ok((full, kind))
}

/// WIN-060: the `DOMAIN\name` of `sid` when it is a user account. A malformed
/// SID, an unknown one, or one naming a group or a well-known principal (such
/// as LocalSystem) is an error saying what it is.
pub fn user_account_for_sid(sid: &str) -> Result<String> {
    let text = wide(sid);
    let mut raw: PSID = std::ptr::null_mut();
    // SAFETY: `text` is NUL-terminated; `raw` receives a LocalAlloc'd SID.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 || raw.is_null() {
        anyhow::bail!("'{sid}' is not a valid SID (expected S-1-5-21-...)");
    }
    let looked_up = lookup_sid(raw);
    // SAFETY: allocated by ConvertStringSidToSidW with LocalAlloc.
    unsafe { LocalFree(raw.cast()) };
    let (account, kind) = looked_up.with_context(|| format!("SID {sid}"))?;
    if kind != SID_TYPE_USER {
        anyhow::bail!(
            "{account} ({sid}) is {}, not a user account; the operator must be one user",
            sid_type_name(kind)
        );
    }
    Ok(account)
}

/// WIN-062: resolve `account` (`user`, `DOMAIN\user`, `user@domain`, or a
/// SID string) to `(sid, DOMAIN\name)`, refusing anything that is not a
/// user account.
pub fn resolve_user_account(account: &str) -> Result<(String, String)> {
    if account.len() > 4 && account[..4].eq_ignore_ascii_case("S-1-") {
        let name = user_account_for_sid(account)?;
        return Ok((account.to_string(), name));
    }
    let text = wide(account);
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, 0i32);
    // SAFETY: a size query with null buffers; it fails by design and writes
    // the required lengths.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            text.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    if sid_len == 0 {
        // SAFETY: reads this thread's last error.
        let code = unsafe { GetLastError() };
        anyhow::bail!("no account named '{account}' (Win32 error {code})");
    }
    // u64 words keep the buffer aligned for a SID.
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: the buffers hold the sizes the size query reported.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            text.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        // SAFETY: reads this thread's last error.
        let code = unsafe { GetLastError() };
        anyhow::bail!("looking up '{account}' failed (Win32 error {code})");
    }
    let sid_text =
        sid_to_string(sid.as_mut_ptr().cast()).context("rendering the account SID failed")?;
    let (name, _) = lookup_sid(sid.as_mut_ptr().cast())?;
    if kind != SID_TYPE_USER {
        anyhow::bail!(
            "{name} ({sid_text}) is {}, not a user account; the operator must be one user",
            sid_type_name(kind)
        );
    }
    Ok((sid_text, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_is_a_windows_sid() {
        let sid = current_user_sid().expect("the process token has a user SID");
        assert!(sid.starts_with("S-1-"), "unexpected SID {sid}");
    }

    #[tokio::test]
    async fn pipe_client_identity_is_this_process_and_impersonation_ends() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let name = format!(r"\\.\pipe\tetron-test-ident-{}", std::process::id());
        let server = ServerOptions::new().create(&name).unwrap();
        let mut client = ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();
        client.write_all(b"x").await.unwrap();
        let mut server = server;
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).await.unwrap();
        let id = named_pipe_client_identity(&server).unwrap();
        assert_eq!(Some(id.sid.clone()), current_user_sid());
        assert_eq!(id.is_elevated_admin, is_current_process_elevated_admin());
        // The thread is itself again: it has no impersonation token.
        let mut token = std::ptr::null_mut();
        // SAFETY: a query on this thread; a failure is the expected outcome.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        assert_eq!(opened, 0, "the thread still impersonates after the call");
    }

    // WIN-060: the current user resolves; groups and well-known principals and
    // malformed SIDs are refused with what they are.
    #[test]
    fn user_account_for_sid_accepts_only_users() {
        let me = current_user_sid().unwrap();
        let account = user_account_for_sid(&me).unwrap();
        assert!(account.contains('\\'), "{account}");
        let lower = me.to_lowercase();
        assert_eq!(user_account_for_sid(&lower).unwrap(), account);
        for (sid, what) in [
            ("S-1-5-18", "well-known"),
            ("S-1-5-32-544", "group"),
            ("S-1-1-0", "well-known"),
        ] {
            let e = format!("{:#}", user_account_for_sid(sid).unwrap_err());
            assert!(
                e.contains(what) && e.contains("not a user account"),
                "{sid}: {e}"
            );
        }
        let e = format!("{:#}", user_account_for_sid("not-a-sid").unwrap_err());
        assert!(e.contains("not a valid SID"), "{e}");
        let e = format!(
            "{:#}",
            user_account_for_sid("S-1-5-21-1-2-3-999999").unwrap_err()
        );
        assert!(e.contains("no account"), "{e}");
    }

    // WIN-062: an account name, DOMAIN\name and a SID resolve to the same
    // user; a group or unknown name is refused.
    #[test]
    fn resolve_user_account_by_name_or_sid() {
        let me = current_user_sid().unwrap();
        let full = user_account_for_sid(&me).unwrap();
        let short = full.rsplit('\\').next().unwrap().to_string();
        for input in [full.as_str(), short.as_str(), me.as_str()] {
            let (sid, name) = resolve_user_account(input).unwrap();
            assert!(sid.eq_ignore_ascii_case(&me), "{input}: {sid}");
            assert_eq!(name, full, "{input}");
        }
        let e = format!("{:#}", resolve_user_account("Administrators").unwrap_err());
        assert!(e.contains("not a user account"), "{e}");
        let e = format!("{:#}", resolve_user_account("SYSTEM").unwrap_err());
        assert!(e.contains("not a user account"), "{e}");
        let e = format!(
            "{:#}",
            resolve_user_account("no-such-user-tetron").unwrap_err()
        );
        assert!(e.contains("no account named"), "{e}");
    }

    #[test]
    fn elevation_matches_the_mandatory_level() {
        // `whoami /groups` lists "High Mandatory Level" (or System) exactly for
        // an elevated token; a standard token is Medium.
        let out = std::process::Command::new("whoami")
            .arg("/groups")
            .output()
            .expect("whoami runs");
        let text = String::from_utf8_lossy(&out.stdout);
        let high = text.contains("S-1-16-12288") || text.contains("S-1-16-16384");
        assert_eq!(is_current_process_elevated_admin(), high);
    }
}
