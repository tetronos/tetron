//! Platform-neutral identity of an IPC caller (WIN-010), as vouched for by the
//! OS: `SO_PEERCRED` on Unix, the named-pipe client token on Windows.
//! Authorization (`MeshManager::check_authorized`) and the IPC admission
//! reserve (IPC-ADMISSION-002) decide on this, never on raw platform ids.

/// Who is on the other end of an IPC connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Caller {
    /// Peer credentials of a Unix socket connection.
    #[cfg_attr(not(unix), allow(dead_code))]
    Unix { uid: u32, gid: u32 },
    /// Token of a Windows named-pipe client. Built by the named-pipe server;
    /// exists on every platform so its rules are tested everywhere.
    #[cfg_attr(not(windows), allow(dead_code))]
    Windows {
        sid: String,
        is_local_system: bool,
        is_elevated_admin: bool,
    },
}

impl Caller {
    /// May do anything, including granting operator access: root on Unix,
    /// LocalSystem or an elevated Administrator on Windows.
    pub(crate) fn is_privileged(&self) -> bool {
        match self {
            Caller::Unix { uid, .. } => *uid == 0,
            Caller::Windows {
                is_local_system,
                is_elevated_admin,
                ..
            } => *is_local_system || *is_elevated_admin,
        }
    }

    /// Is the configured operator. Windows has no operator account yet.
    pub(crate) fn is_operator(&self, operator_uid: Option<u32>) -> bool {
        match self {
            Caller::Unix { uid, .. } => operator_uid == Some(*uid),
            Caller::Windows { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(is_local_system: bool, is_elevated_admin: bool) -> Caller {
        Caller::Windows {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
            is_local_system,
            is_elevated_admin,
        }
    }

    #[test]
    fn privileged_is_root_local_system_or_elevated_admin() {
        assert!(Caller::Unix { uid: 0, gid: 0 }.is_privileged());
        assert!(Caller::Unix { uid: 0, gid: 1000 }.is_privileged());
        assert!(!Caller::Unix { uid: 1000, gid: 0 }.is_privileged());
        assert!(win(true, false).is_privileged());
        assert!(win(false, true).is_privileged());
        assert!(!win(false, false).is_privileged());
    }

    #[test]
    fn operator_is_matching_unix_uid_only() {
        let user = Caller::Unix {
            uid: 1000,
            gid: 1000,
        };
        assert!(user.is_operator(Some(1000)));
        assert!(!user.is_operator(Some(1001)));
        assert!(!user.is_operator(None));
        // gid never matters.
        assert!(
            !Caller::Unix {
                uid: 1001,
                gid: 1000
            }
            .is_operator(Some(1000))
        );
        // No Windows operator account yet, whatever the configured UID.
        assert!(!win(false, false).is_operator(Some(0)));
        assert!(!win(false, false).is_operator(Some(1000)));
    }
}
