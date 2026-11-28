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

    /// Is the configured operator: the operator UID on Unix, the operator
    /// account's SID on Windows (WIN-060).
    pub(crate) fn is_operator(&self, operator: &Operator) -> bool {
        match self {
            Caller::Unix { uid, .. } => operator.uid == Some(*uid),
            Caller::Windows { sid, .. } => operator
                .sid
                .as_deref()
                .is_some_and(|op| op.eq_ignore_ascii_case(sid)),
        }
    }
}

/// The configured operator account (AUTHZ-001, WIN-060): a UID on Unix, a
/// user SID on Windows. Each platform's caller is compared with its own field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Operator {
    pub(crate) uid: Option<u32>,
    pub(crate) sid: Option<String>,
}

impl Operator {
    /// The operator from the daemon's settings; none if they can not be read.
    pub(crate) fn load() -> Operator {
        crate::config::load()
            .map(|c| Operator {
                uid: c.operator_uid,
                sid: c.operator_sid,
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn uid(uid: u32) -> Operator {
        Operator {
            uid: Some(uid),
            sid: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn sid(sid: &str) -> Operator {
        Operator {
            uid: None,
            sid: Some(sid.to_string()),
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
        assert!(user.is_operator(&Operator::uid(1000)));
        assert!(!user.is_operator(&Operator::uid(1001)));
        assert!(!user.is_operator(&Operator::default()));
        // gid never matters.
        assert!(
            !Caller::Unix {
                uid: 1001,
                gid: 1000
            }
            .is_operator(&Operator::uid(1000))
        );
        // A configured SID never makes a Unix caller the operator.
        assert!(!user.is_operator(&Operator::sid("S-1-5-21-1-2-3-1001")));
    }

    // WIN-060: a Windows caller is the operator when its token user SID is the
    // configured operator SID, compared case-insensitively.
    #[test]
    fn windows_operator_is_matching_sid_only() {
        let user = win(false, false);
        assert!(user.is_operator(&Operator::sid("S-1-5-21-1-2-3-1001")));
        assert!(user.is_operator(&Operator::sid("s-1-5-21-1-2-3-1001")));
        assert!(!user.is_operator(&Operator::sid("S-1-5-21-1-2-3-1002")));
        assert!(!user.is_operator(&Operator::default()));
        // A configured UID never makes a Windows caller the operator.
        assert!(!user.is_operator(&Operator::uid(0)));
        assert!(!user.is_operator(&Operator::uid(1000)));
    }
}
