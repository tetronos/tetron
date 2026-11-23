//! Shared wire protocol for tetron.
//!
//! Both the `tetron` daemon/CLI and GUI frontends speak the same [`ipc::IpcMessage`]
//! enum over a length-prefixed msgpack Unix socket. This crate is the single source
//! of truth for that protocol so frontends never hand-mirror it.

pub mod firewall;
pub mod invite;
pub mod ipc;
mod types;

pub use firewall::{Action, Direction, Protocol};
pub use types::{GroupMode, TransportMode};

/// PROTO-EPOCH-001: the wire protocol generation this build speaks. Before 1.0
/// it is `MAJOR.MINOR` of this crate: every 0.x minor may change the wire
/// format, no patch may. Two peers with the same epoch understand each other.
pub const PROTOCOL_EPOCH: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

#[cfg(test)]
mod tests {
    #[test]
    fn protocol_epoch_is_major_minor_of_the_crate_version() {
        let v = env!("CARGO_PKG_VERSION");
        let want: Vec<&str> = v.split('.').take(2).collect();
        assert_eq!(super::PROTOCOL_EPOCH, want.join("."));
        assert_eq!(super::PROTOCOL_EPOCH, "0.15");
    }
}
