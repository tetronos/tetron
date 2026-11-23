//! PROTO-WIRE-002: write msgpack frames (named-map encoding, as the daemon and
//! clients do) of representative IpcMessage values, built with the
//! tetron-proto of a release tag, into the directory given as argv[1].
//! Fixed keys and values so the output is byte-stable for a given tag.

use std::net::Ipv4Addr;
use std::path::Path;

use tetron_proto::ipc::{IpcMessage, NetworkRole, NetworkStatus, PeerStatus};
use tetron_proto::{GroupMode, TransportMode};

fn id(seed: u8) -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

fn messages() -> Vec<(&'static str, IpcMessage)> {
    let peer = PeerStatus {
        endpoint_id: id(2),
        ip: Ipv4Addr::new(10, 88, 0, 2),
        ipv6: None,
        hostname: Some("b".into()),
        connection: None,
        is_coordinator: false,
        last_seen: Some(1_795_000_000),
    };
    let net = NetworkStatus {
        network: "spike".into(),
        role: NetworkRole::Coordinator,
        my_ip: Ipv4Addr::new(10, 88, 0, 1),
        my_ipv6: None,
        my_hostname: Some("a".into()),
        network_key: Some("key".into()),
        member_count: 1,
        peers: vec![peer],
        tun_name: "tetron0".into(),
        nuke_proposals: vec![],
        active: true,
        subnet: "10.88.0.0/24".into(),
        nuke_consensus_threshold: 2,
    };
    vec![
        ("status", IpcMessage::Status),
        ("shutdown", IpcMessage::Shutdown),
        (
            "create",
            IpcMessage::Create {
                mode: GroupMode::Restricted,
                network_name: Some("spike".into()),
                hostname: Some("a".into()),
                transport: Some(TransportMode::Default),
                subnet: None,
                nuke_consensus: None,
                force: false,
            },
        ),
        (
            "join",
            IpcMessage::Join {
                network_key: "key".into(),
                alias: None,
                hostname: Some("b".into()),
                transport: None,
                invite: Some(vec![1, 2, 3]),
                force: false,
            },
        ),
        (
            "resume",
            IpcMessage::Resume {
                hostname: None,
                network: Some("spike".into()),
            },
        ),
        ("standby", IpcMessage::Standby { network: None }),
        (
            "invite_create",
            IpcMessage::InviteCreate {
                network: "spike".into(),
                expires: Some("24h".into()),
            },
        ),
        (
            "invite_created",
            IpcMessage::InviteCreated {
                invite_key: "inv".into(),
                invite_id: "abcd".into(),
                expires_at: Some(1_795_086_400),
            },
        ),
        (
            "ok",
            IpcMessage::Ok {
                message: "done".into(),
            },
        ),
        (
            "error",
            IpcMessage::Error {
                message: "nope".into(),
            },
        ),
        (
            "joined",
            IpcMessage::Joined {
                network: "spike".into(),
                my_ip: Ipv4Addr::new(10, 88, 0, 2),
                my_ipv6: None,
                warning: None,
            },
        ),
        (
            "status_response",
            IpcMessage::StatusResponse {
                endpoint_id: id(1),
                active: true,
                daemon_version: std::env::var("FIXTURE_VERSION").unwrap_or_default(),
                networks: vec![net],
                packets_rx: 1,
                packets_tx: 2,
                bytes_rx: 3,
                bytes_tx: 4,
                drops: Default::default(),
                fragmented_ipv4: 0,
                fragmented_ipv6: 0,
            },
        ),
    ]
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: proto-fixtures OUT_DIR");
    std::fs::create_dir_all(&dir).expect("create OUT_DIR");
    for (name, msg) in messages() {
        let bytes = rmp_serde::to_vec_named(&msg).expect("encode");
        std::fs::write(Path::new(&dir).join(format!("{name}.msgpack")), bytes).expect("write");
    }
}
