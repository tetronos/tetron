//! PROTO-WIRE-002: every msgpack frame written by a previous release
//! (tests/fixtures/<tag>/, made by contrib/proto-fixtures/gen.sh) must decode
//! with the current types. A removed or renamed field, a field added without
//! `#[serde(default)]`, or a renamed variant fails here.

use std::path::Path;

use tetron_proto::ipc::{self, IpcMessage};

#[test]
fn every_previous_release_fixture_decodes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut count = 0;
    for tag in std::fs::read_dir(&root).expect("tests/fixtures exists") {
        let tag = tag.unwrap().path();
        for file in std::fs::read_dir(&tag).unwrap() {
            let file = file.unwrap().path();
            let bytes = std::fs::read(&file).unwrap();
            if let Err(e) = rmp_serde::from_slice::<IpcMessage>(&bytes) {
                panic!("{} no longer decodes: {e}", file.display());
            }
            count += 1;
        }
    }
    assert!(
        count >= 12,
        "expected the v0.15.5 set at least, found {count} fixtures"
    );
}

#[test]
fn v0_15_5_status_response_is_same_epoch() {
    let bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/v0.15.5/status_response.msgpack"),
    )
    .unwrap();
    let IpcMessage::StatusResponse {
        protocol_epoch,
        daemon_version,
        networks,
        ..
    } = rmp_serde::from_slice(&bytes).unwrap()
    else {
        panic!("not a StatusResponse");
    };
    assert_eq!(protocol_epoch, "", "v0.15.5 predates the field");
    assert_eq!(daemon_version, "0.15.5");
    assert_eq!(networks[0].peers.len(), 1);
    assert_eq!(
        ipc::epoch_check(&protocol_epoch, &daemon_version),
        ipc::EpochCheck::Match
    );
}
