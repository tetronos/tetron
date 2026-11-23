'''
tetron-proto wire contract: protocol epoch, version-skew tolerance, and the
release signal to the suite clients. Plan:
DO-NOT-COMMIT/PLAN_tetron_suite_proto_dependency_pinning_bump_automation_and_registry_at_v1.md
(phase 1). USER decisions 2026-11-23: a protocol mismatch warns, never
refuses (R5); bump scripts and workflows live in each client repo (R4).

Dependency order: PROTO-EPOCH-001 first. PROTO-EPOCH-002 and PROTO-EPOCH-003
need it and are independent of each other. PROTO-EPOCH-004 needs 002 and 003.
PROTO-WIRE-001 needs 001. PROTO-WIRE-002 and CON-PROTO01 are independent of
everything else. PROTO-REL-001 is independent of the code items.
'''

from libspec import Requirement, Constraint


class ProtocolEpochConstant(Requirement):
    """REQUIREMENT-ID: PROTO-EPOCH-001

    `tetron-proto` exports `PROTOCOL_EPOCH: &str`, the wire protocol
    generation a build speaks. Before 1.0 it is `MAJOR.MINOR` of the
    `tetron-proto` crate version (`0.15` for 0.15.x), because in 0.x every
    minor may change the wire format and every patch must not. Built from
    `CARGO_PKG_VERSION_MAJOR` and `CARGO_PKG_VERSION_MINOR` at compile time,
    no runtime parsing.

    Phase 2 (suite 1.0.0, plan section 6): `tetron-proto` gets its own semver
    by wire compatibility and the epoch becomes its major alone. That is a
    later requirement; this one fixes the 0.x rule only.

    Tests: `PROTOCOL_EPOCH` equals the first two dot-separated parts of
    `CARGO_PKG_VERSION`.
    """
    req_id = "PROTO-EPOCH-001"


class StatusResponseCarriesEpoch(Requirement):
    """REQUIREMENT-ID: PROTO-EPOCH-002

    `IpcMessage::StatusResponse` gains `protocol_epoch: String` with
    `#[serde(default)]`; the daemon fills it with `PROTOCOL_EPOCH`. An older
    daemon omits it and the client reads an empty string; an older client
    ignores the field (messages are encoded as named maps). `daemon_version`
    stays and keeps its meaning (the binary version, for the restart hint).

    Depends on: PROTO-EPOCH-001.

    Tests: round trip with the field; a StatusResponse encoded without the
    field decodes with `protocol_epoch == ""`.
    """
    req_id = "PROTO-EPOCH-002"


class EpochCheckHelper(Requirement):
    """REQUIREMENT-ID: PROTO-EPOCH-003

    `tetron_proto::ipc::epoch_check(protocol_epoch, daemon_version)` returns
    `EpochCheck::Match`, `EpochCheck::Mismatch { daemon, client }` or
    `EpochCheck::Unknown`, comparing the daemon's epoch with this build's
    `PROTOCOL_EPOCH`. When `protocol_epoch` is empty (a daemon older than
    PROTO-EPOCH-002) the daemon epoch is taken from `daemon_version`
    (`MAJOR.MINOR`); when that is empty or unparsable too, the result is
    `Unknown`. `EpochCheck::warning()` gives `None` for Match and Unknown and
    one line for Mismatch that names both epochs and which side to upgrade
    (`tetron daemon speaks protocol 0.16, this client 0.15: upgrade this
    client`; the reverse names the daemon).

    A mismatch is a warning, never a refusal (USER R5): the client keeps
    working with what it can decode. Every suite client calls this helper
    once per connection that reads a StatusResponse; this repo only
    provides it.

    Depends on: PROTO-EPOCH-001. Independent of PROTO-EPOCH-002 (it only
    takes strings).

    Tests: match; daemon newer; daemon older; empty epoch with a parsable
    daemon_version (both outcomes); both empty is Unknown; garbage is
    Unknown; Match and Unknown give no warning.
    """
    req_id = "PROTO-EPOCH-003"


class CliShowsEpoch(Requirement):
    """REQUIREMENT-ID: PROTO-EPOCH-004

    `tetron status --json` adds `"protocol_epoch"` (the daemon's value as
    received, empty for an older daemon). Plain `tetron status` prints the
    `EpochCheck::warning()` line on stderr when there is one, next to the
    existing restart hint; nothing is printed when the epochs match.

    Depends on: PROTO-EPOCH-002, PROTO-EPOCH-003.

    Tests: the JSON builder includes the field; the warning text is
    produced by the helper (covered in PROTO-EPOCH-003).
    """
    req_id = "PROTO-EPOCH-004"


class UndecodableRequestNamesProtocol(Requirement):
    """REQUIREMENT-ID: PROTO-WIRE-001

    Extends IPC-DECODE-ERR-001. The `IpcMessage::Error` the daemon sends for a
    request it cannot decode (most often a variant from a newer client)
    starts with `request not supported by this daemon (tetron VERSION,
    protocol EPOCH): ` followed by the decode error. The whole message,
    prefix included, goes through IPC-DECODE-ERR-001's
    `truncate_decode_error` bound. The client sees why,
    and which side to upgrade, instead of a bare decode error.

    Depends on: PROTO-EPOCH-001.

    Tests: the formatter produces the prefix with this build's version and
    epoch; a 900 kB error is still bounded.
    """
    req_id = "PROTO-WIRE-001"


class PreviousReleaseFixturesDecode(Requirement):
    """REQUIREMENT-ID: PROTO-WIRE-002

    `tetron-proto/tests/fixtures/<tag>/` holds msgpack frames (named-map
    encoding) of representative messages as the release `<tag>` wrote them:
    every request variant without data, `Status`, `StatusResponse` with one
    network and one peer, `InviteCreate`, `InviteCreated`, `Error`. A test
    decodes every fixture of every committed tag with the current types and
    fails on any error. This catches a removed or renamed field, a field
    added without `#[serde(default)]`, and a changed variant name, which are
    the changes that break an older peer.

    The first set is generated from v0.15.5 (`tetron-proto` is unchanged
    between v0.15.5 and this branch's base). At each release the new set is
    added; old sets stay for the life of the epoch.

    Independent of the PROTO-EPOCH items.
    """
    req_id = "PROTO-WIRE-002"


class ProtoWireRules(Constraint):
    """CONSTRAINT-ID: CON-PROTO01

    The wire tolerance rules that can be checked by text: in
    `tetron-proto/src/**/*.rs` there is no `deny_unknown_fields`, and no
    `rmp_serde::to_vec(` outside `#[cfg(test)]` modules (positional
    encoding would make field order part of the wire format). Encoding is
    `rmp_serde::to_vec_named` only.

    ENFORCEMENT (reconcile.py): proto_wire_rules.violations equals 0.
    """
    constraint_id = "CON-PROTO01"
    enforcement_logic = "{{ proto_wire_rules.violations == 0 }}"


class ReleaseDispatchToClients(Requirement):
    """REQUIREMENT-ID: PROTO-REL-001

    On a release tag, `.github/workflows/release.yml` sends one
    `repository_dispatch` with event type `tetron-release` and payload
    `{"tag": "<tag>"}` to every repository listed in
    `contrib/suite-clients.txt` (one `tetronos/<repo>` per line, `#`
    comments). Each client repo runs its own `bump-proto.yml` on that event
    (bump script, tests, pull request); nothing merges by itself.

    The dispatch uses the repository secret `SUITE_DISPATCH_TOKEN` (the
    tetronos bot token, never a personal token). A missing secret or a
    failed dispatch to one repo is logged and does not fail the release:
    the release itself is already out, and the client can be bumped by
    hand with its `contrib/bump-proto.sh`.

    Independent of the code requirements.

    Tests: `contrib/suite-clients.txt` parses (only `tetronos/<name>` lines
    and comments); the workflow step reads that file and nothing else
    (checked in reconcile by the existing workflow checks).
    """
    req_id = "PROTO-REL-001"
