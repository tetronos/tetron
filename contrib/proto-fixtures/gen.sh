#!/bin/sh
# PROTO-WIRE-002: generate the wire fixtures of a release tag:
#   contrib/proto-fixtures/gen.sh v0.15.5
# Extracts that tag's tetron-proto into a temporary directory, builds the
# generator against it (crates.io dependencies, outside the workspace), and
# writes tetron-proto/tests/fixtures/<tag>/*.msgpack. Run at each release; the
# generator follows the current types, so update main.rs when a message gains
# a field.
set -eu
tag=${1:?usage: gen.sh vX.Y.Z}
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$root" archive "$tag" tetron-proto | tar -x -C "$work"
cp -r "$root/contrib/proto-fixtures" "$work/gen"
sed -i "s|PROTO_PATH|$work/tetron-proto|" "$work/gen/Cargo.toml"
out="$root/tetron-proto/tests/fixtures/$tag"
(cd "$work/gen" && FIXTURE_VERSION=${tag#v} cargo run -q --release -- "$out")
echo "fixtures for $tag in $out"
ls "$out"
