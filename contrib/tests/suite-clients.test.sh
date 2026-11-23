#!/bin/sh
# PROTO-REL-001: contrib/suite-clients.txt holds only `tetronos/<repo>` lines
# and `#` comments (blank lines allowed), and release.yml dispatches from that
# file and no other list.
set -eu
cd "$(dirname "$0")/../.."
f=contrib/suite-clients.txt
bad=$(grep -v -E '^(#.*|tetronos/[A-Za-z0-9._-]+|)$' "$f" || true)
[ -z "$bad" ] || { echo "FAIL: bad lines in $f:"; echo "$bad"; exit 1; }
n=$(grep -c -E '^tetronos/' "$f")
[ "$n" -ge 1 ] || { echo "FAIL: no clients in $f"; exit 1; }
grep -q 'contrib/suite-clients.txt' .github/workflows/release.yml || { echo "FAIL: release.yml does not read $f"; exit 1; }
grep -q 'event_type\\":\\"tetron-release' .github/workflows/release.yml || { echo "FAIL: release.yml does not send tetron-release"; exit 1; }
echo "PASS: $n suite clients, release.yml dispatches from $f"
