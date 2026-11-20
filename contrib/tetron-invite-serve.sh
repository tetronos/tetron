#!/bin/sh
# tetron-invite-serve.sh - easy entry for tetron-invite-serve.py
# (INVITE-SERVE-002). Run it with no arguments: it uses your only network, or
# lists them. Prints a short URL for the joiner. See the .py file for options.
set -eu

for c in python3 tetron; do
	command -v "$c" >/dev/null 2>&1 || { echo "tetron-invite-serve: $c not found" >&2; exit 1; }
done
exec python3 -I "$(dirname "$0")/tetron-invite-serve.py" "$@"
