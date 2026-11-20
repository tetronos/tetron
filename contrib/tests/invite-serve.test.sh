#!/usr/bin/env bash
# Hermetic test of contrib/tetron-invite-serve.py and .sh (INVITE-SERVE-001,
# INVITE-SERVE-002). A stub `tetron` on PATH answers status and invite create;
# the server binds the default route address on a high port.
set -uo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"
PY="$D/tetron-invite-serve.py"
SH="$D/tetron-invite-serve.sh"
T="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

mkdir "$T/bin"
cat > "$T/bin/tetron" <<'STUB'
#!/bin/sh
case "$1" in
status) printf '{"networks":[%s]}\n' "$(cat "$STUB_NETS")" ;;
invite) echo '{"invite_key":"INVITEKEY123"}' ;;
esac
STUB
chmod +x "$T/bin/tetron"
export PATH="$T/bin:$PATH" STUB_NETS="$T/nets"
echo '{"network":"alpha"}' > "$T/nets"

start() { # extra args; sets URL, PID, ERR
	ERR="$T/err.$RANDOM"
	python3 -I "$PY" --port 18979 "$@" > "$T/out" 2> "$ERR" &
	PID=$!
	for _ in $(seq 50); do [ -s "$T/out" ] && break; sleep 0.1; done
	URL=$(head -n1 "$T/out")
}
get() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$1"; }

# default network, path shape, 200 on the token (case-insensitive), 404 else
start
case "$URL" in http://*:*/??????) ok "url has a 6 character path" ;; *) bad "url shape: $URL" ;; esac
TOK=${URL##*/}
[[ "$TOK" =~ ^[abcdefghjkmnpqrstvwxyz23456789]{6}$ ]] && ok "token alphabet" || bad "token alphabet: $TOK"
[ "$(curl -s --max-time 3 "$URL")" = INVITEKEY123 ] && ok "serves the invite" || bad "serves the invite"
[ "$(curl -s --max-time 3 "${URL%/*}/${TOK^^}")" = INVITEKEY123 ] && ok "case-insensitive" || bad "case-insensitive"
[ "$(curl -s --max-time 3 "$URL")" = INVITEKEY123 ] && ok "serves again after a fetch" || bad "serves again"
[ "$(get "${URL%/*}/")" = 404 ] && ok "404 elsewhere" || bad "404 elsewhere"
kill -TERM $PID; wait $PID; [ $? -eq 0 ] && ok "SIGTERM exits 0" || bad "SIGTERM exit"

# lockout after 5 wrong paths: exit 3
start
for i in 1 2 3 4 5; do get "${URL%/*}/x$i" >/dev/null; done
wait $PID; rc=$?
[ $rc -eq 3 ] && ok "lockout exits 3" || bad "lockout exit $rc"
grep -q "too many" "$ERR" && ok "lockout reason on stderr" || bad "lockout reason"

# invite from stdin, no tetron call
echo STDININVITE | python3 -I "$PY" --port 18979 --invite-stdin > "$T/out" 2>/dev/null &
PID=$!; for _ in $(seq 50); do [ -s "$T/out" ] && break; sleep 0.1; done
URL=$(head -n1 "$T/out")
[ "$(curl -s --max-time 3 "$URL")" = STDININVITE ] && ok "invite from stdin" || bad "invite from stdin"
kill -TERM $PID; wait $PID 2>/dev/null

# port in use: next free port
LANIP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')
python3 -m http.server 18979 --bind "$LANIP" >/dev/null 2>&1 &
SPID=$!; sleep 0.5
start
case "$URL" in *:18979/*) bad "port fallback" ;; *) ok "port fallback" ;; esac
kill -TERM $PID; wait $PID 2>/dev/null; kill $SPID

# several networks, not a terminal: exit 2
printf '{"network":"alpha"},{"network":"beta"}\n' > "$T/nets"
python3 -I "$PY" </dev/null >/dev/null 2>"$T/e"; [ $? -eq 2 ] && ok "several networks exit 2" || bad "several networks"
grep -q "alpha, beta" "$T/e" && ok "names listed" || bad "names listed"
# none: exit 1
echo > "$T/nets"; python3 -I "$PY" </dev/null >/dev/null 2>&1; [ $? -eq 1 ] && ok "no network exit 1" || bad "no network"

# wrapper: missing tool is named; works with no arguments
echo '{"network":"alpha"}' > "$T/nets"
PATH="$T/bin" /bin/sh -c "PATH=$T/bin; $SH" 2>"$T/e"; grep -q "python3 not found" "$T/e" && ok "wrapper names missing python3" || bad "wrapper missing tool"
"$SH" --port 18979 > "$T/out" 2>/dev/null &
for _ in $(seq 50); do [ -s "$T/out" ] && break; sleep 0.1; done
[ "$(curl -s --max-time 3 "$(head -n1 "$T/out")")" = INVITEKEY123 ] && ok "wrapper runs with no network argument" || bad "wrapper run"

exit $fail
