#!/usr/bin/env python3
"""tetron-invite-serve.py - serve one tetron invite on the LAN (INVITE-SERVE-001).

Usage: tetron-invite-serve.py [NETWORK] [--port PORT] [--invite-stdin]

Prints a short URL on the first line of stdout. On the joiner, enter it in the
tetron-tui join field (J), or: curl --proto =http -fsS URL | tetron join -
The invite is single use, so it keeps serving after a fetch. Stops after 5
wrong paths (exit 3), after 1 hour without a request, or on Ctrl+C / SIGTERM.
Needs tetron on PATH. Python stdlib only.
"""
import argparse
import http.server
import json
import secrets
import signal
import subprocess
import sys
import time

ALPHABET = "abcdefghjkmnpqrstvwxyz23456789"  # speakable: no 0 o 1 l i u
TOKEN_LEN = 6
MAX_WRONG = 5
IDLE_SECONDS = 3600
PORT_TRIES = 20


def die(msg, code=1):
    print(f"tetron-invite-serve: {msg}", file=sys.stderr)
    sys.exit(code)


def run(cmd, step):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        die(f"{step} failed: {e}")
    if r.returncode != 0:
        die(f"{step} failed")
    return r.stdout


def pick_network(arg):
    if arg:
        return arg
    st = json.loads(run(["tetron", "status", "--json"], "tetron status"))
    names = [n["network"] for n in st.get("networks", [])]
    if not names:
        die("no tetron network found")
    if len(names) == 1:
        return names[0]
    if not sys.stdin.isatty():
        die("several networks, name one: " + ", ".join(names), 2)
    for i, n in enumerate(names, 1):
        print(f"{i}) {n}", file=sys.stderr)
    try:
        return names[int(input("network number: ")) - 1]
    except (ValueError, IndexError, EOFError):
        die("no network chosen", 2)


def lan_address():
    out = run(["ip", "-4", "route", "get", "1.1.1.1"], "ip route get")
    f = out.split()
    if "src" not in f[:-1]:
        die("no default route, can not pick a LAN address")
    return f[f.index("src") + 1]


class Server(http.server.HTTPServer):
    timeout = 1

    def __init__(self, addr, token, invite):
        self.token, self.invite = token, invite
        self.wrong = 0
        self.last = time.monotonic()
        super().__init__(addr, Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.last = time.monotonic()
        if self.path.strip("/").lower() == self.server.token:
            body = (self.server.invite + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.server.wrong += 1
            self.send_error(404)


def bind(ip, port):
    token = "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_LEN))
    for p in range(port, port + PORT_TRIES):
        try:
            return Server((ip, p), token, None), p
        except OSError:
            continue
    die(f"no free port from {port}")


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("network", nargs="?")
    ap.add_argument("--port", type=int, default=7979)
    ap.add_argument("--invite-stdin", action="store_true")
    a = ap.parse_args()

    ip = lan_address()
    if a.invite_stdin:
        invite = sys.stdin.readline().strip()
        if not invite:
            die("no invite on stdin")
    else:
        net = pick_network(a.network)
        out = run(["tetron", "invite", net, "create", "--json"],
                  f"tetron invite {net} create")
        try:
            invite = json.loads(out)["invite_key"]
        except (ValueError, KeyError):
            die("could not read invite_key from tetron output")

    srv, port = bind(ip, a.port)
    srv.invite = invite
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append("signal"))
    print(f"http://{ip}:{port}/{srv.token}", flush=True)
    print("serving until Ctrl+C, 5 wrong paths or 1 hour idle", file=sys.stderr)
    try:
        while not stop:
            srv.handle_request()
            if srv.wrong >= MAX_WRONG:
                print("stopped: too many wrong requests", file=sys.stderr)
                return 3
            if time.monotonic() - srv.last >= IDLE_SECONDS:
                print("stopped: idle for 1 hour", file=sys.stderr)
                return 0
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    print("stopped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
