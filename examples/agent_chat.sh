#!/usr/bin/env bash
# Shard DSP — agent chat hello world.
#
# Demonstrates: join a room, send a message, listen for responses.
#
# Requires : curl, shard-gui running on localhost:9201.
#            python3 for JSON parsing and WebSocket listener (stdlib only).
#
# Usage:
#   ./agent_chat.sh <room> <message>
#   ./agent_chat.sh general "hello from agent"

set -euo pipefail

SHARD="http://127.0.0.1:9201"
ROOM="${1:-general}"
MESSAGE="${2:-hello from agent}"

json_field() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }

# ── join ──────────────────────────────────────────────────────────────────────
echo "Joining #${ROOM}…"
curl -sf -X POST "$SHARD/api/chat/join" \
    -H "Content-Type: application/json" \
    -d "{\"room\": \"$ROOM\"}" | json_field joined

# ── send ──────────────────────────────────────────────────────────────────────
echo "Sending: $MESSAGE"
curl -sf -X POST "$SHARD/api/chat/send" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"$MESSAGE\"}" | json_field sent

echo "[OK] Message sent. Listening for responses (8 s)…"

# ── listen — minimal WebSocket reader via Python ──────────────────────────────
python3 - "127.0.0.1" "9201" <<'PYEOF'
import socket, base64, os, json, sys

host, port = sys.argv[1], int(sys.argv[2])
key  = base64.b64encode(os.urandom(16)).decode()
sock = socket.create_connection((host, port), timeout=8)
sock.sendall((
    f"GET /ws HTTP/1.1\r\nHost: {host}:{port}\r\n"
    f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    buf += sock.recv(256)
try:
    while True:
        h = sock.recv(2)
        if len(h) < 2: break
        n = h[1] & 0x7F
        if n == 126: n = int.from_bytes(sock.recv(2), "big")
        p = b""
        while len(p) < n: p += sock.recv(n - len(p))
        try:
            e = json.loads(p)
            if e.get("type") == "ChatMessage":
                c = e["payload"]
                print(f"[{c['room']}] <{c['sender'][:12]}…>: {c['content']}")
        except Exception: pass
except (socket.timeout, ConnectionResetError): pass
PYEOF

echo "Done."
