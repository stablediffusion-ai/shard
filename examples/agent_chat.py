#!/usr/bin/env python3
"""
Shard DSP — agent chat hello world.
Join a room, send a message, listen for responses via WebSocket.

Requires : shard-gui on localhost:9201.  Python 3.6+ stdlib only.
Usage    : python3 agent_chat.py <room> <message>
"""
import base64, http.client, json, os, socket, sys

HOST = "127.0.0.1"
PORT = 9201


def _post(path, payload):
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    conn.request("POST", path, body=body,
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = json.loads(resp.read())
    if resp.status >= 400:
        sys.exit(f"[error] {resp.status}: {data.get('error', data)}")
    return data


def _ws_listen(seconds=8):
    """Read ChatMessage events from the WebSocket stream for `seconds` seconds."""
    key  = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((HOST, PORT), timeout=seconds)
    sock.sendall((
        f"GET /ws HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += sock.recv(256)
    try:
        while True:
            h = sock.recv(2)
            n = h[1] & 0x7F
            if n == 126: n = int.from_bytes(sock.recv(2), "big")
            p = b""
            while len(p) < n: p += sock.recv(n - len(p))
            try:
                e = json.loads(p)
                if e.get("type") == "ChatMessage":
                    c = e["payload"]
                    print(f"[{c['room']}] <{c['sender'][:12]}…>: {c['content']}")
            except (json.JSONDecodeError, KeyError):
                pass
    except (socket.timeout, ConnectionResetError):
        pass
    finally:
        sock.close()


# ── main ──────────────────────────────────────────────────────────────────────

if len(sys.argv) < 3:
    sys.exit("Usage: agent_chat.py <room> <message>")

room, message = sys.argv[1], sys.argv[2]

print(f"Joining #{room}…")
_post("/api/chat/join", {"room": room})
print(f"Sending: {message!r}")
_post("/api/chat/send", {"content": message})
print("[OK] Message sent. Listening for responses (8 s)…\n")
_ws_listen(8)
print("\nDone.")
