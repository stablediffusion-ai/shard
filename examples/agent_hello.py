#!/usr/bin/env python3
"""
Shard DSP — agent context persistence hello world.

Full loop:
  Session 1 — create a context blob, upload it, store the magnet.
  Session 2 — restore the context from the stored magnet.

Requires : shard-gui running on localhost:9201.
Dependencies : Python 3.6+ stdlib only (http.client, json, pathlib).
"""
import http.client
import json
import pathlib
import sys
import tempfile

HOST        = "127.0.0.1"
PORT        = 9201
MAGNET_FILE = pathlib.Path.home() / ".shard_hello_magnet"


def _post(path, body, content_type):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=120)
    conn.request("POST", path, body=body,
                 headers={"Content-Type": content_type})
    resp = conn.getresponse()
    data = json.loads(resp.read())
    if resp.status >= 400:
        print(f"[error] HTTP {resp.status}: {data.get('error', data)}", file=sys.stderr)
        sys.exit(1)
    return data


def upload(file_path: pathlib.Path) -> str:
    boundary = "shardbound"
    raw = file_path.read_bytes()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + raw + f"\r\n--{boundary}--\r\n".encode()
    return _post("/api/files/upload", body,
                 f"multipart/form-data; boundary={boundary}")["magnet"]


def download(magnet: str) -> pathlib.Path:
    body = json.dumps({"magnet": magnet}).encode()
    result = _post("/api/files/download", body, "application/json")
    return pathlib.Path(result["path"])


# ── main ──────────────────────────────────────────────────────────────────────

if not MAGNET_FILE.exists():
    # ── Session 1: save context ───────────────────────────────────────────────
    context = {"agent": "hello-world", "step": 1, "memory": ["first run"]}
    tmp = pathlib.Path(tempfile.mktemp(suffix="_ctx.json"))
    tmp.write_text(json.dumps(context, indent=2))

    print(f"Uploading {tmp.name} …")
    magnet = upload(tmp)
    MAGNET_FILE.write_text(magnet)
    tmp.unlink()

    print(f"[OK] Context saved.\nMagnet: {magnet}")
    print("Run again to restore it.")

else:
    # ── Session 2: restore context ────────────────────────────────────────────
    magnet = MAGNET_FILE.read_text().strip()
    print(f"Restoring context…\n{magnet}")
    restored = download(magnet)
    data = json.loads(restored.read_text())
    print(f"[OK] Context restored: {data}")
    MAGNET_FILE.unlink()
    print("Magnet file removed — next run starts fresh.")
