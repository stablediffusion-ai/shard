# Shardnet

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

> Store and share files without servers. Encrypted on your device. Split across the network. Nothing to trust.

Shardnet is a peer-to-peer distributed storage protocol built in Rust. Files are encrypted client-side with AES-256-GCM, split into 15 Reed-Solomon fragments (10 data + 5 parity), and distributed across the network. Any 10 fragments reconstruct the original file. No central server, no accounts, no metadata leakage.

**[→ Read the full Whitepaper (Protocol Specification)](./WHITEPAPER.md)**

---

## How it works

Files are encrypted client-side with **AES-256-GCM**, split into 15 shards via
**Reed-Solomon erasure coding** (10 data + 5 parity), and distributed across the
swarm. Any 10 of the 15 shards are sufficient to reconstruct the original file.

Node discovery uses a **Kademlia DHT** (XOR metric, k-buckets). Transport is
**QUIC/TLS** (mutual authentication via Ed25519 identity keys). A file is
referenced by a single **magnet string** that encodes both the file ID and the
decryption key.

---

## Requirements

- Linux x86_64 (pre-built static binaries, no dependencies)
- **Minimum 2 nodes** to upload and download (the uploader + 1 peer that stores the shards)
- More peers improve fault tolerance: a file survives as long as any 10 of its 15 shards remain accessible

---

## Quick start

### Download a release

```bash
tar -xzf shard-v0.97.0-linux-x64-static.tar.gz
chmod +x shard-cli shard-gui
```

### Join the public swarm

The default seed is **shardnet.app:9100**. Nodes connect to it automatically on startup.

```bash
# CLI node — connects to shardnet.app:9100 automatically
./shard-cli

# GUI node — web interface on :9201
./shard-gui
```

---

## CLI usage

```
shard> /put <file>        Upload a file, prints magnet link
shard> /get <magnet>      Download a file by magnet link
shard> /read <magnet>     Fetch and render a markdown shard inline (ANSI)
shard> /join <room>       Join a chat room
shard> /leave             Leave current room
shard> /peers             Show routing table size
shard> /status            Node info, storage usage and config
shard> /exit              Save state and quit
```

Flags:

| Flag | Effect |
|---|---|
| `--daemon` | Background Unix daemon, logs to `./logs/` |
| `--passive` | Listen-only mode — no upload, no chat; `/get` and `/read` remain available |
| `--disk-quota <bytes>` | Override storage quota at startup (e.g. `2000000000` = 2 GB); takes priority over `config.toml` |
| `--retention <secs>` | Override shard retention at startup (e.g. `604800` = 7 days); takes priority over `config.toml` |

**Upload**

```
shard> /put photo.jpg
[SUCCESS] Uploaded.
Magnet: y36fKjLLjYcs8Ls3PZVvchIuMaZsgFL3wJwDNCAUw5U3HI...
```

**Download** (on any node in the swarm)

```
shard> /get y36fKjLLjYcs8Ls3PZVvchIuMaZsgFL3wJwDNCAUw5U3HI...
> Fetching file to ./downloads...
[SUCCESS] Download complete.
```

---

## GUI usage

```bash
./shard-gui --port 9200 --gui-port 9201 --gui-host 0.0.0.0
```

Open `http://<host>:9201` in a browser. Monochrome UI (black/grey palette). Tabs:

- **Home** — node identity, peer count, file upload/download
- **Browser** — paste a magnet, renders `.md` shards inline
- **Chat** — room-based messages, Ed25519-signed

---

## Running a seed node

A seed node acts as the public entry point for the swarm. It does not bootstrap
to anyone else (`--seed` disables outgoing bootstrap).

```bash
# Seed on a public IP — P2P on :9100, GUI accessible remotely on :9101
./shard-gui --port 9100 --seed --gui-host 0.0.0.0 --gui-port 9101
```

CLI variant (no web interface):

```bash
./shard-cli --port 9100 --seed
```

---

## Bootstrap options

| Scenario | Command |
|---|---|
| Auto (default) | `./shard-cli` — tries `shardnet.app:9100` then `127.0.0.1:9100` |
| Explicit peer | `./shard-cli --bootstrap 192.168.1.10:9000` |
| Seed mode | `./shard-cli --seed` — no outgoing bootstrap |

---

## NAT / firewall

Nodes behind NAT work as clients (upload + download) without port forwarding.
The protocol uses:

- **STUN** — discovers the public IP:port via the seed
- **UDP hole punching** — coordinated through the seed when direct connection fails
- **LAN preference** — nodes sharing a public IP route to each other via LAN address

Nodes intended as fragment storage targets (upload destinations) should have
their QUIC port reachable inbound, or run on a public IP.

---

## Building from source

Requires Rust stable.

```bash
# Debug build
cargo build --bins

# Release — fully static binary via Docker (no glibc dependency)
docker run --rm -v "$(pwd)":/app -w /app rust:alpine \
  sh -c "apk add --no-cache musl-dev && cargo build --release --bin shard-cli --bin shard-gui"
```

---

## Building the whitepaper

Requires Docker.

```bash
./build_whitepaper.sh
```

Generates `dist/whitepaper.pdf` and syncs the PDF download filename in `dist/whitepaper.html` to match the version in `WHITEPAPER.md`. Run this before committing whenever `WHITEPAPER.md` changes.

---

## Project structure

```
src/
├── bin/
│   ├── cli.rs          CLI entry point and REPL
│   ├── gui.rs          GUI node entry point
│   └── term_md/        Terminal markdown renderer (ANSI, no external deps)
├── config.rs           Node configuration (TOML)
├── context.rs          Node state (Arc<InnerNode>)
├── crypto.rs           AES-256-GCM file encryption
├── dht.rs              Kademlia routing table (k-buckets, XOR metric)
├── events.rs           Internal event bus (ShardEvent)
├── gui/
│   └── index.html      Single-page web UI
├── gui_server.rs       Axum HTTP/WebSocket server + REST API
├── handlers.rs         Packet handlers (DHT, STUN, NAT punch, chat, transfer)
├── node.rs             Node methods (bootstrap, broadcast, upload/download)
├── packet.rs           Protocol message definitions (Bincode)
├── router.rs           Packet dispatch
├── sharding.rs         Reed-Solomon encode/decode
├── tasks.rs            Background tasks (peer maintenance, STUN refresh)
├── transfer.rs         File upload / download streams
└── transport.rs        QUIC/TLS, NAT traversal (hole punching, LAN detection)
```

---

## Protocol

| Layer | Technology |
|---|---|
| Transport | QUIC (quinn 0.11) + TLS 1.3 (rustls) |
| Identity | Ed25519 (ed25519-dalek 2.1) |
| Routing | Kademlia DHT — K=20, XOR metric |
| Erasure coding | Reed-Solomon — 10 data + 5 parity shards |
| Encryption | AES-256-GCM (aes-gcm 0.10) |
| Serialization | Bincode |
| HTTP/WS server | Axum 0.7 |

---

## Version

`v0.97.0` — static Linux x86_64 binary, no runtime dependencies.

---

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3) - see the [LICENSE](LICENSE) file for details.
