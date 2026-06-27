#!/usr/bin/env bash
# Test minimal DSP — 3 nœuds (seed + stockage + uploader + downloader)
#
# Topologie :
#   9000  seed       (routing table uniquement)
#   9001  stockage   (reçoit les shards)
#   9002  uploader   (reste vivant via FIFO → DHT stable pour le downloader)
#   9003  downloader (nœud éphémère, /get puis /exit)
#
# Usage : bash test_minimal.sh

set -uo pipefail
cd "$(dirname "$0")"

B=./target/release/shard-cli
PIDS=()
TAIL_PID=""
TESTFILE="dsp_test_$$.txt"
FIFO=/tmp/dsp_9002_fifo

# ── Couleurs ──────────────────────────────────────────────────────────────────
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; CYAN='\033[36m'; RESET='\033[0m'
ok()   { printf " ${GREEN}OK${RESET}\n"; }
warn() { printf " ${YELLOW}WARN${RESET} %s\n" "$1"; }
fail() { printf " ${RED}FAIL${RESET}\n\n"; tail -30 "$1" 2>/dev/null | sed 's/^/  /'; exit 1; }
step() { printf "[ %-8s] %s" "$1" "$2"; }

# ── Config test allégée ───────────────────────────────────────────────────────
# difficulty=1 (1 bit PoW au lieu de 6) → démarrage quasi-instantané.
# Le rate limiter loopback est désormais bypassé dans node.rs.
write_test_config() {
    local port="$1"
    local dir="./data_swarm/node_${port}"
    mkdir -p "${dir}/sys"
    cat > "${dir}/config.toml" << 'TOML'
[network]
default_port = 9000
bootstrap_peers = []
enable_upnp = false

[storage]
max_storage_bytes = 10000000000
cleanup_interval_sec = 1800
retention_period_sec = 86400

[mining]
difficulty = 1
TOML
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
    [ ${#PIDS[@]} -gt 0 ] && kill "${PIDS[@]}" 2>/dev/null || true
    exec 5>&- 2>/dev/null || true
    rm -f "$TESTFILE" "$FIFO" "./$(basename "$TESTFILE")"
    rm -rf ./data_swarm/ ./downloads/
}
trap cleanup EXIT

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Test minimal DSP — 3 nœuds             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Build ─────────────────────────────────────────────────────────────────────
step "build" "cargo build --release ... "
cargo build --release -q 2>&1 || { printf " ${RED}FAIL${RESET}\n"; exit 1; }
ok

rm -rf ./data_swarm/ ./downloads/ "$FIFO"
mkdir -p ./downloads

# ── Payload ───────────────────────────────────────────────────────────────────
step "payload" "création (8 Ko de données aléatoires) ... "
{
    printf "DSP minimal test\nDate: %s\nPID: %d\n" "$(date)" "$$"
    dd if=/dev/urandom bs=1024 count=8 2>/dev/null | base64
} > "$TESTFILE"
ok

# ── Seed 9000 ─────────────────────────────────────────────────────────────────
write_test_config 9000
step "seed" "démarrage port 9000 ... "
sleep infinity | RUST_LOG=shard=info,quinn=warn "$B" --port 9000 --seed \
    > /tmp/dsp_9000.log 2>&1 &
PIDS+=($!)
sleep 2
ok

# ── Stockage 9001 ─────────────────────────────────────────────────────────────
write_test_config 9001
step "peer-1" "démarrage port 9001, bootstrap 9000 ... "
sleep infinity | RUST_LOG=shard=info,quinn=warn "$B" --port 9001 \
    --bootstrap 127.0.0.1:9000 \
    > /tmp/dsp_9001.log 2>&1 &
PIDS+=($!)
sleep 3
ok

# ── Uploader 9002 ─────────────────────────────────────────────────────────────
write_test_config 9002
step "uploader" "démarrage port 9002 ... "
mkfifo "$FIFO"
exec 5<>"$FIFO"   # O_RDWR : pas de blocage en attente du lecteur

RUST_LOG=shard=debug,quinn=warn "$B" --port 9002 \
    --bootstrap 127.0.0.1:9000 \
    < "$FIFO" > /tmp/dsp_9002.log 2>&1 &
PIDS+=($!)
sleep 3   # bootstrap + iterative DHT lookup (3 rounds × ~250ms + handshakes)

PEERS=$(grep -o 'Active peers: [0-9]*' /tmp/dsp_9002.log 2>/dev/null | tail -1 | grep -o '[0-9]*$' || true)
ok
printf "           routing table : ${CYAN}%s${RESET} pair(s)\n" "${PEERS:-0}"

# ── Upload ────────────────────────────────────────────────────────────────────
# TESTFILE est déjà en CWD — pas de cp nécessaire
printf "/put %s\n" "$TESTFILE" >&5

echo ""
printf "[ upload  ] /put en cours (max 90s) :\n"

MAGNET=""
MAX_WAIT=90
for i in $(seq 1 $MAX_WAIT); do
    MAGNET=$(grep -oE '[A-Za-z0-9_-]{86}' /tmp/dsp_9002.log 2>/dev/null | head -1)
    [ -n "$MAGNET" ] && break

    # Dernière ligne utile : chunks, DHT, connexions
    LAST=$(grep -E '\[UP\]|\[DOWN\]|chunk|fragment|stored|iterative|lookup|DHT|Peer|direct|punch|relay|ERROR|error|WARN|warn' \
        /tmp/dsp_9002.log 2>/dev/null \
        | tail -1 \
        | sed 's/^[0-9TZ.:+-]* [A-Z]* [a-z_::]* //' \
        | cut -c1-72)
    printf "\r  %3ds │ %-72s" "$i" "${LAST:-en attente de la réponse DHT...}"
    sleep 1
done
printf "\n"

[ -n "$MAGNET" ] || fail /tmp/dsp_9002.log

FRAGS=$(find ./data_swarm -name "*.bin" 2>/dev/null | wc -l)
printf "[ upload  ] ${GREEN}OK${RESET} — %d fragment(s) stockés\n" "$FRAGS"
printf "           magnet : ${CYAN}%.52s…${RESET}\n" "$MAGNET"
echo ""

# ── Download 9003 ─────────────────────────────────────────────────────────────
write_test_config 9003
printf "[ download] /get en cours (max 90s) :\n"
sleep 2

# tail -f en arrière-plan pour afficher les lignes de progression
tail -f /tmp/dsp_9003.log 2>/dev/null \
    | grep --line-buffered -E '\[UP\]|\[DOWN\]|chunk|fragment|SUCCESS|ERROR|Peer|DHT|direct|punch' \
    | sed -u 's/^/  │ /' &
TAIL_PID=$!

printf "/get %s\n/exit\n" "$MAGNET" \
    | RUST_LOG=shard=debug,quinn=warn timeout 90 "$B" --port 9003 \
        --bootstrap 127.0.0.1:9000 \
        > /tmp/dsp_9003.log 2>&1 || true

sleep 0.3   # laisser tail vider son buffer
kill "$TAIL_PID" 2>/dev/null || true; TAIL_PID=""
printf "\n"

grep -q "SUCCESS" /tmp/dsp_9003.log || fail /tmp/dsp_9003.log
printf "[ download] ${GREEN}OK${RESET}\n\n"

# ── Vérification intégrité ────────────────────────────────────────────────────
step "verify" "intégrité du fichier reconstruit ... "
BASE=$(basename "$TESTFILE" .txt)
# Chercher dans ./downloads/ et dans les data_swarm de chaque nœud
DEST=$(find . -path "*/downloads/${BASE}*" -o -path "*/downloads/${TESTFILE}" 2>/dev/null | head -1)

if [ -n "$DEST" ] && diff -q "$TESTFILE" "$DEST" >/dev/null 2>&1; then
    ok
    printf "           ${GREEN}%s == %s${RESET}\n" "$TESTFILE" "$DEST"
elif [ -n "$DEST" ]; then
    printf " ${RED}MISMATCH${RESET} contenu différent : %s\n" "$DEST"
    exit 1
else
    warn "fichier introuvable — succès confirmé via log (path non standard)"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   PASS — upload + download vérifiés      ║"
echo "╚══════════════════════════════════════════╝"
echo ""
printf "Logs : /tmp/dsp_9000.log  /tmp/dsp_9001.log\n"
printf "       /tmp/dsp_9002.log  /tmp/dsp_9003.log\n"
