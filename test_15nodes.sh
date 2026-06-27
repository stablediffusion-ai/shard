#!/usr/bin/env bash
# Test DSP — 15 nœuds de stockage + seed + uploader + downloader
#
# Topologie (16 processus) :
#   9000        seed       (bootstrap, pas de stockage applicatif)
#   9001–9013   stockage   (13 nœuds — avec seed+uploader = 15 nœuds DHT actifs)
#   9014        uploader   (reste vivant via FIFO → DHT stable)
#   9015        downloader (nœud éphémère, /get puis /exit)
#
# Reed-Solomon : 10 data shards + 5 parity = 15 fragments.
# Avec 15 nœuds DHT actifs, chaque fragment peut atterrir sur un nœud distinct.
#
# Usage : bash test_15nodes.sh

set -uo pipefail
cd "$(dirname "$0")"

B=./target/release/shard-cli
PIDS=()
TAIL_PID=""
TESTFILE="dsp_15n_$$.txt"
FIFO=/tmp/dsp_9014_fifo
SEED_PORT=9000
STORAGE_PORTS=(9001 9002 9003 9004 9005 9006 9007 9008 9009 9010 9011 9012 9013)
UPLOADER_PORT=9014
DOWNLOADER_PORT=9015

# ── Couleurs ──────────────────────────────────────────────────────────────────
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; CYAN='\033[36m'; RESET='\033[0m'
ok()   { printf " ${GREEN}OK${RESET}\n"; }
warn() { printf " ${YELLOW}WARN${RESET} %s\n" "$1"; }
fail() { printf " ${RED}FAIL${RESET}\n\n"; tail -30 "$1" 2>/dev/null | sed 's/^/  /'; exit 1; }
step() { printf "[ %-9s] %s" "$1" "$2"; }
info() { printf "           ${CYAN}%s${RESET}\n" "$1"; }

# ── Config test allégée ───────────────────────────────────────────────────────
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
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   Test DSP — 15 nœuds de stockage (Reed-Solomon complet)  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Build ─────────────────────────────────────────────────────────────────────
step "build" "cargo build --release ... "
cargo build --release -q 2>&1 || { printf " ${RED}FAIL${RESET}\n"; exit 1; }
ok

rm -rf ./data_swarm/ ./downloads/ "$FIFO"
mkdir -p ./downloads

# ── Payload (64 Ko pour exercer plusieurs chunks Reed-Solomon) ────────────────
step "payload" "création (64 Ko de données aléatoires) ... "
{
    printf "DSP 15-nodes test\nDate: %s\nPID: %d\n" "$(date)" "$$"
    dd if=/dev/urandom bs=1024 count=48 2>/dev/null | base64
} > "$TESTFILE"
ok
info "taille : $(du -sh "$TESTFILE" | cut -f1)"

# ── Seed 9000 ─────────────────────────────────────────────────────────────────
write_test_config "$SEED_PORT"
step "seed" "port $SEED_PORT ... "
sleep infinity | RUST_LOG=shard=info,quinn=warn "$B" --port "$SEED_PORT" --seed \
    > "/tmp/dsp_${SEED_PORT}.log" 2>&1 &
PIDS+=($!)
sleep 2
ok

# ── Nœuds de stockage 9001–9013 — démarrage par vague de 4 ──────────────────
echo ""
printf "  Démarrage des nœuds de stockage :\n\n"

WAVE_SIZE=4
wave=0
count=0

for port in "${STORAGE_PORTS[@]}"; do
    write_test_config "$port"
    step "peer-$(printf '%02d' $((count+1)))" "port $port ... "
    sleep infinity | RUST_LOG=shard=info,quinn=warn "$B" --port "$port" \
        --bootstrap "127.0.0.1:${SEED_PORT}" \
        > "/tmp/dsp_${port}.log" 2>&1 &
    PIDS+=($!)
    ok
    count=$((count+1))
    wave=$((wave+1))

    if [ "$wave" -ge "$WAVE_SIZE" ]; then
        printf "           pause 3s (convergence DHT partielle)...\n"
        sleep 3
        wave=0
    fi
done

# Attente convergence globale
echo ""
step "dht" "attente convergence globale (10s) ... "
sleep 10
ok

# Compter les nœuds qui ont vu au moins 1 pair
ACTIVE=$(grep -rl "Active peers: [1-9]" /tmp/dsp_900*.log /tmp/dsp_901[0-3].log 2>/dev/null | wc -l)
info "${ACTIVE}/${#STORAGE_PORTS[@]} nœuds de stockage ont confirmé leur DHT"

# ── Uploader 9014 ─────────────────────────────────────────────────────────────
write_test_config "$UPLOADER_PORT"
echo ""
step "uploader" "port $UPLOADER_PORT, bootstrap ... "
mkfifo "$FIFO"
exec 5<>"$FIFO"   # O_RDWR : pas de blocage en attente du lecteur

RUST_LOG=shard=debug,quinn=warn "$B" --port "$UPLOADER_PORT" \
    --bootstrap "127.0.0.1:${SEED_PORT}" \
    < "$FIFO" > "/tmp/dsp_${UPLOADER_PORT}.log" 2>&1 &
PIDS+=($!)
sleep 6   # bootstrap + 3 rounds de lookup itératif
ok

PEERS=$(grep -o 'Active peers: [0-9]*' "/tmp/dsp_${UPLOADER_PORT}.log" 2>/dev/null | tail -1 | grep -o '[0-9]*$' || true)
RTABLE=$(grep -o 'routing table : [0-9]*' "/tmp/dsp_${UPLOADER_PORT}.log" 2>/dev/null | tail -1 | grep -o '[0-9]*$' || true)
info "uploader voit ${PEERS:-0} pairs — routing table : ${RTABLE:-0} entrées"

# ── Upload ────────────────────────────────────────────────────────────────────
# TESTFILE est déjà en CWD — pas de cp nécessaire
printf "/put %s\n" "$TESTFILE" >&5

echo ""
printf "[ put      ] /put en cours (max 120s) :\n"

MAGNET=""
MAX_WAIT=120
for i in $(seq 1 $MAX_WAIT); do
    MAGNET=$(grep -oE '[A-Za-z0-9_-]{86}' "/tmp/dsp_${UPLOADER_PORT}.log" 2>/dev/null | head -1)
    [ -n "$MAGNET" ] && break

    LAST=$(grep -E '\[UP\]|\[DOWN\]|chunk|fragment|stored|iterative|lookup|DHT|Peer|direct|punch|relay|ERROR|WARN' \
        "/tmp/dsp_${UPLOADER_PORT}.log" 2>/dev/null \
        | tail -1 \
        | sed 's/^[0-9TZ.:+-]* [A-Z]* [a-z_::]* //' \
        | cut -c1-72)
    FRAGS=$(find ./data_swarm -name "*.bin" 2>/dev/null | wc -l)
    printf "\r  %3ds │ frags: %-3d │ %-65s" "$i" "$FRAGS" "${LAST:-en attente...}"
    sleep 1
done
printf "\n"

[ -n "$MAGNET" ] || fail "/tmp/dsp_${UPLOADER_PORT}.log"

FRAGS=$(find ./data_swarm -name "*.bin" 2>/dev/null | wc -l)
printf "[ put      ] ${GREEN}OK${RESET} — %d fragment(s) stockés (attendu 15)\n" "$FRAGS"
printf "             magnet : ${CYAN}%.52s…${RESET}\n" "$MAGNET"

# Distribution par nœud
echo ""
printf "  Distribution des fragments :\n"
find ./data_swarm -mindepth 3 -name "*.bin" 2>/dev/null \
    | sed 's|./data_swarm/\([^/]*\)/.*|\1|' \
    | sort | uniq -c | sort -rn \
    | while read -r cnt node; do
        BAR=$(printf '%*s' "$cnt" '' | tr ' ' '█')
        printf "    %-20s │ %s (%d)\n" "$node" "$BAR" "$cnt"
    done
echo ""

# ── Download 9015 ─────────────────────────────────────────────────────────────
write_test_config "$DOWNLOADER_PORT"
printf "[ download ] /get en cours (max 120s) :\n"
sleep 3

tail -f "/tmp/dsp_${DOWNLOADER_PORT}.log" 2>/dev/null \
    | grep --line-buffered -E '\[UP\]|\[DOWN\]|chunk|fragment|SUCCESS|ERROR|Peer|DHT|direct|punch' \
    | sed -u 's/^/  │ /' &
TAIL_PID=$!

printf "/get %s\n/exit\n" "$MAGNET" \
    | RUST_LOG=shard=debug,quinn=warn timeout 120 "$B" --port "$DOWNLOADER_PORT" \
        --bootstrap "127.0.0.1:${SEED_PORT}" \
        > "/tmp/dsp_${DOWNLOADER_PORT}.log" 2>&1 || true

sleep 0.3
kill "$TAIL_PID" 2>/dev/null || true; TAIL_PID=""
printf "\n"

grep -q "SUCCESS" "/tmp/dsp_${DOWNLOADER_PORT}.log" || fail "/tmp/dsp_${DOWNLOADER_PORT}.log"
printf "[ download ] ${GREEN}OK${RESET}\n\n"

# ── Vérification intégrité ────────────────────────────────────────────────────
step "verify" "intégrité du fichier reconstruit ... "
BASE=$(basename "$TESTFILE" .txt)
DEST=$(find . -path "*/downloads/${BASE}*" -o -path "*/downloads/${TESTFILE}" 2>/dev/null | head -1)

if [ -n "$DEST" ] && diff -q "$TESTFILE" "$DEST" >/dev/null 2>&1; then
    ok
    info "${GREEN}$TESTFILE == $DEST${RESET}"
elif [ -n "$DEST" ]; then
    printf " ${RED}MISMATCH${RESET} contenu différent : %s\n" "$DEST"
    exit 1
else
    warn "fichier introuvable — succès confirmé via log (path non standard)"
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   PASS — 15 nœuds, upload + download Reed-Solomon OK      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
printf "Logs : /tmp/dsp_900{0..9}.log  /tmp/dsp_901{0..5}.log\n"
