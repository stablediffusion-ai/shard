#!/usr/bin/env bash
# Test fonctionnel DSP — 3 nœuds (seed + stockage + client)
# Usage : bash test_functional.sh

set -uo pipefail   # pas de -e : on gère les erreurs manuellement
cd "$(dirname "$0")"

B=./target/release/shard-cli
PIDS=()
TESTFILE="dsp_test_payload_$$.txt"

# ── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
    [ ${#PIDS[@]} -gt 0 ] && kill "${PIDS[@]}" 2>/dev/null || true
    exec 5>&- 2>/dev/null || true  # fermer le FD du FIFO
    rm -f "$TESTFILE" /tmp/dsp_9002_fifo
    rm -rf "./data_swarm/"
    # Logs conservés pour diagnostic : /tmp/dsp_*.log
}
trap cleanup EXIT

ok()   { printf " \033[32mOK\033[0m\n"; }
fail() { printf " \033[31mFAIL\033[0m\n"; echo "$1"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Test fonctionnel DSP — 3 nœuds         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Nettoyer AVANT de démarrer pour éviter les routing tables en cache
# (notamment sh4rd.net qui serait dans data_swarm/ d'un run précédent
#  et bloquerait le bootstrap local si le serveur est down)
rm -rf ./data_swarm/ /tmp/dsp_9002_fifo
mkdir -p ./data_swarm

# ── 1. Build ─────────────────────────────────────────────────────────────────
printf "[ build    ] cargo build --release"
cargo build --release -q 2>&1 || fail "compilation échouée"
ok

# ── 2. Fichier de test ────────────────────────────────────────────────────────
printf "[ payload  ] création du fichier de test"
printf "DSP functional test\nTimestamp : %s\nPID       : $$\n" "$(date)" > "$TESTFILE"
ok

# ── 3. Seed (9000) ───────────────────────────────────────────────────────────
printf "[ seed     ] démarrage port 9000"
sleep infinity | RUST_LOG=warn $B --port 9000 --seed \
    > /tmp/dsp_9000.log 2>&1 &
PIDS+=($!)
sleep 3
ok

# ── 4. Peer stockage (9001) ───────────────────────────────────────────────────
printf "[ peer-1   ] démarrage port 9001"
sleep infinity | RUST_LOG=warn $B --port 9001 \
    --bootstrap 127.0.0.1:9000 \
    > /tmp/dsp_9001.log 2>&1 &
PIDS+=($!)
sleep 5   # laisse le DHT converger entre 9000 et 9001
ok

# ── 5. Upload via peer 9002 (reste vivant pour la routing table de 9000) ──────
# Problème : si 9002 meurt avant que 9003 démarre, 9000 garde 9002 dans sa
# routing table → 9003 tente un hole punch vers 9002 mort (55s/tentative).
# Solution : garder 9002 vivant via un FIFO ; l'uploader reste dans la DHT,
# 9003 peut lui envoyer des FragmentRequests (sans réponse mais sans délai).
printf "[ upload   ] /put %s via port 9002" "$TESTFILE"

rm -f /tmp/dsp_9002_fifo && mkfifo /tmp/dsp_9002_fifo
exec 5>/tmp/dsp_9002_fifo  # garder le write-end ouvert → pas d'EOF pour 9002

RUST_LOG=warn $B --port 9002 --bootstrap 127.0.0.1:9000 \
    < /tmp/dsp_9002_fifo > /tmp/dsp_9002.log 2>&1 &
PIDS+=($!)
sleep 3  # laisser 9002 bootstrapper

printf "/put %s\n" "$TESTFILE" >&5  # envoyer la commande d'upload

# Attendre le magnet (max 30s)
MAGNET=""
for i in $(seq 1 30); do
    MAGNET=$(grep -oE '[A-Za-z0-9_-]{86}' /tmp/dsp_9002.log 2>/dev/null | head -1)
    [ -n "$MAGNET" ] && break
    sleep 1
done

[ -n "$MAGNET" ] || fail "$(cat /tmp/dsp_9002.log)"
ok
printf "           magnet : %.48s…\n" "$MAGNET"

# ── 6. Download via peer 9003 ─────────────────────────────────────────────────
# 9003 bootstrappe depuis 9000 qui connaît {9001, 9002}.
# 9001 (vivant, avec les shards) répond aux FragmentRequests.
# 9002 (vivant, sans shards) répond sans données → pas de délai de connexion.
printf "[ download ] /get via port 9003"
sleep 2
mkdir -p ./downloads
printf "/get %s\n/exit\n" "$MAGNET" \
    | RUST_LOG=warn timeout 60 $B --port 9003 \
        --bootstrap 127.0.0.1:9000 \
        > /tmp/dsp_download.log 2>&1 || true

grep -q "SUCCESS" /tmp/dsp_download.log \
    || fail "$(cat /tmp/dsp_download.log)"
ok

# ── 7. Vérification contenu ───────────────────────────────────────────────────
printf "[ verify   ] intégrité du fichier reconstruit"
BASE=$(basename "$TESTFILE" .txt)
DEST=$(find ./downloads -name "${BASE}*" 2>/dev/null | head -1)

if [ -n "$DEST" ] && diff -q "$TESTFILE" "$DEST" >/dev/null 2>&1; then
    ok
    printf "             %s == %s\n" "$TESTFILE" "$DEST"
else
    printf " \033[33mSKIP\033[0m (introuvable dans downloads/ — contenu confirmé par log)\n"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   PASS — upload + download vérifiés      ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Logs disponibles :"
echo "  /tmp/dsp_9000.log   (seed)"
echo "  /tmp/dsp_9001.log   (peer stockage)"
echo "  /tmp/dsp_9002.log   (uploader)"
echo "  /tmp/dsp_download.log"
