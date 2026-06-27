#!/usr/bin/env bash
# Shard DSP — agent context persistence hello world.
#
# Full loop:
#   Session 1 — create a context blob, upload it, store the magnet.
#   Session 2 — restore the context from the stored magnet.
#
# Requires : curl, shard-gui running on localhost:9201.
#            python3 for JSON parsing (stdlib, no jq needed).

set -euo pipefail

SHARD="http://127.0.0.1:9201"
MAGNET_FILE="$HOME/.shard_hello_magnet"
CTX_FILE="$(mktemp /tmp/shard_ctx_XXXXXX.json)"

json_field() {
    python3 -c "import sys, json; print(json.load(sys.stdin)['$1'])"
}

if [ ! -f "$MAGNET_FILE" ]; then
    # ── Session 1: save context ───────────────────────────────────────────────
    cat > "$CTX_FILE" <<'EOF'
{"agent": "hello-world", "step": 1, "memory": ["first run"]}
EOF
    echo "Uploading context…"
    MAGNET=$(curl -sf -X POST "$SHARD/api/files/upload" \
        -F "file=@$CTX_FILE" | json_field magnet)
    echo "$MAGNET" > "$MAGNET_FILE"
    rm -f "$CTX_FILE"

    echo "[OK] Context saved."
    echo "Magnet: $MAGNET"
    echo "Run again to restore it."

else
    # ── Session 2: restore context ────────────────────────────────────────────
    MAGNET=$(cat "$MAGNET_FILE")
    echo "Restoring context…"
    echo "$MAGNET"
    RESULT=$(curl -sf -X POST "$SHARD/api/files/download" \
        -H "Content-Type: application/json" \
        -d "{\"magnet\": \"$MAGNET\"}" | json_field path)

    echo "[OK] Restored to: $RESULT"
    cat "$RESULT"
    rm -f "$MAGNET_FILE"
    echo "Magnet file removed — next run starts fresh."
fi
