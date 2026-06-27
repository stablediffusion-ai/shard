#!/usr/bin/env bash

LOG_DIR="/tmp/shard_network"
PID_FILE="$LOG_DIR/pids"

if [ ! -f "$PID_FILE" ]; then
    echo "No PID file at $PID_FILE — trying pkill fallback..."
    pkill -f "shard-cli --port 4[0-9][0-9][0-9]" && echo "Nodes killed." || echo "No running nodes found."
    exit 0
fi

COUNT=0
while IFS= read -r PID; do
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        ((COUNT++)) || true
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "Stopped $COUNT node(s)."
