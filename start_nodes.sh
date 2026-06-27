#!/usr/bin/env bash
set -euo pipefail

N=${1:-15}
BASE_PORT=4201
LOG_DIR="/tmp/shard_network"
PID_FILE="$LOG_DIR/pids"
BINARY="./dist/shard-cli"

if [ ! -x "$BINARY" ]; then
    echo "error: $BINARY not found or not executable"
    exit 1
fi

mkdir -p "$LOG_DIR"
> "$PID_FILE"

echo "Starting $N shard nodes on ports $BASE_PORT–$((BASE_PORT + N - 1))..."

for i in $(seq 1 "$N"); do
    PORT=$((BASE_PORT + i - 1))

    # Feed stdin: wait for bootstrap, join general, say hello, then idle
    (
        sleep 5
        echo "/join general"
        sleep 1
        echo "Hello from shard node :$PORT"
        while true; do sleep 3600; done
    ) | "$BINARY" --port "$PORT" > "$LOG_DIR/node_$PORT.log" 2>&1 &

    echo $! >> "$PID_FILE"
    printf "  node :%d started (PID %d)\n" "$PORT" "$!"
done

echo ""
echo "$N nodes running — logs: $LOG_DIR/node_<port>.log"
echo "Stop with: ./stop_nodes.sh"
