#!/bin/sh
# Build fully static Linux x86_64 binaries via Docker + musl.
# No glibc dependency — runs on any Linux x86_64 system (kernel 3.2+).
# Requires: Docker
# Output: dist/shard-cli  dist/shard-gui
set -e

VERSION="0.97.0"
DIST="dist"
TARGET="x86_64-unknown-linux-musl"

# Explicit --target so the output lands in target/$TARGET/release/
# and the binary is guaranteed musl-linked even if the host Rust toolchain
# defaults differ between Docker image versions.
CARGO_CMD="cargo build --release --target ${TARGET} --bin shard-cli --bin shard-gui"

echo "==> Building shard-cli and shard-gui"
echo "    target  : ${TARGET}"
echo "    version : ${VERSION}"
echo ""

docker run --rm \
    -v "$(pwd)":/app \
    -w /app \
    rust:alpine \
    sh -c "apk add --no-cache musl-dev && ${CARGO_CMD}"

echo ""
echo "==> Copying binaries to ${DIST}/..."
mkdir -p "$DIST"
cp "target/${TARGET}/release/shard-cli" "$DIST/shard-cli"
cp "target/${TARGET}/release/shard-gui" "$DIST/shard-gui"
chmod +x "$DIST/shard-cli" "$DIST/shard-gui"

echo "==> Verifying static linking..."
file "$DIST/shard-cli"
file "$DIST/shard-gui"
# Fail loudly if dynamic glibc crept in
if file "$DIST/shard-cli" | grep -q "dynamically linked"; then
    echo "ERROR: shard-cli is not statically linked — aborting." >&2
    exit 1
fi
if file "$DIST/shard-gui" | grep -q "dynamically linked"; then
    echo "ERROR: shard-gui is not statically linked — aborting." >&2
    exit 1
fi

echo ""
echo "==> SHA-256 checksums..."
sha256sum "$DIST/shard-cli" "$DIST/shard-gui"

echo ""
echo "==> Done."
echo "    $(du -sh "$DIST/shard-cli" | cut -f1)  dist/shard-cli"
echo "    $(du -sh "$DIST/shard-gui" | cut -f1)  dist/shard-gui"
echo ""
echo "    Update dist/index.html checksums and run: git add dist/ && git commit"
