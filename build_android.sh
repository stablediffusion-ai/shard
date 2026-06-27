#!/bin/sh
set -e

IMAGE="shard-android-builder"
JNILIBS="android/app/src/main/jniLibs"

echo "==> Building Docker image..."
docker build -f Dockerfile.android -t "$IMAGE" .

echo "==> Cross-compiling Rust for Android ARM targets..."
docker run --rm \
    -v "$(pwd)":/app \
    -w /app \
    "$IMAGE" \
    cargo ndk \
        -t arm64-v8a \
        -t armeabi-v7a \
        --platform 26 \
        build --release --bin shard-gui

echo "==> Copying binaries to jniLibs (as .so for Android W^X compatibility)..."
mkdir -p "$JNILIBS/arm64-v8a" "$JNILIBS/armeabi-v7a"

cp target/aarch64-linux-android/release/shard-gui   "$JNILIBS/arm64-v8a/libshard-gui.so"
cp target/armv7-linux-androideabi/release/shard-gui  "$JNILIBS/armeabi-v7a/libshard-gui.so"

echo "==> Rust binaries ready."
echo "    arm64-v8a:    $(du -sh "$JNILIBS/arm64-v8a/libshard-gui.so"   | cut -f1)"
echo "    armeabi-v7a:  $(du -sh "$JNILIBS/armeabi-v7a/libshard-gui.so" | cut -f1)"

echo "==> Building APK Docker image..."
docker build -f Dockerfile.apk -t shard-apk-builder .

echo "==> Building APK with Gradle..."
docker run --rm \
    -v "$(pwd)/android":/app \
    -v shard-gradle-cache:/root/.gradle \
    -w /app \
    shard-apk-builder \
    gradle assembleDebug

echo ""
echo "==> APK ready:"
echo "    android/app/build/outputs/apk/debug/app-debug.apk"
