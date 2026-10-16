#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:=$PWD/build/cargo}"
export CARGO_TARGET_DIR
cargo build --locked -p readb-android-core
classes=$(mktemp -d)
trap 'rm -rf "$classes"' EXIT HUP INT TERM
javac -d "$classes" android/src/dev/readb/companion/NativeBridge.java android/tests/NativeBridgeSmoke.java android/src/dev/readb/companion/ServiceTracker.java android/tests/ServiceTrackerTest.java
java --enable-native-access=ALL-UNNAMED -Xcheck:jni -Djava.library.path="$CARGO_TARGET_DIR/debug" -cp "$classes" NativeBridgeSmoke
java -cp "$classes" ServiceTrackerTest
