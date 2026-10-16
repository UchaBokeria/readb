# readb

Read docs/status.md and docs/design.md before work.
Rust remote Android ADB manager. PC clients go through the configured server.
Preserve pairing, identity pins, private state and unrelated VPN peers.
Shared viewers; one controller per device. Never bypass busy or unknown cleanup.
No public credentials, device serials, private reports or enrollment tokens.
Web off by default. Keep requested awake policy separate from real unlocked status.
Use cargo fmt --check, cargo test --locked and cargo clippy --all-targets -- -D warnings.
Public code is noncommercial; dependencies keep their licenses.
Keep README short. Design/history in docs/. Real device proof is separate from tests.

Android source/build/acceptance: docs/android.md. Run workspace tests and
scripts/test-android-jni.sh; the packager must reject4KiB-only JNI libraries.
APK builds do not prove locked boot, VPN handover or Quest screen unlock.
