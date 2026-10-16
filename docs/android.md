# Android companion

Development only. Not the live Quest/Pixel helper yet.

Rust owns report validation, ordering and retry timing. Java owns Android Keystore,
NSD, permissions, boot and the embedded official WireGuard backend. The UI uses
the dashboard theme. No separate WireGuard app is needed.

Reports start with no cached port. Startup is immediate; periodic checks run every
20 seconds. Port/network events accelerate the next report, with a 5-second minimum
between attempts. Failures retry after 5, 10, 20, 40 and then 60 seconds. Android can
delay service execution. The dashboard must show actual report age.

Enrollment permits one private IPv4 server route, never a default route. Reports
bind to the matching VPN network and never follow HTTP redirects. TLS ADB remains
paired and pinned by the server. The inner report uses HTTP inside WireGuard.
Profile ciphertext is device-protected; its AES-GCM key stays in Android Keystore.
The private enrollment file itself contains secrets: keep it private and remove it
from shared storage after import. An encrypted old-helper handover is still pending.

A saved profile does not start the VPN. Start requests Android VPN consent. It can
replace another active Android VPN. Stop keeps the encrypted profile and pairing.
New enrollment is refused while services are enabled or cleanup is still running.

Credential storage availability is not proof of Quest VR unlock. The companion
reports Quest screen-lock state as unknown. Server keepalive does not bypass a PIN.
Protected reboot unlock and new-network wireless-debugging consent remain open.

## Build

Needs JDK, Android SDK36/build-tools36.0.0, Linux x86_64 NDK27 and Rust1.95.0.
The script installs only checksum-pinned target libraries into its private build
directory. It does not modify your Rust toolchain.

```sh
scripts/build-android-core.py --toolchain PATH_TO_RUST_1_95 --ndk PATH_TO_NDK27
android/build.py --sdk PATH_TO_ANDROID_SDK --native-lib build/android-core/cargo/aarch64-linux-android/release/libreadb_android_core.so
scripts/test-android-jni.sh
scripts/preview-companion.py
```

The packager rejects wrong-architecture and4KiB-only native libraries; both JNI
libraries and the APK ZIP layout must support16KiB pages.

The APK has a separate development signing key under ignored build output.
This is not a stable release signature. Keep that key for development upgrades.
Use `--storage-checks` to include development-only storage instrumentation. That
runner uses a synthetic profile, restores prior ciphertext and starts no VPN.
Run synchronously through the device controller; never launch it in the background.

Before live migration: encrypted old-profile handover, platform permission checks,
real device storage/upgrade/boot/UI tests, signed release and Android dependency
notice audit. Keep the old helpers and paired server until acceptance passes.

References: [JNI](https://docs.rs/jni/0.22.4/jni/),
[Android VPN](https://developer.android.com/develop/connectivity/vpn),
[local network permissions](https://developer.android.com/privacy-and-security/local-network-permission).
The current build targets API36. Revisit local-network permission flows before
raising it to API37; do not claim modern permission acceptance from compilation.

## Current device evidence

October17: development arm64 APK installed/upgraded on Quest API34. Six storage
checks passed before and after16KiB rebuild. No real profile or transport switch.
The normal non-waiting launch returned successfully; no app crash was recorded.
Capture was black and input reported no focused app/window. Browser layout checks
are separate; headset visual/hand acceptance remains open. Avoid waiting for a
headless Quest activity to resume with am start -W; it timed out in this test.
