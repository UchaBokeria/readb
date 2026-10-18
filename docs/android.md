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

## Packaging metadata checkpoint

October17: pinned tunnel1.0.20260102 POM declares Apache2.0, annotation1.9.1
and collection1.5.0. Collection-jvm1.5.0 dependency management and annotation-jvm
1.9.1 both resolve Kotlin stdlib1.9.24, matching the manual build pins. This is
metadata verification, not complete APK/native transitive notice acceptance.
Audit exact embedded Go modules, retain all notices and package them before a
stable release; do not replace the upstream licenses with readb's custom terms.

Sources: [tunnel POM](https://repo.maven.apache.org/maven2/com/wireguard/android/tunnel/1.0.20260102/tunnel-1.0.20260102.pom),
[collection POM](https://dl.google.com/dl/android/maven2/androidx/collection/collection-jvm/1.5.0/collection-jvm-1.5.0.pom),
[annotation POM](https://dl.google.com/dl/android/maven2/androidx/annotation/annotation-jvm/1.9.1/annotation-jvm-1.9.1.pom).

## App-window capture (development only)

Build with `--ui-checks`. The test APK includes `.UiChecks`; ordinary builds omit
it. Run synchronously under the device controller:

```sh
quest-adb --ticket "$JOB_TICKET" shell am instrument -w dev.readb.companion/.UiChecks
quest-adb --ticket "$JOB_TICKET" shell am instrument -w -e section bottom dev.readb.companion/.UiChecks
```

Requires no enrolled profile. It launches only readb, checks document readiness,
horizontal overflow and44px targets, then copies its actual hardware window with
[PixelCopy](https://developer.android.com/reference/android/view/PixelCopy). The
result contains a bounded `png_base64` capture; save privately and inspect it.
It closes its test activity and does not import profiles, grant permissions or
start a VPN/report service. Capture is window-content evidence, not hand comfort,
headset positioning, protected unlock or reboot acceptance.
