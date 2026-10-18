# Legacy Android handover

Development source. Nothing here proves a device migration or enables a VPN.
Owner Android review comes first. Do not install upgraded legacy helpers or start
handover until the owner review and certificate checks pass.

## Small boundary

`HandoverClient.importFrom(context, SOURCE_PACKAGE)` is an explicit future UI call.
It is not called from startup, a broadcast, WebView or the current app screen.
Source is only `dev.quickshard.adblink` or `dev.hermes.pixeladbhelper`.

Both packages verify the other's actual current signing certificate. The exporter
checks the real Binder calling UID on **every** transaction, rejects shared UIDs,
and accepts only `dev.readb.companion`. The client binds the exact source component.
Missing/incorrect public certificate pins fail closed. A signature permission is
insufficient: the three packages have separate signing keys.

The recipient creates a persistent Android Keystore RSA3072 key and a random32-byte
nonce. AES256-GCM encrypts the payload; RSA-OAEP SHA256/MGF1-SHA1 wraps only the
random AES key (explicit identical parameters for Android compatibility). AAD
binds both packages/certificate digests and the complete recipient request.
Binder carries ciphertext. No plaintext shared-storage file, shell argument or log.

One exporter journal retains the exact request and encrypted response. Persist and
sync it before returning. Data is explicitly fsynced before AtomicFile completion;
exact committed-byte readback detects a rename/sync failure AtomicFile only logs. The same request recovers a lost reply; another request
is refused. ACK must match request plus ciphertext SHA256. ACK is durable and
idempotent; old data is retained. The recipient atomically saves its reencrypted
payload and receipt together before ACK, then records ACK completion. Failed
writes never authorize a different recipient/enrollment. Reads confirm directory
sync before accepting a record left visible after an uncertain write.

The client runs off the main thread, allows one local handover at a time and times
out the UI response without claiming the underlying Binder operation stopped.
It retains the active-operation barrier until the worker actually exits. Retry
uses the stored request. Existing enrollment is preserved; imported material goes
into a **separate** AES-GCM/Keystore recovery store, not active ProfileStore.
No import enables old opt-ins, grants OS permissions or starts services.

## Different sources

Quest exports its embedded VPN profile, report token/enable flag, separately
stored PIN/presence/enable flag, VPN enable flag and exact consent fields:
`enabled`, `wake_on_connect`, `ssid_sha256`, `bssid_sha256`.
The new PIN export accessor reads a disabled saved credential without enabling it.
No wildcard-network consent and no reset of previous opt-ins. Legacy encrypted
files and Keystore keys remain for rollback.

Pixel exports only its report token and reporter-enabled flag. Its VPN belongs to
the separate WireGuard app; that helper cannot export its key. Preserve that app,
old peer and server-side TLS ADB keys. readb enrollment gets its own managed peer
only during separately approved/verified cutover. Quest's old `.5` profile may be
retained as rollback material; do not silently adopt it into managed `.100–.150`.

New readb has no active PIN/accessibility-consent implementation. Import preserves
those records; it does not claim automatic Quest unlock, inherited accessibility
permission, inherited VPN consent, debugging approval or unattended boot recovery.

## Build and acceptance

Ordinary builds contain no trust asset. Export services are disabled in both
legacy manifests. readb `android/build.py --handover-trust FILE` embeds explicit
public `package.name=lowercase_sha256_certificate` pins; no default owner pins.
Quest helper accepts the same file through explicit `READB_HANDOVER_TRUST` env.
Service enablement remains an explicit device acceptance step after verification.
Do not change the development signing keys. All three existing private PC
keystores were readable on October18; that is not installed-signature equality.
Verify installed package certificates against the built APKs before any upgrade.

Host checks: `python scripts/test-android-handover.py` tests encryption/bounds,
wrong key/nonce/AAD, corruption/trailing data, strong key requirements and durable
one-request export/ACK recovery with injected lost acknowledgements.
Android: build `--handover-checks`, run `.HandoverChecks` synchronously after review.
It uses isolated random fixture stores and synthetic credentials, never exporters,
real profiles, VPNs or phone settings. Actual Keystore/fsync/device checks remain
pending until that runner is installed and executed. Helper-source copies share
the same protocol; compare them before packaging an export build.

Current blocker: Hermes PC quota guard is latched paused. Pixel helper source
additions are preserved but **not completed or built**; its shared Android file
still needs the readb/Quest fsync compatibility fix and build trust-asset wiring
when that guard admits work. Do not switch hosts to bypass it. Source compilation
and host tests do not authorize device migration or legacy cleanup.

## October18 source evidence

Host crypto11 + one-use journal10 checks passed. Journal fault tests cover an
export/ACK write that becomes visible before a simulated lost acknowledgement;
restart returns the same encrypted response, never reads plaintext again, and
refuses a different request, wrong ACK/binding and truncated record. Readb Android
sources plus synthetic HandoverChecks compile with SDK36; Quest helper sources
compile too. The existing Quest VPN/consent/bench runtime suite passed, including
26 production-controller fixtures. Shared readb/Quest Java source parity passed.
These are source/host proofs; no source APK or exporter was installed for this
work. Device Keystore, Binder certificate equality and actual UID transfer are
still acceptance gates. Keep recipient request/key until recovery completes; a
new request cannot bypass the exporter journal after reinstall/data loss.
