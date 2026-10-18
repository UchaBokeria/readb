# Status

October18. Development build0.2.0. No stable release or device cutover.

## Live

Blackwall has an active **empty staging server**, running77406f5 code. Existing
interface/systemd setup passed twice without restarting either staged service.
Web is off. Original WireGuard peers/config and legacy device services remain.
PC device access still uses the canonical Blackwall Quest/Pixel routes.

New controller-proxy source is not installed. Never replace a binary-bound setup
journal or remove legacy services to bypass an upgrade/acceptance gate.

## Source

- Rust multi-device coordinator, CLI/local+SSH contexts, private imports/tickets,
  shared viewers, one controller/device, durable cancellation/restart fences.
- Pinned isolated secure ADB servers, report replay/downgrade guards, telemetry,
  keepalive policy, actions, history/logs, optional authenticated dashboard.
- Existing-interface systemd setup: protected root policy/helper, selected-user
  installer, durable file/activation recovery and saved-provider verification.
- Root helper: bounded peer policy, unrelated-peer preservation, durable intents,
  per-peer restoration, route events and periodic recovery. Minimal capabilities.
- Controller network proxy: exact device/ticket preflight, durable operation,
  one-use request proof, fixed credential-checked root callback and typed outcomes.
  CLI follows the selected context; root maintenance remains explicitly local.
- Private upgrade-marker storage: exact upgrade/config binding, no-replace
  publication, private-file admission and explicit matching resume. Runtime
  registry/daemon enforcement is still pending.
- Android companion/JNI: encrypted profile/storage, embedded WireGuard, reporting,
  permission UI and Quest panel source. Development APK exists; migration pending.

## Evidence

243host and243Rust1.88/musl workspace tests, fmt/Clippy passed for4f93874.
Independent whole-proxy review found no important source issue. Actual SSH fixture
passed two-host viewers, correct controller conflict and older-helper refusal
before intent. All leases released; transient unit stopped; live PIDs unchanged.

Actual Blackwall private mount/network namespace passed restricted-root callback,
unsafe ownership/path refusal, competing binder refusal and inode-safe cleanup.
Helper-runtime replacement regression reproduced a stranded callback, then passed
with periodic directory/socket identity checking and rebind. Full243host+243MSRV,
fmt/Clippy pass for that fix too. Neither source slice is deployed.

Android JNI,16KiB packaging, six encrypted-storage checks and Quest panel captures
passed earlier development checks. Those do not prove profile/VPN handover, current
headset connectivity, unattended first unlock or release readiness.

## Next gates

1. Journaled managed upgrade and saved-provider admission for exact managed peers.
2. Authenticated one-use encrypted old/new Android UID handover; preserve PIN/keys.
3. Actual Quest and Pixel permission/VPN/report/port/UI/boot/cutover/rollback checks.
4. Fresh-interface/dependency/init support, configured four-agent behavior smokes,
   stable signing/notices/release assets, then scoped legacy cleanup.

Protected unattended Quest first unlock/debugging consent remains unproved.
Keep requested awake/unlocked policy separate from observed OS status.

Design: design.md. Android: android.md. Root boundary: network.md. Setup: setup.md.
Full owner migration plan/evidence: cloud/docs/readb-design.md and
cloud/docs/readb-implementation.md. Earlier development snapshots remain in Git.

Maintenance storage prerequisite passes249host+249Rust1.88/musl, fmt/Clippy.
It is a storage library, not an active upgrade barrier or a deployed upgrade.
