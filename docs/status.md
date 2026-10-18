# Status

October18. Development build0.2.0. No stable release or device cutover.

## Live

Blackwall has an active **empty staging server**, running77406f5 code. Existing
interface/systemd setup passed twice without restarting either staged service.
The owner enabled its optional dashboard separately. Original WireGuard
peers/config and legacy device services remain.
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
- Upgrade maintenance barrier: exact upgrade/config marker, catalog/transport/
  state idle admission, cached backend guards, restart enforcement and local
  prepare/resume CLI. Diagnosis stays available.
- Empty-staging software upgrade: original completed setup/image/provider binding,
  journaled maintenance/stop/install/start/rebind/release, old-server frozen
  bootstrap, exact interrupted-phase recovery and read-only original admission.
  No device migration or VPN restart. General nonempty upgrade/rollback pending.
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

Full checklist: [release gates](acceptance.md).

1. Reviewed empty-staging live upgrade; general managed-device upgrade/rollback.
2. Authenticated one-use encrypted old/new Android UID handover; preserve PIN/keys.
3. Actual Quest and Pixel permission/VPN/report/port/UI/boot/cutover/rollback checks.
4. Fresh-interface/dependency/init support, configured four-agent behavior smokes,
   stable signing/notices/release assets, then scoped legacy cleanup.

Protected unattended Quest first unlock/debugging consent remains unproved.
Keep requested awake/unlocked policy separate from observed OS status.

Design: design.md. Android: android.md. Root boundary: network.md. Setup: setup.md.
Full owner migration plan/evidence: cloud/docs/readb-design.md and
cloud/docs/readb-implementation.md. Earlier development snapshots remain in Git.

Maintenance runtime/CLI passes260host+260Rust1.88/musl tests, fmt/Clippy.
Actual isolated SSH proof passed controller/viewer refusal, persisted barrier
through service restart, wrong-owner refusal and exact resume/new claim. Fixture
stopped; live service PIDs unchanged. No live upgrade deployed.

Root-only provider-baseline evidence API passes264host+264Rust1.88/musl tests,
fmt/Clippy and scoped review. Actual root SO_PEERCRED RPC passed in private
mount/network namespaces with a synthetic kernel. Exact recorded healthy peers
alone are excluded; unknown peers and pending/drift remain fail-closed. Proof
executables removed; live user-service PIDs unchanged. Root upgrade consumer and
saved-baseline binding are still pending. No provider/peer/device was migrated.

Managed-provider consumer now passes266host+266Rust1.88/musl, fmt/Clippy and
independent review. It authenticates helper evidence, binds policy and complete
current snapshot, verifies the saved external state and rechecks evidence before
return. Original strict inspection/receipt shape remain unchanged. The root
transaction still must bind the original setup journal/provider and serialize
maintenance/install/start/binding/release; no live upgrade is implied.

Empty-staging upgrade source passes287host+287Rust1.88/musl workspace tests and
full fmt/Clippy. A private Blackwall mount/network fixture ran real old/new
coordinator/helper processes against a synthetic manager/kernel. Clean upgrade,
lost freeze/stop/start replies and a catalog edit during freeze all passed;
original setup/config stayed intact and healthy repeats made no manager changes.
Actual systemd disposable sole-process freeze/stop passed separately. Actual host
read-only original-plan admission passed without changing protected files/peers
or creating upgrade intent. These are distinct from a live staging cutover.

Empty-staging rollback source now preserves a separate image-bound progress
stream and the original forward evidence. Old coordinator starts only after
restored files, helper, original setup binding and durable marker release.
A saved release/start acknowledgement can recover without stopping later work.
Protected pinned candidate input covers interruptions before the new release
was retained. General nonempty upgrade/rollback and live cutover remain open.

Final native291 tests, full fmt/Clippy and scoped independent review pass.
Immutable portablecc182b0d passed nine private namespace scenarios: clean;
early forward interruption; partial user installer/helper start; lost stop,
helper/final start and marker release replies; later real catalog work preserved.
The saved-release recovery finding was reproduced and fixed. One fixture stop
exceeded its simplified12s manager timeout; evidence was retained and the bounded
owned-process kill path brought it in line with the real unit stop contract.
Full Rust1.88/musl release workspace291 tests also pass. No live upgrade,
device migration, VPN change or host reboot was performed by these checks.

## First-use work — October19

Pixel appearance accepted. The owner’s next gate is a real fresh-user setup,
without importing a profile file. Native HTTPS address/code entry, resume/cancel,
encrypted storage/final receipt and confirmed bootstrap-address correction are
in source. Dashboard has Add device UI. Server invitation/HTTP/effect adapters
and authenticated report-firewall broker are in implementation. Not deployed or
accepted on a device. Legacy routes remain canonical.

Native HTTPS passed real local TLS rejection/redirect/bounds/cancel tests.
Storage passed fault/recovery tests; these do not prove Android Keystore delivery.
Combined core71f773e portablec9d0f2bc passed14 isolated forward/rollback scenarios.
No live upgrade from these checks. See [first-use plan](enrollment-first-user.md)
and [release gates](acceptance.md). Owner Chrome extension currently unavailable;
new dashboard visual review is blocked. No fallback browser was used.
