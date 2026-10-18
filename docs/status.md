# Status

October17, development build0.2.0. No production readb service or public release yet.

Working locally: multi-device registry and private imports, shared viewers/one
controller, cleanup fences, local/SSH contexts, private tickets, binary streams,
action catalog, pairing over private stdin, history/log follow, dashboard and
user service/client installer. Browser checks used isolated fixtures.

First identity review/trust and pause/reconnect work in local tests.

Pending: complete fresh-server/VPN installer,
full config and dashboard onboarding, Android companion, two-host cutover,
signed release and agent behavior checks. Old Quest/Pixel services stay live.
Builds and fixtures do not prove device acceptance.

Local checks:89 Rust tests, Clippy with warnings denied, rustfmt and JS syntax.
RustSec checked60 locked dependencies with no known advisory reported. Independent
reviews fixed RPC truncation, dashboard restart, ADB environment routing, key
durability, review-job binding and cancelled-prompt TTY input retention.

The concise skill passed syntax and a simulated reference/help check. Actual
Codex/Claude/OpenCode/Hermes device behavior checks are still pending.

Android branch adds strict V2/no-port reports, persisted replay/downgrade guards,
pure Rust report scheduling and a bounded JNI bridge. Host JVM smoke passed;
arm64 native build and development APK compile/sign/alignment checks passed.
Encrypted profile/VPN/report/UI source exists. Development APK installed on Quest
API34; six synthetic encrypted-storage checks passed with prior data restored.
Upgraded16KiB APK passed the same six storage checks. Non-waiting launch returns
normally, but Quest capture is black and input has no focused app/window; headset
visual acceptance remains blocked. No new VPN/report startup or real profile import. Desktop and390px preview checked through owner Chrome extension.
Source public main/submodule exist; no live readb cutover or stable release.
See android.md for build and pending platform acceptance.

Fresh setup foundation: `--local setup plan` now reports typed read-only preflight
with stable intent hash and named blockers. Existing-interface reuse checks actual
WireGuard type/address/listener; whole-subnet validation prevents public routes.
Private phase journal rejects concurrent writers, changed plans, unsafe paths and
completion of an interrupted phase after restart. No apply/root helper yet.
See setup.md; this is not fresh-server or replacement acceptance.

Actual Blackwall staging exposed missing isolated ADB-server startup. New code
adds owned lazy foreground server lifecycle, retained socket activation, child ACK,
per-device failure isolation and permanent shutdown/cancellation gates. Failed
manual pinned connect now returns an error.108 workspace tests and Clippy/fmt pass;
independent lifecycle review found no remaining scoped issue. New real two-host
retry is pending; this is not device acceptance. Catalog persistence retry/ambiguity
remains an explicit blocker before cutover.

Actual Blackwall staging with source2bf0b9a passed fresh secure pin and simultaneous
PC/Blackwall viewer reads with one controller. Competing controller got the real
owner/job conflict; observer-only profile denied a harmless non-profile command.
All leases released; transient service stopped and its isolated listener closed.
Legacy5038 stayed healthy. No companion/report/VPN or production service cutover.

Catalog durability/recovery now passes122 workspace tests, Clippy/fmt and focused
independent review. Intent is durable before staging; config/state binding is
atomic and unique; ordinary edits check baseline hashes. Uncertain writes fence
catalog changes. Offline recovery rejects active daemon, external edits and
unexpected filesystem errors, preserving keys. See setup.md. No live catalog
mutation or cutover acceptance; fresh setup/apply and helper handover remain.

Narrow root network helper: typed private Unix RPC with kernel UID admission,
root-owned policy/state ancestry, interface key/address pin, private /32 scope and
unrelated-peer preservation. Durable intent survives interrupted/ambiguous writes;
explicit reconcile accepts only recorded kernel snapshots.132 workspace tests and
Clippy/fmt pass. Real isolated Blackwall namespace passes enrollment/removal, helper
restart state, conflict and external-edit checks; live mobile unchanged. No live
helper install, boot restoration or fresh-server apply yet. See network.md.

Root-only per-peer restore now runs on helper startup. It restores only missing
recorded peers; present changed peers, address collisions and unresolved intent
stop it.135 workspace tests/Clippy/fmt and focused review pass. Blackwall namespace
smoke also proved missing-peer restoration across helper restart and user denial.
This simulates lost kernel peers; actual host/device reboot acceptance is pending.

Root-helper file installer adds fixed root paths, hash-addressed executable,
owned-file receipt, durable intent, offline recovery and startup fence under the
shared state lock. Unknown/external changes are preserved. It never activates a
service or alters VPN.146 workspace tests, Clippy/fmt and focused review pass;
Blackwall root image tests and capability-restricted namespace smoke pass.
Fresh setup/config creation and actual unit activation still pending.

Declared MSRV verified: Rust1.88.0 passed all146 workspace tests on the PC,
in addition to host Rust1.98 checks. Toolchain was checksum-verified and installed
only in ignored isolated build output; normal host/Android toolchains unchanged.

Setup intent prerequisite: selected passwd user/home/GID, executing binary, unused
enrollment range and exact server interface are bound by a read-only plan. Root
probes reject user-writable executables and test home access after dropping UID/GID.
155 workspace tests pass; final Clippy/fmt pass and focused review found no further
important issues. A root-owned temporary static candidate on Blackwall passed
existing-mobile plan checks using a clearly synthetic endpoint; no files installed,
service activated or peers changed. Production setup apply remains pending.

Root policy library phase adds durable no-replace creation, receipt and explicit
recovery with shared startup/install fencing.160 workspace tests, Clippy/fmt pass;
focused review found no important issue.14 installer/policy image tests also pass
as root on Blackwall with temporary root binary cleaned. No live root policy or
service installed. Setup composition and companion migration remain unfinished.

Composed files stage: `setup files` binds the root journal to the exact owner,
home, endpoint, policy and executing binary. Explicit recovery checks subordinate
intent scopes before consuming them and verifies real files/receipts.167 workspace
tests and Clippy/fmt pass; six composed filesystem tests pass as root on Blackwall.
No production readb files/units activated; full non-root coordinator setup,
root activation/runtime network recovery and device migration remain pending.

Selected-user installer runner now has a sealed executing-image path, revalidated
passwd/home/groups, dropped real/effective/saved IDs and capabilities, no_new_privs
and a cleared environment. Host168 tests and actual Blackwall root->scriptkid
probe pass. Portable Rust1.88 musl also passes168 workspace tests; the root probe
passes on Blackwall with no interpreter/NEEDED ELF dependencies. Local-only accounts
are the musl acceptance scope; native dynamic GNU supports host NSS.

A static glibc root probe aborted while loading Blackwall libnss_systemd; static
GNU builds are now rejected. Portable script selects musl. Direct SYS_renameat2
calls preserve no-replace semantics where the old musl CRT lacks a wrapper.
This runner is a library prerequisite: complete user-installer journaling, service
activation/persistence and live companion migration still remain.

Installer admission hardened:170 workspace tests/fmt/Clippy and focused review pass.
Unrelated units/configs survive rejected installs. Multi-file user journal remains
next; no production cutover. Quest2D panel candidate passes6storage checks and
1280x900 focus/frame, but actual panel visual capture remains unproved.

Quest actual-window top/bottom captures now pass development UiChecks and visual
review at1280x900; all6storage checks pass after upgrade. No real profile/VPN/report
activation. Hands/resize lifecycle, protected boot and migration acceptance remain.

User-file installer now has a private write-ahead transaction, exact explicit
`--recover`, owned completion receipts and receipt-bound before/after verification.
The command link publishes last; server file installs only reload, never start a
service. Review fixes cover recovered-file fsync, replaced receipts across restart
and best-effort pending-fence restoration after failed cleanup sync. Host182tests,
Rust1.88 musl182tests, JNI/stale-callback checks and fmt/Clippy pass. Full setup
activation, network runtime recovery and encrypted device migration remain open.

Portable4.2MB musl release passed isolated Blackwall user install/reload-failure/
explicit-recovery checks with temporary HOME and fake manager. No live service or
device change. Source c94a538; full migration gates above remain open.


October18 runtime recovery slice: route-netlink link/address events plus30second
periodic checks restore at most one recorded missing peer per pass. Notifications
coalesce with a2second floor after completion, including slow failures; event-free
failures back off5/10/20/40/60seconds. Changed identity/routes and pending intent
remain fenced. Down interfaces stay down. Status exposes recovery health.
Service-manager calls now have deadlines and bounded output; uncertain completion
requires inspecting actual state before retry. No new production unit is active.

Actual Blackwall isolated network namespace proved link deletion/recreation,
down/up, key mismatch, periodic fallback and unrelated-peer preservation. Global
mobile config/key/routes were unchanged and all namespace/root fixtures removed.
This tests manager/scheduler/kernel behavior, not the full production daemon loop,
boot persistence or device cutover. Full helper activation/controller scope remains
open. Review found a completion-cooldown bug; a failing regression preceded its fix.

Host191 and Rust1.88/musl191 workspace tests, Clippy and formatting pass.
