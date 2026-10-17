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
