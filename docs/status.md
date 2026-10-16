# Status

October16, development build0.2.0. No production readb service or public release yet.

Working locally: multi-device registry and private imports, shared viewers/one
controller, cleanup fences, local/SSH contexts, private tickets, binary streams,
action catalog, pairing over private stdin, history/log follow, dashboard and
user service/client installer. Browser checks used isolated fixtures.

First identity review/trust and pause/reconnect work in local tests.

Pending: complete fresh-server/VPN installer,
full config and dashboard onboarding, Android companion, two-host cutover,
release/submodule and agent behavior checks. Old Quest/Pixel services stay live.
Builds and fixtures do not prove device acceptance.

Local checks:69 Rust tests, Clippy with warnings denied, rustfmt and JS syntax.
RustSec checked41 locked dependencies with no known advisory reported. Independent
reviews fixed RPC truncation, dashboard restart, ADB environment routing, key
durability, review-job binding and cancelled-prompt TTY input retention.

The concise skill passed syntax and a simulated reference/help check. Actual
Codex/Claude/OpenCode/Hermes device behavior checks are still pending.
