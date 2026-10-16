# CLI

Build: `cargo build --locked`. Rust1.88+. Tested locally with1.98.
Run `readb --help`. Every command group has help.

Choose a server:

```sh
readb context add lab --ssh SERVER --state /absolute/private/state
readb context use lab
readb device ls
readb --device phone device inspect
```

Claim before device commands. Use real agent, host, session and job names.
The reply gives a private ticket file on this computer.

```sh
readb --device phone job claim --agent codex --origin laptop --session SESSION --job screenshots --mode view
readb --device phone --ticket FILE action run screenshot > screen.png
readb --device phone --ticket FILE job release
```

Use control mode for input, installs and transfers. Viewers share read profiles.
File paths passed to pull/push/install are server paths. Screenshot stdout is local.
Heartbeat every30s during review. Default expiry90s. Busy means wait or coordinate.
Unknown cleanup needs evidence; do not remove journals or steal another job.

```sh
readb history --limit 50
readb --device phone logs -f
readb device ls -q | xargs -r -I{} readb --device {} device inspect
readb install --client --dry-run
readb skill install codex  # also claude, opencode, hermes, all
```

Logs are redacted coordinator JSONL. `action run logs` reads Android logcat.
`logs --since` takes Unix seconds. Web stays off until `dashboard enable`.
Web is loopback-only. Tunnel it through SSH. Read its private key on the server;
never put that key in a URL or public chat.

First enrollment is still a manual development flow: import a private600 device
JSON with `device add --file FILE`, claim control, `device pair --port PORT` (code
on stdin), then `device connect --port PORT`. Review its fingerprint and use
`device trust --fingerprint SHA256 --yes`. No normal commands before fresh pin.
A signed companion and complete onboarding installer are not released yet.

`device disconnect` pauses automatic reconnect for that device; `device connect`
resumes it. `device rm --yes` retains its private files and requires a controller.
Reusing a removed ID with retained keys needs explicit recovery; use a new ID.
