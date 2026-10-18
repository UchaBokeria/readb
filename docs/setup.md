# Server setup

Development stage. The plan command is read-only. It does not install tools,
accept SDK terms, create a VPN, pair devices or replace a service.

Run on the server:

```sh
readb --local setup plan --endpoint vpn.example.org:51820
```

Existing VPN: pass its real settings and `--reuse-interface`. Example:

```sh
readb --local setup plan --endpoint vpn.example.org:51820 \
  --reuse-interface --interface mobile --address 10.99.0.2 --prefix 24
```

JSON goes to stdout. Exit0 means this preflight found no blockers; exit78 means
read the blockers and next steps. This is not installation or device acceptance.
Checks are a snapshot; apply must recheck them before any mutation.

A plan has a stable SHA of its schema and requested settings. Changing free space
or connection state does not change that identity. Missing evidence blocks
readiness. Reuse checks actual WireGuard type, server address/prefix and listener.
It never replaces existing interface keys, peers or routes.

The private phase journal binds exact inputs and serializes writers. Root files
can be installed separately, or activated with the existing-interface systemd
adapter below. Fresh-server creation remains unfinished. Interrupted phases need
explicit recovery. Keep old services until real
replacement acceptance and rollback checks pass.

PC clients keep using their SSH context. Never set up direct device transport
on a client as a fallback. Web stays off by default.

## Interrupted catalog writes

Add, remove and trust changes use a private journal. An uncertain write blocks
further catalog changes with `catalog_cleanup_unknown`; existing device jobs
remain available. Stop the daemon before recovery. On the server:

```sh
readb --local --state-dir /absolute/state config recover --file /absolute/server.json
```

Use the original config and state paths. Recovery accepts only the recorded
before/after file hash; it never overwrites another edit. It preserves keys and
removes only known empty, uncommitted device directories. Start the daemon again
to load the config that actually reached disk. Other errors keep recovery fenced.

Keep the config private (0600), in an owned directory without other writers. A
hidden `.readb-state-*.json` marker binds each config to one state directory.
Leave that marker in place. This recovery does not clear a device cleanup fence.

## Bind a setup intent

For an existing interface, root can also bind the plan to its future service user
and an unused enrollment range:

```sh
sudo readb --local setup plan --endpoint vpn.example.org:51820 \
  --reuse-interface --interface mobile --address 10.99.0.2 \
  --user scriptkid --range-first 10.99.0.100 --range-last 10.99.0.150
```

Use your real endpoint and free range. This is still read-only. It validates the
passwd account, owned nonsymlink home, selected-user access, exact interface pin
and peer overlaps. The intent binds owner/home, network options, policy and the
executing binary hash. The peer observation has a separate baseline hash; apply
must inspect again. Root probes never execute tools from writable user paths.

## Install root files

Development phase for an existing systemd/WireGuard server. Repeat the bound plan
with `setup files` instead of `setup plan`. Requires root, `--local`, `--user`,
`--reuse-interface` and the same endpoint/range flags. This installs the private
policy and immutable helper/unit files. It does not activate a service, switch VPN
or enroll a device. JSON keeps those acceptance fields false.

An interruption needs the original binary and exact flags plus `--recover`.
Recovery validates each subordinate policy/binary intent and its owned artifacts
before replay. Another upgrade's intent or an external edit stays blocked. A
completed journal is rechecked against real files on every retry. Save the original
command privately; changing owner/home/range/endpoint/binary changes the binding.

Host boot also needs a real persistent network provider. An active interface alone
is insufficient; inspect its configuration and enabled boot unit before activation.

The selected-user execution library uses a sealed copy of the current ELF. Before
exec it sets the passwd groups and all UID/GID slots, clears capabilities, sets
no_new_privs and supplies a clean selected-user environment. It never runs a
user-writable binary as root. Timeout/errors report unconfirmed installation;
inspect the recorded phase before retry. Full setup orchestration is still pending.
Portable/local account limits and destination checks: [builds](build.md).

## Interrupted user installation

`readb install --client` and `readb install --server` now journal user files.
They never start or enable a service. Server mode reloads the existing user service
manager after writing its unit; the command link is published last. Full root-to-user
setup and live migration remain separate.

An interruption leaves private `~/.local/share/readb-installer/pending.json`.
Repeat the exact command and original binary with `--recover`. Changed plans,
external file edits or altered receipts remain fenced. Do not remove the intent.
The journal stores hashes, modes and paths, not configuration secrets. Existing
config stays unchanged; edited or unknown completions are preserved. A prior exact
receipt allows an owned completion upgrade.

Recovery syncs accepted files and parent directories before writing a receipt and
clearing intent. Failed cleanup restores the pending fence best-effort; broken
storage can prevent restoration, and the error explicitly requires inspection.
A successful file install is not service/network/device acceptance.

Bound setup also records the selected user's install destination. Use
`--install-dir /home/USER/opt/readb` or keep `~/.local/lib/readb`. The path must be
inside that passwd home. A changed path changes the recovery intent. The root
files phase still does not install user files or activate a service.

Post-activation code can inspect exact root policy/unit/release/receipts without
acquiring the running helper's exclusive state lock. This inspector writes nothing,
rejects pending intents and proves files only. It does not prove unit/process or
network health; full activation orchestration remains pending.

## Existing-interface activation (development)

`setup provider` checks saved WireGuard identity, peers and boot persistence.
It reads only. `setup apply --user USER --reuse-interface ...` then installs and
starts the narrow root helper and the selected user's empty coordinator.
It never restarts the VPN or enrolls a device. Web stays off.

The journal pins the binary, destination, user and original network evidence.
Every service action has an intent and an observed result. After interruption,
use the same command with `--recover`; changed files or network evidence block it.
An existing managed user release can upgrade only while its service is stopped.
Unknown installs stay untouched. Devices still need separate migration acceptance.

This adapter requires systemd, an enabled wg-quick provider and existing tools.
Fresh network creation, missing-tool installation and other init adapters remain
unfinished. Do not retire old device services after an empty-registry setup.


## Upgrade maintenance (development)

The coordinator can close admission before a verified upgrade. This does not
install files or stop a service. On the server, read `doctor` for the exact
`config_fingerprint`, then use the root upgrade plan's SHA256 identity:

```sh
readb --local maintenance prepare --upgrade UPGRADE_SHA256 --config CONFIG_SHA256
```

Active controllers, viewers, transport work and cleanup fences refuse preparation.
A private marker survives restart. Jobs, reports, keepalive transport and catalog
writes stay blocked; `doctor` stays available. Never cancel another job to upgrade.

`maintenance resume` takes the same two hashes. Use it only after the new files,
processes, provider and setup binding are verified and the root transaction has
saved its final release intent. It cannot undo shutdown. An unconfirmed resume
requires upgrade-journal diagnosis; marker absence alone does not prove success.
`maintenance resume --recover` confirms a lost removal acknowledgement only on
the same still-closed daemon with the exact cached owner. A fresh/open daemon
cannot use it to invent ownership. Root final-release recovery is separate.

## Empty-staging software upgrade

Use the candidate binary and the **same setup flags** as the original install:

```sh
readb --local setup upgrade --help
# Add the original endpoint, interface, user, range and install destination.
readb --local setup upgrade [original setup flags] --inspect
readb --local setup upgrade [original setup flags]
```

`--inspect` verifies the original completed journal, exact files/processes and
provider without creating upgrade intent. After an interrupted action, rerun the
exact candidate/flags with `--recover`. Do not discard or replace its evidence.

Only an empty server is supported here. A new daemon uses its maintenance RPC;
the older server needs an exact sole frozen process and an existing empty catalog
binding before offline marker publication. Busy, unknown, edited or nonempty
state refuses. New files/services and activation receipts are verified before
the new setup binding and final release. Old images/journal bytes stay retained.
No host reboot, VPN restart, device cutover or general rollback is performed.

## Empty-staging rollback

Use root on the server. Keep the original setup flags and recorded images.

```sh
readb --local setup rollback [original setup flags] --inspect
readb --local setup rollback [original setup flags]
# After interruption: same rollback binary and flags, plus --recover.
```

Rollback has its own durable progress. It preserves the forward journal, restores
old files and the original setup binding, releases maintenance, then starts the
old coordinator last. A lost reply never replays completed stops. An already
released old coordinator can keep its later catalog work; recovery does not
force it idle. Unknown edits or another maintenance owner block recovery.

If forward upgrade stopped before retaining its new release, add
`--upgrade-image /protected/path/readb`. That file must be root-owned, mode700,
under protected directories, and match the recorded image hash. A changed
retained release cannot use this fallback. No missing image is guessed.

Initial rollback supports empty staging only. It does not migrate devices,
restart a host/VPN, clear an unknown intent or discard earlier evidence.
