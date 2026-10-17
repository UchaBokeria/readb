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

The private phase journal is library infrastructure, not an apply command yet.
It binds the plan SHA, serializes writers and records ordered running/completed
phases durably. An interrupted phase cannot complete through a new handle.
Reconciliation, owned-file receipts, root network helper and full apply remain
pending. Keep old services until replacement acceptance and rollback checks pass.

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
