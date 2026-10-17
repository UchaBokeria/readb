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
