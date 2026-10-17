# Network helper

Development stage. Existing-interface reuse only. No live helper installed yet.
Fresh provisioning and boot restoration are still pending.

The coordinator stays unprivileged. A separate root helper accepts typed peer
requests on `/run/readb-network/control.sock`. It admits root or one configured
UID using kernel socket credentials. It cannot run a supplied shell command,
change endpoints/private keys, replace an interface or remove an unrecorded peer.

Root policy pins the interface, server public key, IPv4/prefix and a dedicated
address range. New peers get one /32. Conflicting keys, overlapping AllowedIPs,
changed managed peers and changed interface identity stop the operation.
Existing unrelated peers stay outside the managed manifest. No automatic adoption.

Root-owned policy: `/etc/readb/network-policy.json` (0600, protected parent).
Root state: `/var/lib/readb-network` (0700). Every state ancestor must be root-owned
without group/world writes. Run a root-owned immutable binary outside user-writable
paths. The ordinary user installer does not install this helper yet.

```sh
readb --local network helper --policy /etc/readb/network-policy.json \
  --state /var/lib/readb-network
```

Policy fields: schema1, uid, interface, server_key, server_address, prefix, first,
last. The enrollment range must stay within one private subnet and exclude the
server, network and broadcast addresses. Supply the real server public key.
No private keys belong in requests or policy.

On the server, as the configured coordinator user:

```sh
readb --local network status
readb --local network enroll --id phone --key PUBLIC_KEY --address DEVICE_IP
readb --local network rm phone
readb --local network reconcile
```

PC users reach the server over SSH. This command does not create client VPN/ADB
transport. Normal enrollment must also coordinate device jobs before switching
an active device; this helper alone does not grant that authorization.

A durable intent precedes kernel changes. Full before/after peer snapshots must
match before clearing it. Storage, command or verification uncertainty fences
further changes across restart. Explicit reconcile accepts only the recorded
before or after state. It never automatically rolls back an external edit.
Root operators must coordinate direct WireGuard edits; the kernel has no atomic
compare-and-set for a whole peer snapshot. Post-write drift is detected and fenced.

132 workspace tests, Clippy and formatting pass. An isolated Blackwall network
namespace passed real root-helper RPC, unprivileged enrollment/removal, restart
state, adoption denial, unrelated-peer preservation and external-edit refusal.
No live VPN change, fresh install, boot restoration or device cutover is proved.
