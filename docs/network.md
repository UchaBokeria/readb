# Network helper

Development stage. Existing-interface root/user setup passed on a real staging
server. Device cutover, fresh provisioning and host-boot acceptance remain open.

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

On the server, the configured coordinator user can read status. Peer writes are
root maintenance only until controller-scoped integration is ready. Root operators
must honor the active device job; maintenance is not a way around another owner.

```sh
readb --local network status
sudo readb --local network enroll --id phone --key PUBLIC_KEY --address DEVICE_IP
sudo readb --local network rm phone
sudo readb --local network reconcile
# Root only: restore missing recorded peers
sudo readb --local network restore
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

135 workspace tests, Clippy and formatting pass. An isolated Blackwall network
namespace passed real root-helper RPC, unprivileged enrollment/removal, restart
state, adoption denial, unrelated-peer preservation and external-edit refusal.
No live VPN change, fresh install, boot restoration or device cutover is proved.

While running, the helper checks its pinned interface on startup, link/address
notifications and every30seconds. It restores at most one recorded missing peer
per pass. Events coalesce; the earliest next pass is2seconds after completion,
including slow failed probes. Without events, failures retry after5/10/20/40/60s.
Events can accelerate that backoff to the2second floor. Missing notification
support falls back to periodic checks. Status exposes the last error and next check.

Existing changed peers and conflicting external routes are left alone. A stopped
interface stays stopped; the helper never creates, rekeys or brings up an interface.
An unresolved intent keeps status/reconcile available and blocks automatic writes.
Ordinary clients cannot call either root restore entry point. Isolated namespace
tests prove link deletion/recreation, down/up, key mismatch, unrelated-peer
preservation and periodic recovery. No host or Android reboot was performed.

## Install helper files

Requires an existing private root policy at `/etc/readb/network-policy.json`.
This is one setup phase, not the complete fresh-server installer.

```sh
sudo readb --local network install --dry-run
sudo readb --local network install
# Only after an interrupted installation:
sudo readb --local network install-recover
```

Dry-run prints proposed paths/unit; filesystem admission still happens on install.
Install writes a root-owned hash-addressed binary, the unit and a private receipt.
It never starts a service or changes the VPN. Stop a running helper before upgrade.
Unknown units, changed owned releases/units, unsafe paths and symlinks are refused.
Source bytes come from the executing inode, not a replaceable user pathname.

Interrupted install blocks helper startup under the same state-directory lock.
Explicit recovery verifies recorded files and syncs them and directory links. It
commits a complete known install or restores its previous verified unit/receipt.
External changes stay fenced. Unused immutable releases and all device data stay.
Activation/unit-manager acceptance belongs to the next setup phase.

146 workspace tests, Clippy/fmt and focused review pass. All nine installer
filesystem tests also passed as root on Blackwall in isolated image directories.
The namespace helper passed with only CAP_NET_ADMIN and CAP_CHOWN. No production
unit installation/activation, host reboot, fresh setup or device cutover proved.

Runtime recovery is tested with fake kernels and a real isolated Blackwall network
namespace. Full helper-loop/service-manager restart acceptance remains a setup gate;
the namespace check does not prove production boot persistence. Kernel probes run
serially with bounded subprocesses; a slow operation can delay RPC replies. A lost
reply is unconfirmed completion: inspect status/pending intent before retrying.
Do not clear a fence or repeat a peer mutation merely because a client timed out.

Root policy creation is now a separate journaled library phase. It creates only
the canonical0600 policy, with atomic no-replace publication. A pending policy
blocks both helper startup and binary installation under their shared lock.
Recovery accepts only the recorded absent/exact file and before/after receipt;
external edits and root coordinator accounts are refused. It never starts a unit
or changes a peer. Setup CLI composition remains pending.

Development safety boundary (October18): direct non-root root-helper Apply and
Reconcile requests refuse with `network_controller_proxy_required`.
A matching UID is not a device controller lease. Root maintenance and status are
unchanged. Job-scoped coordinator integration is the next step; this is not yet
replacement enrollment acceptance. Keep existing device services running.

Controller proof (source, not deployed): coordinator journals a device operation
and retains its one-use nonce. Root checks it over the fixed authority socket
before a peer write. Both ends check kernel UIDs; proof/reply bind the exact
request digest. The callback permits no caller-selected path. Root retains only
NET_ADMIN+CHOWN. Missing authority refuses the request; ordinary ADB can still run.
A lost/ambiguous peer result requires reconciliation, never blind retry.
CLI integration and managed upgrade must pass before enabling this on devices.

Normal client network status/enroll/rm now use the selected coordinator context.
Enroll/rm require its actual device controller ticket; no direct client VPN/ADB.
The coordinator verifies device/ticket first, then root capability before writing
an intent. An older helper returns upgrade-required with no operation journal.
Root-only maintenance still requires explicit --local on the server.

```sh
readb network status
readb --ticket PRIVATE_TICKET network enroll --id DEVICE --key PUBLIC_KEY --address VPN_IP
readb --ticket PRIVATE_TICKET network rm DEVICE
```

Source checks include real SSH compatibility with the old installed helper; a
full new-helper managed upgrade is still required before production enrollment.

The authority server checks its held directory/socket identities once per second.
Helper RuntimeDirectory removal/recreation drops the stale binding and retries the
fixed path. It does not delete a different socket inode. A real restricted-root
namespace regression proved this recovery; legacy live services were unchanged.


Root upgrade admission can request `provider_baseline` over the protected helper
socket. It returns the exact policy SHA256, recorded devices and live external
snapshot. Only root may request it. A pending/poisoned manager, changed interface,
or missing/changed managed peer refuses. Exclusion uses exact recorded keys and
routes; an unknown in-range peer stays external. This is read-only evidence, not
an upgrade or permission to replace the saved baseline. The pending consumer must
verify helper identity/policy hash and compare the original saved external peers.

`setup_provider::inspect_managed` is the read-only consumer: it authenticates the
root socket, validates policy and complete live snapshot, runs the existing saved
VPN verifier on external peers, then rechecks helper evidence. Receipt shape stays
unchanged. Original `inspect` stays strict. The upgrade transaction must still bind
this receipt and baseline to the original setup proof before any stop or install.
