# Report firewall

Status: pure admission code only. No broker is installed. No rules are changed.
A successful unit test is not proof that a phone can report.

## Why

A new device needs a narrow path to its report listener. Blackwall's current
network helper cannot write UFW state under its sandbox. Keep that helper and
its setup journals intact. Install a separate, bounded broker later.

The first supported adapter is intentionally narrow: active UFW 0.36.2,
iptables 1.8.10 nft backend, and a proven IPv4 INPUT path. Other hosts stop with
an actionable setup/unsupported reason. Never enable, reset or replace their
firewall automatically.

## Two gates

1. Before creating a peer: authenticate the installed broker and check the
   installed interface, server address, managed range and report-port scope.
   Until that broker exists, `prerequisite()` returns
   `report_firewall_setup_required`. No production positive capability exists.
2. After the peer is registered and the selected daemon owns the listener FD:
   derive the exact rule from root policy, root peer registry and the V2 catalog
   listener. Apply the bounded operation and save its durable receipt. Only then
   may profile delivery proceed. Listener configuration alone is not FD proof.

The rule permits inbound TCP on one interface, from one device IPv4/32, to one
server IPv4/32 and one report port. It binds the device ID, policy hash and peer
hash. No request accepts a command, executable path, wildcard, CIDR, protocol or
free-form firewall argument. A read-only enrollment preview is a proposal, not
this authority.

## Pure API

`report_firewall::ReportRule::from_bound` derives a serialize-only rule.
`Intent::ensure` refuses existing/foreign grants. `Intent::revoke` requires an
observed owned grant receipt; it cannot delete a free-form rule.

`Intent::observe` recognizes only the complete saved before or expected after
snapshot. Any other change fences recovery. An unchanged before-state is not
permission for an uncontrolled retry. The future broker must hold its own lock
and persist/fsync the full intent before effects.

Receipts are in-memory observations, not signed credentials or durable records.
`Receipt::check_current` checks the owned grant and its effective path in both
kernel and persistent views. Disjoint later device rules are allowed; shadowing,
missing/duplicate grants, foreign exact accepts and changed tool identity refuse.
Both APIs require a freshly rederived bound rule and refuse policy or peer
identity drift. The root registry/catalog are not kept current by this pure
module; the future authenticated adapter must fetch them again for each call.

## Snapshot contract

Only the future authenticated root parser may supply `HostFacts` and `Snapshot`.
Never accept these structures or a caller's boolean as a root capability over RPC.

The parser must:

- Resolve fixed tools through protected root-owned paths; open without following
  a final symlink, pin bytes/inode and recheck before execution. The normalized
  facts require regular single-link, non-writable, non-set-ID executables and
  protected ancestry. The fixed tools are `/usr/sbin/ufw` and
  `/usr/sbin/xtables-nft-multi`. UFW's Python interpreter, imported modules,
  ufw-init scripts and runtime dependencies also need protected provenance.
- Prove the actual installed versions and supported chain topology. Flatten the
  IPv4 NEW TCP INPUT evaluation path in order. Its insertion boundary is before
  the UFW user chain's terminal return/default. A target ACCEPT must be final
  for this path; additional nft hooks or chains with unmodeled semantics refuse.
- Preserve every included rule, order, predicate and comment in kernel and saved
  views. Unknown conditions remain unknown, never silently disjoint. Known
  nonmatching rules may be omitted only with their complete ordered semantics
  committed to `other_state`. Never map an unknown protocol or match to `Other`. A matching earlier DROP/REJECT shadows;
  an earlier foreign ACCEPT gives no readb ownership. Matching unknowns refuse.
- Hash all remaining relevant persistent/kernel state into `other_state`,
  excluding volatile counters/timestamps only. Include chain policies, hook
  priorities, non-modeled chains, IPv6 and UFW settings. The exact operation
  changes only one owned rule in each view; anything else is drift.

This module does not parse UFW output, inspect files, authenticate a socket,
execute a tool, install a listener or prove the above facts. Unsupported parser
coverage must stop admission. The synthetic tests establish logic only.

## Broker plan (not implemented)

A separate root socket service accepts only typed ensure/revoke requests from the
installed network controller. Check SO_PEERCRED, controller image, installed
policy and current registered peer. Reject unknown schemas/fields and any tuple
outside policy. Require the normal coordinator/maintenance gates and an actual
owned report-listener proof. Bind the one-use request to the full tuple digest.

Keep the current network helper's unit and original software-only ApplyPlan
contract unchanged. The broker gets only the exact UFW persistent/lock paths and
network capability proved by a private namespace/sandbox test. Do not grant an
arbitrary root shell or widen the existing helper's write paths. UFW's fixed
trusted scripts may run internally; no request can supply shell text.

UFW needs `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/run/ufw.lock` and the
xtables lock. Verify actual reads/writes on the supported host before committing
a service template. Do not hold UFW's lock while invoking its frontend: that
frontend takes the same lock. Use a broker transaction lock plus exact pre/post
snapshots to detect external administrative races. Never restore a whole old
firewall snapshot or delete an unowned rule during recovery.

The owned comment is `readb-report:<full rule SHA256>`. Do not adopt an identical
foreign rule or a matching comment with different semantics. Store pending intent
and fsync before applying; recheck fixed tools and policy, apply fixed typed argv,
then parse both views and persist the after receipt. Lost replies reconcile only
exact before/after. Unknown partial kernel/saved state fences with a useful reason.

## Acceptance still required

- Review the pure API and malicious/foreign/race fixtures.
- Implement the authenticated fixed-tool parser and additive broker installer.
- Prove exact sandbox file/capability needs in private namespaces.
- Test interrupted ensure/revoke and external rule races under actual UFW.
- Wire the pre-peer capability gate and post-peer/listener receipt phases into
  enrollment, with durable recovery and no profile handoff before readiness.
- Receive a real authenticated device report. A rule receipt or WireGuard
  handshake alone does not prove report reachability.

Do not touch the existing Pixel 10.99.0.3 / Quest 10.99.0.5 rules, legacy reporters, other UFW rules,
WireGuard interface or Tailscale while building this path.

## Checked 2026-10-19

Eight synthetic admission tests and all four crate doctests pass. Scoped Clippy,
format and diff checks pass. Fixtures cover fixed scope, foreign/duplicate rules,
shadowing, unknown matches, exact lost-reply recovery, unrelated drift, tool
provenance and stale policy/peer receipts. No runtime broker or UFW mutation was
tested or installed in this slice.
