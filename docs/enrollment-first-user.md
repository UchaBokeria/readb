# First device setup

Owner priority: URL + one-use code. No setup-file step by default.
Source plan only. Current preview cannot apply. No live acceptance yet.

## User path

1. Admin selects **Add device** in the dashboard, or CLI. Name + phone/Quest.
2. Server checks installed network/firewall policy and current upgrade fences.
   If setup is missing, stop here with the exact repair command. Do not give a
   code that promises a working profile when the broker is unavailable.
3. Show HTTPS server URL and a short-lived one-use setup code. Keep code out of
   URLs, access logs, history and normal status JSON. Admin reveal is explicit.
4. In Android, enter URL + code. The app already holds its own request and local
   recovery credential in encrypted storage before its first network request.
5. Server atomically binds the code to that exact installation/request and
   recovery-credential commitment. Different recipient/request cannot reuse it.
6. Coordinator performs journaled setup under the existing controller/root
   boundaries. Android sees brief progress or the exact blocked prerequisite.
7. Server sends the existing recipient-encrypted envelope. Android stores it
   atomically, then returns the authenticated stored ACK. Server finalizes and
   returns the authenticated final receipt. Only this completes setup.
8. Android explains the remaining OS steps: VPN consent, wireless-debugging
   authorization, and secure ADB pairing code/port using the existing server
   pairing flow. Never pretend app install grants these permissions.

## Durable retries

- Generate the app's random recovery credential before the first network call,
  store it encrypted with exact URL/request, and send it only in HTTPS bodies.
  Server stores only its hash. No code persistence is needed.
- A lost redeem reply is retried with the same code and exact request. A bound
  session can be recovered with the original request + recovery credential after
  the code expires. Never allocate twice or regenerate material on retry.
- All session access binds device/transaction/full recipient-request hash and
  recovery credential. ACK/final additionally use the existing cryptographic
  delivery protocol, not the recovery credential as proof of Android storage.
- Existing enrollment journal/barrier remains authoritative. The setup-session
  ledger adds code/request binding, not a second peer writer. Persist intents
  before effects. Original admin owner/transaction stays fixed. Expiry revokes
  unused codes; it never silently deletes a pending peer/profile or steals work.
- One writer for code/session ledger; bounded size/TTL/attempts, rate-limited
  unauthenticated endpoints, uniform wrong/expired/used-code responses. Read-only
  progress may reveal only a bound session's public status. No global device list.

## HTTP seam (to freeze with Android before code)

Normal dashboard authorization is required to issue/revoke a setup code.
Public Android endpoints accept bounded JSON over verified HTTPS only:

- `POST /onboard/v1/claim`: `{code, request_b64, client_auth}`. Return the
  same transaction context/progress on exact retry. Hash auth server-side.
- `POST /onboard/v1/resume`: `{request_sha256, client_auth}`. Return public
  progress, or exact committed encrypted envelope. Never plaintext profile.
- `POST /onboard/v1/ack`: `{request_sha256, client_auth, ack_b64}`. Verify delivery
  ACK, persist/finalize durably, return exact final receipt on retry.

No credentials in query strings, redirects, access logs or error messages.
No HTTP fallback or accepting all certificates. HTTPS trust remains Android's
normal verified TLS; redirect to another origin is refused. Admin may use the
existing loopback private HTTP service behind its authenticated HTTPS tunnel.

## Implementation order

1. Finish reviewed read-only preview. Shared public firewall prerequisite is
   missing until the separate authenticated broker is implemented and installed.
2. Review exact setup-session state/HTTP contract with Android storage owner;
   implement RED/GREEN tests for code reuse, expiry, lost replies, credential
   mismatch, crash uncertainty, rate limits and envelope replay.
3. Wire existing journal phases to sole NetworkController + authenticated broker
   + exact owned listener. Add no raw WireGuard/firewall write path.
4. Add minimal Android URL/code flow to accepted UI; existing encrypted storage
   supplies request/resume/ACK/final. No unrelated visual redesign.
5. Upgrade owned Blackwall readb only after exact artifact and rollback evidence.
   Smoke with a fresh bounded test device under owner coordination. Preserve old
   Pixel/Quest services and pairing until real replacement acceptance.

## Gates still open

Authenticated firewall broker; full effect orchestration; durable setup-session
ledger/HTTP routes; Android bootstrap transport; real Blackwall/device acceptance.
A pure codec, successful preview, local build or host output receipt closes none.

## Frozen wire response

JSON schema1. Binary values use canonical padded standard Base64; hashes and
`client_auth` use 64 lowercase hex characters. `request_sha256` hashes the decoded
exact request bytes. The 16hex setup code can be entered as four groups of four
with hyphens; no secret goes in an HTTP query, redirect or diagnostic.

Each successful bound response includes all of:

```json
{"schema":1,"code":"setup_pending","phase":"bound","request_sha256":"64hex","context_b64":null,"envelope_b64":null,"final_b64":null,"retry_after_ms":1000,"message":"Preparing device."}
```

- `context_b64` becomes the exact codec Context bytes when committed. Once set,
  it never changes for that request. Device/transaction identity is in Context.
- `envelope_b64` appears only once durably committed. Return exact ciphertext on
  retries. `code=setup_envelope`, `retry_after_ms=0` asks Android to store and ACK.
- `final_b64` appears only after durable server finalization and is replayed
  exactly; `code=setup_complete`, `phase=complete`, `retry_after_ms=0`.
- Phase names: `bound`, `prepared`, `catalog_added`, `controller_held`,
  `peer_applied`, `report_ready`, `listener_ready`, `recipient_bound`,
  `envelope_committed`, `android_stored`, `complete`. Blocking preserves the last
  committed phase. `code=setup_blocked` adds a secret-free `blocker` and brief
  actionable message, never falsely claims completion.
- HTTP200 means a valid session response, not readiness. Pending uses the above
  retry delay; clients poll with bounded backoff and a visible Cancel control.
  Cancel stops client polling; future admin cancel may revoke unused invitations
  or retain an exact pending transaction for explicit recovery, never delete peers.
- Invalid/expired/wrong-recipient/consumed-code or wrong-auth returns HTTP403
  `{schema:1,code:"invalid_setup",message:"Code or setup session is not valid."}`.
  No account/device existence leaks. Malformed bounded JSON returns400
  `invalid_request`; unsupported method/path returns404.
- Rate limit returns429 `setup_rate_limited` plus `retry_after_ms` and HTTP
  `Retry-After` seconds. Upstream/prerequisite/uncertain-operation blockers return
  503 `setup_blocked` with a secret-free blocker code and same retry convention.
  No setup code is issued while the authenticated report broker is unavailable.
- Code TTL10min, 64bits of random code; at most five invalid attempts/60s per
  bounded actual socket peer plus global budget. Do not trust forwarded IP headers
  automatically. Exact same authenticated claim retries do not spend attempts.

## Source checkpoint — 2026-10-19

Invitation storage now exists in `onboarding_store`: mode600 private atomic
ledger, descriptor/inode binding, one writer, ambiguous-sync handle poisoning,
exact recipient/request and hashed recovery credential. It saves no raw code or
client credential. Same claim/resume survives lost replies and reopen. Expired
unused codes and wrong recipients/auth share one denial. Exact authenticated
retries preserve their session even after wrong-attempt limits. Only unused
original-owner invitations can be revoked; bound work stays pending.

32 library checks +6 invitation checks +2 cross-language delivery checks passed;
all-target Clippy, formatting and diff checks passed. A real exhausted-budget
first-bind bypass failed before its fix. HTTP routes/effect orchestration and
actual broker/device acceptance are still separate pending work. This does not
make setup usable yet or permit a live cutover.
