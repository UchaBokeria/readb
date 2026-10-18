# Device enrollment plan

CLI enrollment transaction is not implemented. Pure private material generation
and credential-checked public helper facts now exist in an isolated source branch.
No device, catalog, peer or firewall change is authorized by this plan alone. Finish managed server upgrade/review before live enrollment. Owner
Android review remains first. Current built-in VPN UI has no profile: pressing
Start correctly asks for enrollment rather than constructing guessed credentials.

## Existing pieces

- `device add --file PRIVATE_JSON`: private DeviceImport, atomic catalog publication.
- Per-device controller jobs, authenticated root `network enroll --id ID --key PUB
  --address PEER`, full-snapshot peer preservation and uncertain-operation fences.
- Isolated local ADB port/home/key namespace per device; secure pair/connect/trust.
- V2 listeners and Android Profile validation; encrypted Android profile import.
- Client contexts use SSH to Blackwall; `client::call(..., false)` collects replies
  privately instead of streaming them to the terminal.

No command generates a complete enrollment profile today. `network status` omits
public server key/address/range. No automatic address/ADB-port allocator, enrollment
transaction, secure profile delivery or readb report firewall phase exists.
The live staging binary is older than the current authenticated network proxy.

## Proposed narrow CLI

```sh
readb --device pixel-readb device enroll --name 'Pixel' --kind phone \
  --endpoint VPN_HOST:PORT --out /absolute/private/profile.json \
  --agent codex --origin pc --session ACTUAL_SESSION --job 'Enroll Pixel' --dry-run
# Same command without --dry-run after source/server review.
# Recover the same pending enrollment with --recover; never generate new secrets.
```

`--out` is on the invoking computer. Existing output, symlinks, unsafe ownership
and unmanaged retained device state refuse. Secrets never appear in stdout,
stderr, argv, history, dashboard JSON or URLs. SSH carries the bounded private
reply; the CLI creates/syncs a mode600 file with no overwrite and prints only ID,
file path and next step. A disconnected client can retrieve the same committed
profile with explicit recovery; no credential regeneration or repeated peer edit.

Dry-run only inspects: no key generation, files, jobs, catalog, bind reservations,
firewall, peers or device work. Candidate availability is rechecked on apply.
Default keepalive/prevent-lock remain requested policy, never proof of OS unlock.

## Small implementation stages

1. Add credential-checked **read-only public** helper enrollment facts: policy
   fingerprint, interface, server public key/address, managed range, exact current
   public peer routes/managed IDs and health/fence. Never private keys or wg dump.
   A candidate preflight proves key/address scope and route availability before
   catalog publication. Endpoint is explicit administrator input; compare port
   with pinned interface facts where available, never infer a public endpoint.
2. Serialize enrollments in the coordinator. Choose first unused policy address
   from catalog + managed/current kernel routes. On this server that is the
   existing configured `.100–.150` range, not legacy `.3`/`.5`. Pick an unused
   unprivileged loopback ADB port distinct from every configured/active listener
   (preserve5037/5038); reserve/recheck at effect time. An external race refuses,
   not adoption. Generate WG keys with bounded official `wg genkey`/`wg pubkey`
   captured privately, and a64hex OS-random report token. Validate the exact
   resulting Android Profile plus DeviceImport before writing intent.
3. Persist one private bounded enrollment journal containing exact generated
   material, owner/job and expected catalog/policy hashes **before** effects.
   Stages: prepared → catalog-added → controller-held → peer-applied →
   report-rule-ready → listener-ready → profile-deliverable. Each stage inspects
   exact before/after state on explicit recovery. Reuse atomic catalog and current
   controller/root network APIs. Do not create a second raw WG writer. If a definite
   address conflict appears after catalog add, leave that pending record idle and
   explain the conflict; never regenerate credentials or silently delete state.
4. Exact listener: V2, path `/v2/DEVICE_ID`, bind only verified server interface IP
   and an available configured report port. Never0.0.0.0/public binding. Shared
   bind ports are allowed only with exact device paths, peer checks and separate
   tokens. Identity starts empty/untrusted. Confirm actual listener health before
   delivering a ready profile; failed binds remain explicit pending acceptance.
5. Report firewall is a separate scoped, journaled root integration. For one device
   allow only **interface + source device/32 + destination server/32 + report TCP
   port**; no wildcard/source range/public report rule. Recheck exact owned rule
   receipt on recovery; preserve every unrelated rule. A server without supported
   firewall integration must report a precise manual gate, not claim ready.
6. Companion profile contains schema1, device_id, server_peer, server_port,
   device_address, token, private_key, server_public_key, endpoint, keep_awake and
   prevent_lock. Server DeviceImport contains id/name/kind/peer/isolated adb_port,
   token/identity-empty/keepalive, plus the exact V2 listener. Only this server/32
   routes through embedded WireGuard. Do not import the legacy phone VPN key or
   change its WireGuard app. Keep legacy phone/Quest peers and old pairing intact.
7. Existing Android SAF plaintext import needs a secure delivery follow-up before
   unattended onboarding: explicit one-time recipient Keystore key/nonce request,
   server wraps the profile with the existing bounded encrypted handover codec,
   then Android decrypts/validates/saves under its UID. Shared storage may carry
   ciphertext only; no plaintext adb extras or public downloads. For initial UI
   review, do not label a private host file alone as completed device enrollment.
8. After explicit user Start/VPN consent, verify actual handshake + authenticated
   V2 report. Claim new controller and pair a **new isolated** ADB key with the
   normal six-digit code/port; connect and review/pin identity. Never auto-trust.
   Preserve old pairing as rollback. Dynamic `device add` rejects preexisting
   device directories, so do not preseed a legacy adbkey before add or restart all
   devices merely to import a key. Old-service removal waits for separate device
   boot/port-rotation/rollback acceptance.

## Evidence and small tests

Read-only Blackwall check, October18: legacy5037/5038 and19191/19192 listening.
UFW permits reports19191 only from `.3`,19192 only from `.5`. No managed-device
report rule exists. Therefore a new VPN handshake alone cannot prove reports work.
Recheck free candidate ports and rules at apply time; these facts drift.

Before implementation: tests for invalid/private output paths, deterministic
candidate conflicts/exhaustion, public-policy drift/fence, wrong endpoint/key,
profile/import consistency, keygen timeout/failure, no-secret diagnostic output,
wrong controller, interrupted each journal stage and lost profile reply. Repeated
recovery must reuse bytes and never replace external peers, listeners or files.
Then isolated fake-kernel/service fixtures; only after review, one real new Pixel
peer, report, pairing, identity, stop/start and rollback. No live enrollment yet.

Source coordination: DeviceCmd Enroll is reserved for this slice after review;
SetupCmd/upgrade remains the upgrade agent's ownership. Public helper facts can
extend network_runtime without changing protected setup/provider receipts. Any
Rust change invalidates the final upgrade binary test/freeze and needs a new
reviewed full build before production activation.

## Reviewed admission constraints

A durable per-device barrier is loaded before registry publication, report
listeners, owned ADB servers and keepalive. Ordinary controllers, viewers, input,
policy changes, network calls and transport work refuse the pending ID. Only the
exact internal enrollment ticket/owner/transaction may perform its typed network
phase. Existing devices continue. Runtime caches retain the barrier after missing
or changed records; disk loss never reopens admission. Status remains diagnostic.

A global enrollment lock covers address/report-listener/physical ADB-port
allocation; persisted reservations survive dropped clients. Internal ticket recovery
first inspects busy state, expiry, active operations and cleanup fences. It may
claim anew only for the exact saved owner after safe expiry and no busy/unknown
state. It never cancels another job, clears an intent or regenerates secrets.
Expected catalog hashes advance only for this recorded catalog mutation. Other
legitimate catalog edits cause an actionable strict refusal unless a specific
compatible transition is independently verified; no silent checksum rebasing.

Server preparation and full device acceptance are distinct. Hold the new-device
barrier through preparation and private profile delivery acknowledgement. After
the private output is fsynced, an explicit client acknowledgement may finalize the
server enrollment and reopen normal pairing; first identity is still untrusted,
and the phone has not been granted OS consent or boot acceptance. A lost output or
ack resumes the same server material/request; an existing different output refuses.
Do not mark a profile generated/deliverable when the listener/firewall phase is
still blocked. Full device/VPN/report/paired-identity acceptance remains separate.

## Isolated implementation checkpoint

Branch `feat/enrollment`, trusted worktree `~/.cache/readb-enrollment-d62c264`,
base d62c264. Clean native baseline287 passed. `/tmp` placement failed the
existing protected-home ancestry fixture; the worktree was moved under the owned
cache, not by weakening that check. The original checkout/upgrade candidate is
unchanged. First source slice: pure route/catalog/pending-reservation allocator,
bounded official WG key generation (private stdin), consistent AndroidProfile and
DeviceImport, initial untrusted identity, bounded private material and non-secret
summary. Material deliberately implements neither Debug nor Serialize; compile-
fail doctests verify both. Public enrollment facts use real socket credentials
at the root helper and refuse unhealthy/fenced/drifted state before writes.
The root-only provider-baseline API remains unchanged. No live enrollment.

Generation integration tests require the host's root-owned wireguard-tools binary;
those tests create only ephemeral non-enrolled key material, not files or peers.
The ordinary CLI still has no enroll command. Durable admission/journal/physical
port reservations, delivery acknowledgement, secure Android delivery and exact
report firewall readiness remain required before a profile becomes deliverable.
