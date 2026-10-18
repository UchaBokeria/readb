# Enrollment orchestration plan

> Use executing-plans and test-driven-development. Each checkpoint gets review.

**Goal:** a useful `device enroll --dry-run` through the saved coordinator, plus
bounded state rules for the later apply transaction. No live enrollment now.

**Architecture:** the daemon owns preview and future enrollment orchestration.
Public metadata comes from the authenticated root helper. Existing
`NetworkController` remains the only peer-effect authority. The flow model tracks
identity, exact intent and confirmations; it grants no kernel or device access.

**Stack:** Rust1.88, existing serde/sha2/clap/std. No new dependency.
**Spec:** `docs/enrollment.md`; preserved PIN, peers, pairing and owner data.

## Checkpoint1 — read-only preview and typed flow

- [x] `src/enrollment_flow.rs`: public request hash, original-owner/transaction
  identity, typed phases/effects and bounded intent→inspect→confirm rules.
  Unknown/changed fences refuse. Pending intent means inspect, never replay an
  effect. Catalog hash advances only to its recorded successor. No new proof
  authority or second state file.
- [x] Coordinate `report_firewall` capability scope with the firewall owner.
  Before any future peer/profile effect, require an installed authenticated
  capability matching interface/server/managed range and exact report tuple.
  Missing/unsupported/unreachable adapter is a setup blocker, never ready.
- [x] `src/enrollment_preview.rs`: strictly read-only server request handling.
  Inspect registry/marker/journal/facts and listening-port metadata. Use pure
  allocator. No Store::open, directory creation, keygen, jobs, binds, catalog,
  peer or firewall writes. Snapshot/ports are advisory and must be rechecked on
  apply. Return candidate+brief checks; `can_apply=false` and
  `profile_deliverable=false` throughout this checkpoint.
- [x] `src/main.rs`: `--device ID device enroll --name NAME --kind
  phone|quest|android --endpoint HOST:PORT --report-port PORT --dry-run`.
  Require explicit dry-run for now. Use configured SSH/context transport.
  No ticket, credentials, output-file or apply/recover path accepted yet.
- [x] `src/daemon.rs`: one strict preview RPC arm; production uses authenticated
  helper reads. Validate request/scope before touching the helper. Malformed
  requests do not fall through to device execution.
- [x] Tests first: owner/request/transaction mismatch; every pending intent and
  phase ordering; wrong catalog successor; maintenance/root/firewall fences;
  unsupported adapter; held-port conflict; no file/tree changes; strict RPC;
  CLI transport and missing-dry-run rejection. Test mutable prerequisites between
  observations and report changed snapshots without readiness.
- [ ] Focused tests, all-target Clippy/fmt; immutable source review. No deployment.

## Later checkpoints

Typed catalog publication and retained-state recovery; exact internal controller
network operation; journaled firewall intent/receipt and real listener FD handoff;
authenticated recipient binding and exact encrypted envelope replay; Android
stored receipt and typed finalization. Do not open the pending barrier from a
host output acknowledgement. Apply keeps the same allocation/upgrade lock order
and persisted material; lost replies never regenerate credentials or steal jobs.

## Owner review boundary

This work does not activate a peer, install a broker, change a VPN, pair ADB or
claim Android acceptance. Those need reviewed source and the existing device gate.

## Preview result

A successful preview command means the read completed, not that setup can run.
`can_apply` and `profile_deliverable` stay false. `candidate` is public metadata,
not a reservation. Missing authenticated `ufw-v1` capability returns
`report_firewall_setup_required`; no installed broker is claimed. Run help at
`readb device enroll --help`. No `--out`, `--recover` or apply exists in this slice.

The pure flow model is not wired to effects or a second journal. Typed proof
constructors remain private until real adapters authenticate them. Both intent
creation and confirmation check current invalidation fences. Future adapter
work must explicitly admit each recorded own network/catalog successor; it may
not bypass the current snapshot check after an expected mutation.

## Source checkpoint evidence — 2026-10-19

- Missing CLI command first failed both transport/rejection tests; added only the
  dry-run path. New API cannot run apply, import, pairing or private output.
- Fence-after-intent test first demonstrated unwanted confirmation; fresh
  prerequisite admission now preserves the pending intent under that fence.
- 11 scoped library checks and 7 preview/CLI checks passed. Includes actual daemon
  RPC rejection and both selected context/local transport with unchanged trees.
- All-target Clippy with warnings denied and formatting passed. This checkpoint
  is source-only, not installed server or Android acceptance. Independent review
  and combined artifact checks remain the parent's integration gate.
