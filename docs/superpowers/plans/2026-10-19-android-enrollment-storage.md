# Android enrollment storage implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Durably receive a new encrypted enrollment without enabling any service before a verified, durable final receipt.

**Architecture:** A pure bounded enrollment journal owns request/context/envelope/profile/final state. An Android adapter encrypts its single record using a new Keystore AES alias and retains a separate Keystore RSA recipient key. ProfileStore.class serializes legacy imports, enrollment and activation. Legacy profile.enc and readb.enrollment.v1 remain unchanged and backward readable.

**Tech Stack:** Java11, Android API33+, existing EnrollmentDelivery codec, Android AtomicFile/Keystore; no dependencies.

**Spec:** docs/enrollment-delivery.md plus parent storage-slice authorization.

## Constraints and API

No UI/provider/Binder/transport, permissions, device operations or service starts. Refuse enrollment if a legacy profile exists, any service is active or enabled, or a different enrollment exists. A request-only record also blocks activation and legacy imports. Corrupt/unreadable/ambiguous new state fails closed; never silently fall back to legacy or regenerate nonces.

New package-private companion EnrollmentStore exposes prepare(contextBytes), accept(contextBytes, request, envelope) -> ACK, finish(contextBytes, request, finalReceipt). prepare pins the exact context and request; duplicate calls return the same bytes. accept validates profile through the existing NativeBridge and WireGuard parser, including device ID matching the context, and persists profile plus envelope in one encrypted record before ACK. Duplicate accept reopens the exact saved envelope with its retained recipient key, compares the profile and reconfirms disk durability before regenerating the same ACK. No receipt secret is serialized or exposed by an added API. finish authenticates the final receipt by reopening that envelope and persists complete state before activation becomes eligible. Duplicates are exact and idempotent; different context/request/envelope/final refuses.

ProfileStore load/enable and boot/start/service checks share the same new-record gate. A finalized new profile is returned by load without changing existing settings; no autoactivation. Existing v1 paths work identically when no new record exists. All Android mutations take ProfileStore.class, including legacy save, enrollment preparation and activation.

## Tasks

- [x] RED pure Java journal tests: exact retries/restart, wrong context/request/envelope/final, existing profile refusal, noACK on write/readback/sync failure or no-space, recovery after committed-but-lost-reply, pending activation refusal and complete-only profile access. Inject storage and keys; synthetic secrets only.
- [x] Implement bounded binary EnrollmentJournal with injectable storage, recipient-key and profile-validator seams, opaque private record and generic errors. One record phases requested/pending/complete; exact retained envelopes and final receipt, no secret accessors. Wipe transient private arrays.
- [x] Implement Android EnrollmentStore with new readb-enrollment-delivery aliases/file, AES256-GCM domain separation, durable AtomicFile data fsync + exact readback + directory fsync. Retain RSA3072 recipient key, never overwrite v1 or delete keys. Public inspection returns readiness only. Optional fixtures may use unique test namespaces only.
- [x] Integrate ProfileStore monitor/gates with boot and report/VPN startup, preserving v1 bytes/aliases and existing owner UI. Host gate tests and source contract checks cover stale enabled flags, direct service requests and legacy-import race boundaries.
- [ ] Verify Java --release11 pure tests and source/target11 SDK compilation; existing host handover/permission/JNI checks and relevant workspace tests. No AndroidKeystore/device durability claim without separately authorized instrumentation. Record immutable checkpoint for independent review before integration.

## Review focus

AtomicFile silent finish failure, post-rename fsync uncertainty, missing versus corrupt record, simultaneous legacy save, process restart after ACK/final, and direct service activation are explicit test cases. AndroidKeystore OAEP/device behavior remains an acceptance gate; host JCE is not proof. Temporary profile JSON strings follow existing validator behavior and must never be logged.

## Approved HTTPS bootstrap amendment

Root and enrollment owner agreed: prepare(HTTPS URL) persists the canonical URL,
recipient request and random256 client_auth atomically before network. The setup
code is never stored. Claim sends code/request/client_auth over verified TLS;
resume sends request hash/client_auth, allowing lost-first-reply recovery. Server
stores only the credential hash and binds the invitation to the exact request.
The package-private native store session exposes client_auth to native HTTPS only,
never WebView/inspection/logging. bind(context) saves the first exact server/device/
transaction context once; conflicting bindings refuse. The same encrypted record
retains bootstrap metadata through ACK/final. No HTTP handler is added here.

## Source checkpoint

October19 source-only: missing-journal and omitted activation gates failed before
implementation. The altered-successful-write regression reproduced an unsafe
request return, then passed with independent journal readback. Cross-language
Rust envelope -> Java journal tests cover initial no-space, unchanged bootstrap
request/auth on retry, committed lost bootstrap/ACK/final replies, read-sync
failure, exact restore/conflict, final-only readiness and generic URL errors.
Activation call-site checks cover load/import and direct VPN/report admission.
All production Java compiled source/target11 against SDK36; pure Java tests use
--release11. No AndroidKeystore, actual disk-full/process-crash or device service
acceptance is implied by injected host failures or compilation. New orphan .new
without a committed record fails closed and requires explicit recovery; it never
silently regenerates a published request. No owner files or aliases were cleared.
