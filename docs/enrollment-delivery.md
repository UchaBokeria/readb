# Enrollment delivery codec plan

Pure source slice, based on e38521c. No bridge, profile storage, CLI, listener,
firewall, enrollment finalization or device acceptance is implemented here.

## Trust and scope

Standard first-user setup uses a verified HTTPS server URL and short-lived one-use
setup code issued by the administrator. Before network, Android durably retains
its exact recipient request and random private resume credential; the server
binds that request to the invitation and checks the resume credential. No setup
file or ADB bridge is required for this path. Never put secrets in URLs, shared
storage, argv, extras, logs or dashboard status responses. Encryption alone does
not authenticate the sender or recipient; verified TLS and session binding remain
required. Never expose a general decryptor.

A pinned ADB migration bridge is an advanced deferred adapter. If implemented,
it must check actual Binder shell/root UID on every transaction and verify the
installed certificate/component, transporting only public requests, ciphertext
and authenticated receipts. It is not the default onboarding requirement.

Only the original enrollment owner may bind a receive request. Delivery starts
after exact peer/firewall/listener readiness. Keep the pending-device barrier
until durable Android profile+receipt storage, verified ACK and typed server
finalization. Android Start remains disabled until a final server receipt. The
codec only verifies receipts: it does not assert storage or change any gate.

## Wire contract

All integers are unsigned big-endian32. Lengths are checked before allocation,
all trailing bytes reject. Hashes are SHA256. IDs use existing device-ID rules.
Context is server binding32bytes, transaction32bytes and length-prefixed device
ID. Server/transaction inputs are canonical lowercase64hex. The request contains
magic RER1, installation32bytes, nonce32bytes and DER SPKI RSA public key blob
(maximum1024bytes); permit only3072/4096bits and exponent65537. Maximum request2048.

Envelope REE1 contains request hash, context hash, receipt-secret hash, wrapped-key
blob, IV12bytes and ciphertext blob. AES256-GCM tag128; RSA-OAEP SHA256 with
MGF1-SHA1 and empty label, matching explicit Android parameters. AAD is the exact
domain `readb-enrollment-delivery-v1` plus NUL, context bytes, request hash and
receipt-secret hash. Plaintext REP1 is random receipt secret32bytes plus a bounded
profile blob (maximum8192). Maximum envelope12288. A fresh seal chooses fresh AES
key/IV/receipt secret; callers must persist and retry the same sealed record.

ACK REA1 and final REF1 contain request/context/envelope hashes and HMAC-SHA256
under the encrypted receipt secret over a separate receipt domain plus exact
magic/hashes. ACK cannot be used as final. Comparing a ciphertext hash alone
never authorizes finalization. Exact repeats verify; wrong context/replay reject.
Single-use/restart policy belongs to the durable enrollment journal, not a
stateless codec. Private RES1 recovery bytes retain request, context, receipt
secret and exact envelope; check commitment/context on restore, never reseal.

## Implementation plan

- [x] RED Rust API and Java host fixture tests for contextual round trip, ACK/final
  separation, tamper/bounds/trailing/key rejection and exact recovery bytes.
- [x] Add `src/enrollment_delivery.rs`: opaque non-Debug/non-Serialize Prepared,
  public-key seal only, bounded private restore, ACK verification/final receipt.
- [x] Add pure `android/src/dev/readb/handover/EnrollmentDelivery.java`: request,
  matching codec, private opened payload, ACK and final verification. Leave
  HandoverProtocol and every Android runtime/storage entry point unchanged.
- [x] Exercise Rust envelope -> Java decryption/ACK -> Rust final -> Java verify,
  including all negative cases, using generated synthetic keys/material only.
- [x] Run full native tests, fmt/Clippy, actual Rust1.88 native/musl checks and
  existing Android host checks; hand immutable source to another reviewer.

## Dependencies

Exact pins: rsa0.9.10 (public encryption only), aes-gcm0.11.1, hmac0.13.0,
zeroize1.9.0, rand_core0.6.4 with OS RNG; sha2_oaep alias0.10.9 and sha1_oaep
alias0.10.6 satisfy RSA's digest0.10 interface. Existing sha2=0.11.1 remains for
context/HMAC hashes. Enable SHA2/HMAC/AES-GCM zeroization; disable AES-GCM's
unneeded default RNG feature and use the explicit OS RNG. No JVM requirement on
the production server, shell crypto,
custom cryptographic primitive, private RSA decryption or private RSA signing.

Primary crate metadata gives rsa MSRV1.65 and AES-GCM/HMAC/zeroize1.85. All
resolved transitive dependencies must actually compile/test on Rust1.88, including
musl; metadata is not that proof. RUSTSEC-2023-0071 remains reported for rsa0.9.10:
its private-key timing exposure is excluded by the public-encryption-only API.
Do not claim an advisory-free dependency graph or add private RSA operations.

Sources: [RSA metadata](https://crates.io/api/v1/crates/rsa/0.9.10),
[AES-GCM metadata](https://crates.io/api/v1/crates/aes-gcm/0.11.1),
[HMAC metadata](https://crates.io/api/v1/crates/hmac/0.13.0),
[RSA advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).

## Later acceptance

Require request substitution/wrong UID/certificate tests, atomic Android
profile+receipt data fsync/readback/directory fsync, crash/lost-ACK/final-reply
recovery, original-owner/barrier finalization, existing profile preservation and
explicit Start/VPN consent. Legacy Binder-export services remain disabled and
their data untouched. None is proved by these pure host codec tests.

## Source checkpoint

October19: the missing-codec RED test was recorded before implementation. The
crosslanguage host test passes, including public-header rewrites that exercise
GCM AAD rather than just stale-hash rejection. The final locked workspace suite
passes on the host and actual Rust1.88 native (315 tests each, including five
compile-fail doctests); actual Rust1.88 musl passes 310 tests. Cross-target cargo
skips those doctests. Musl emits the existing unsupported Android-core cdylib
warning; it does not prevent the server/test build. All-target Clippy with
warnings denied, fmt/diff checks, JNI smoke, NSD stale-callback checks and legacy
handover host checks pass. Independent review of immutable code d64812a found
no important source issues. Java compiles at source/target11 with SDK36 and
class version55, and also under the stricter host `--release 11` API contract.
This is not Android Keystore or actual device delivery acceptance.

Normal cargo-audit database refresh succeeded at commit
999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b (last update October17). Its sole report
is RUSTSEC-2023-0071 for rsa0.9.10; the private-key timing path is excluded here,
not suppressed. Refreshed THIRD-PARTY.md and locked source notices retain the
dependencies' own licenses under readb's separate noncommercial license.
