# Design

One server owns secure ADB connections. Clients reach it over SSH.
Each device has its own pin, credential, transport generation and jobs.
Viewers share positive-profile read commands. One controller changes a device.
Cancellation and restart preserve unknown-cleanup fences. Never guess success.
Private state stays outside source. Web is opt-in and authenticated.
Android uses embedded WireGuard and normal OS permission flows.
Awake policy is configurable; protected boot unlock may need the owner.

Filesystem arguments to ADB operations are server paths. Tokens are stored on the
invoking CLI host. Screenshot stdout can be redirected on the client. Transfers
that write server files require the controller; observers use binary stdout captures.

ADB TLS uses the primary user key. Each device subprocess gets a private home,
key and log directory. Import the actual paired primary key before migration;
setting ADB_VENDOR_KEYS alone is insufficient. First enrollment stays untrusted
until a controller reviews and pins the observed fingerprint.

References: [ADB authentication](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/auth.cpp),
[ADB paths](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/adb_utils.cpp).
