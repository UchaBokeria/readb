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

V2 reports carry a reporter epoch, sequence and optional TLS port. No-port reports
are telemetry, never ADB acceptance. Persist ordering before applying side effects;
port loss or epoch change fences old device work. A device that accepted V2 refuses
legacy wire reports with report_protocol_downgrade, including after server restart.
Manual pinned reconnect remains separate and cannot refresh cached V2 battery
telemetry. Legacy-only devices stay compatible until each staged upgrade.

Android core and server share identifier/report validation. Java service instances
keep enrollment locked during startup/teardown; callbacks use reporter and service
revisions so lost advertisements cannot restore a stale port. Android HTTP runs
outside the serialized state worker. Details and limits: android.md.

Live daemon backends lazily own foreground ADB processes. Parent retains each
loopback socket and passes it through acceptfd:3; child initialization must ACK
on a private fd4 before inventory. USB/emulator discovery is disabled. No
existing listener is adopted; a dead child keeps its port reserved until explicit
quiescent reconnect or stop. Shutdown permanently closes lazy startup before
workers are drained. A failed device startup does not terminate other backends.

Sources: [ADB startup and ACK](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/main.cpp),
[ADB command parsing](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/commandline.cpp).

Configuration persistence failures during device add remain an acceptance blocker:
retained empty .android state can prevent retry; ambiguous post-rename/fsync errors
need a catalog journal. No live cutover until this and setup/device gates pass.
