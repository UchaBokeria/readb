# Release gates

Development only. Passing source tests does not mean a device migrated.
Keep legacy services until the replacement passes device tests and rollback.

| Area | Current proof | Still needed |
|---|---|---|
| CLI, jobs, viewers | Host tests and isolated two-host checks | Real migrated phone and Quest |
| Dashboard | Authenticated empty staging | Real devices and final UI review |
| Linux binary | Native and Rust1.88 musl checks | aarch64 destination checks |
| Server upgrade | Empty-server forward/rollback namespace checks | Combined enrollment guard, rebuilt image, live staging |
| Fresh installation | Existing-interface systemd setup | Dependencies, new interface, supported init paths, clean-machine test |
| Enrollment | Material, journal, owner tickets, barriers, socket and private-output primitives | Typed effect sequence, CLI/dashboard flow |
| Report firewall | Legacy rules preserved | Exact managed device rule and readiness receipt |
| Encrypted delivery | Legacy Binder codec; new delivery design | Enrollment codec, Android durable receipt, finalization |
| Android permissions | Pixel settings targets, consent cancellation and layout checks | Owner review; actual enrolled permission/denial recovery |
| Android private link | Embedded WireGuard source and packaging | New peer, real VPN handshake and authenticated reports |
| Secure ADB | Legacy pinned routes remain live | New isolated pairing, first fingerprint review, rotation/reconnect |
| Keep awake | Policy source and legacy bench service | Migrated-device awake tests; report real lock limits |
| Low battery alerts | Notifier policy and bridge tests | Migrated-device Hermes send/delivery; avoid overlap with legacy alerts |
| Restart recovery | Legacy evidence kept separate | Readb boot, locked boot, Wi-Fi consent, report/port recovery |
| Rollback | Empty-server namespace checks | Per-device credential/profile/VPN rollback |
| Distribution | Development source and APK | Final signing, release assets, installer and dependency notices |
| Cleanup | Legacy paths retained | Remove only accepted, owned replacements |

Details: [status](status.md), [setup](setup.md), [enrollment](enrollment.md),
[Android](android.md). Updates must name the exact source, artifact and device
check. Never turn a build result into a boot or migration claim.
