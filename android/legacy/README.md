# Pre-readb helper adapters

Optional migration source for the two private predecessor helpers. These are
not new phone agents and are not built into the readb companion.

Canonical protocol/auth/journal classes: `../src/dev/readb/handover/*.java`.
Copy those exact files into a legacy helper's `src/dev/readb/handover/` directory.
Copy its `HandoverService.java` template into its existing package directory.
Quest additionally needs `quest/bench-pin-export.patch` (reads disabled saved PIN;
never enables it). It reuses the existing private VpnProfileStore and BenchPinStore.
Pixel adapter has no VPN/PIN access and does not touch the WireGuard app.

Each legacy manifest needs package visibility for `dev.readb.companion`, plus:

```xml
<service android:name=".HandoverService" android:exported="true" android:enabled="false" />
```

Bundle explicit **public** certificate pins as `assets/handover-trust.properties`:
one `package.name=lowercase_sha256_current_signing_certificate` per participating
package. All expected pins must match installed APK certificates. No missing-pin
fallback, no trust-on-first-use, no use of pairing codes as signing identities.
Default builds omit the asset. Keep the service disabled until acceptance review;
any later component enablement is an explicit migration action, never boot logic.

Sign upgraded legacy APKs with their original key; check installed/build signatures
first. An upgrade can trigger existing package-replaced startup logic: coordinate
VPN/device access before installing. Do not uninstall old apps or erase their
Keystore/data. See `../../docs/android-handover.md` for protocol and device gates.

Source copies outside this repo can drift. Compare every shared Java class to
its canonical file before building. Owner's existing Pixel source is paused under
its Hermes guard; templates do not imply that upgrade has been finished or tested.
