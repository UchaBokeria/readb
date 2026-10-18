# Open Wireless debugging

Use the documented public `TileService.ACTION_QS_TILE_PREFERENCES` activity action
with a **Parcelable ComponentName** in `Intent.EXTRA_COMPONENT_NAME`, scoped to
`com.android.settings`. Settings owns the final navigation and all consent.
Do not inject private fragment names or reflect hidden APIs.

The tile class changed. Read declared service metadata, including disabled
components, rather than assuming the SDK version:

- New Pixel API37: `com.android.settings.development.qstile.AdbWirelessDebuggingDevelopmentTile`.
- Older AOSP: `com.android.settings.development.qstile.DevelopmentTiles$WirelessDebugging`.

Use `PackageManager.getServiceInfo` with `MATCH_DISABLED_COMPONENTS`; prefer the
new class when present. A Settings package-visibility query may be needed. Do
not enable the tile, toggle debugging or grant permissions just to open its page.
The explicit public intent works without starting the tile service.

October18 Pixel read-only manifest/DEX inspection: the public action resolves to
exported `com.android.settings.qstile.QSTileLongPressGatewayActivity`, priority100.
Its code recognizes the **new** class above, checks Wireless-debugging availability,
and launches its own AdbWirelessDebuggingFragment before finishing. An old tile
class goes to Developer options instead. That explains why a successfully launched
activity was still the wrong page. The DevelopmentSettingsActivity is exported,
but bypassing the gateway with the old action/component still failed owner tests.

The current normal app's internal preference-highlight hints did not highlight
Wireless debugging on this Pixel. Activity launch success alone is not proof of
direct navigation/highlighting. Test from the real app UID, verify actual page and
Back behavior, then retain per-device evidence. No actual app-UID success was
claimed by this research task; root owns those UI tests. OEM/restriction failures
should fall back to public Developer options with clear directions, never a private
SubSettings/fragment bypass. A glow is OS-owned behavior, not guaranteed by the
public settings intent.

Sources: [public action contract](https://developer.android.com/reference/android/service/quicksettings/TileService#ACTION_QS_TILE_PREFERENCES),
[older AOSP router](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/heads/main/src/com/android/settings/development/DevelopmentSettingsDashboardFragment.java).
New Pixel behavior was checked against its actual installed Settings APK, not
inferred from that older AOSP router. Private local artifacts live in ignored
`build/readb-pixel-review/settings-system.apk` and `settings-gateway-code.txt` in
the Quickshard workspace. Do not redistribute the system APK as a readb asset.

23:34+04 shell proof: publicQSaction with actualnewParcelabletilecomponent
opened Wireless debugging directly; screenshotwireless-new.png shows correct
page and connectionport matching foregroundNSD. Oldtile and explicitoldactivity
variants reproducibly remained in general Developer options. App code now
choosesdeclarednew/olddisabledservice usingpublicPackageManager metadata with
onlySettingspackagevisibility, then publicQSaction; generichighlight is fallback.
FreshAPK/install/appbutton+Back acceptance still pending. No debugtoggle changed.

23:40+04 actual app-UID acceptance PASS: updated APK's own Open wireless
debugging button opened exact Wireless debugging page via publicGateway/newtile;
normal Back returned directly to readb. All3 compactUIpages passed nativeinsets,
visible44pxtargets and nohorizontaloverflow. Actual capturedconnectionport
matchedsystemsettings. Private wireless-app-uid.png + compact*.log/png. No
wireless toggle, pairingcode, VPN or profile change. Owner updatedAndroidreview
pending; actualenrollment/WGdemo still waits guardedserverupgrade+generator.
