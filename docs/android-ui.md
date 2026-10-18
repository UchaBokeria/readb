# Android companion UI

The companion is a small device utility. Connection state comes first; setup and
permissions stay one tap away. No marketing page or endless settings scroll.

## Design

Use the dashboard's existing ink-blue tokens: background#121820, surface#1a222d,
raised#222d3a, text#edf2f6, muted#9eacbc, accent#a5c7f6. Android's installed
sans-serif keeps text familiar. Headings22–26px; body15px; help13px.

Compact app bar. One main status surface. Three bottom destinations:
Connection, Setup, Settings. Left-aligned content; maximum640px on phones and
panels. Native status/navigation bars remain visible; Activity owns OS insets.
Buttons48px minimum. Tab bar has safe-area padding. Long diagnostics wrap.

```text
readb                         State

Connection
[private link status + next action]
Tunnel / secure ADB / last report
[Start link]             [Stop]
Details (collapsed)

Connection        Setup        Settings
```

Setup shows the actual ordered process: import encrypted profile, allow
notifications, enable wireless debugging, start the built-in WireGuard tunnel,
pair on the server. No separate WireGuard app is needed. Starting changes the
active Android VPN; say that before the action, not after it.

Permissions use short status rows with clear Open/Allow controls. Settings hold
VPN/app controls and boot/security limitations. Technical information stays
collapsed. Never call a requested tunnel setting a verified server connection.
A missing profile gets Import setup as its primary action; an enrolled device
gets Start private link. Show current service errors without a false healthy state.

## Compatibility

Preserve the Readb command bridge and existing status element IDs. Add
`window.readbNavigate('connection'|'setup'|'settings')` for app-owned UI checks.
UI checks must inspect visible buttons only; hidden tab panels have no bounds.
No network navigation, external fonts or secrets are added. Actual Pixel captures
are required after packaging; source/browser checks alone are not acceptance.

Current connection port is a fresh foreground observation, independent of profile
or report-service state. Show it only for an integer1024–65535 observed within
45seconds with a non-reversed clock and debugging not explicitly disabled.
Otherwise show Not discovered. Wireless debugging explicitly off produces a red
warning on every tab, with a direct Open settings action. Pairing and connection
ports remain clearly distinguished.

## Native Android bounds and endpoint state

Owner correction October18: keep normal system bars and inset content around
status/navigation/cutout/keyboard. Do not use full-screen flags or opt out of
modern Android policy. UiChecks reproduced `ui_system_bar_overlap` before fix.
The native root now applies delivered WindowInsets once; WebView stays inside.

Wireless debugging opens the public development-settings action with Android
Settings' `toggle_adb_wireless` preference-highlight arguments. OEMs can ignore
these arguments; do not claim a specific scroll/highlight without device proof.
This targets wireless debugging, not USB debugging or arbitrary settings fragments.

Foreground NSD observes only this device's advertised TLS connect endpoint;
callbacks are generation/lifecycle guarded and service-loss invalidates pending
resolution. No enrollment/VPN is needed for observation. Ports expire after45s,
clear when debugging is known off or the activity stops, and never come from a
saved report. Unknown settings access stays unknown. The red warning is shown
only when wireless debugging is known off. Observation is not pairing or identity
verification. Host freshness checks: `python scripts/test-android-endpoint.py`.

References: [Android insets](https://developer.android.com/develop/ui/views/layout/insets),
[Settings highlight argument](https://android.googlesource.com/platform/packages/apps/Settings/+/master/src/com/android/settings/SettingsActivity.java),
[wireless preference](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/heads/main/res/xml/development_settings.xml).

## Pixel device evidence October18

All3 tabs passed actual UiChecks including native system-bar bounds; captures
visually reviewed. Real own-device TLS port displayed before enrollment, matching
Android Wireless debugging. Generic developer-preference highlight was ignored
on this Pixel; it is fallback only. New public tile-preferences route uses declared
new/old service identity rather than SDKguess. See android-wireless-settings.md
for app-UID direct-target acceptance gate. No VPN or debug toggle was changed.

## Access review and launcher

First launch shows one app-owned access checklist when the native versioned
`permission_setup_required` flag is true. Android notifications/VPN prompts start
only from Review Android prompts. Finish/X/back records Finish for now; status
polls do not reopen it. Settings can reopen review explicitly. Wireless debugging
opens its settings switch; special secure-settings access is never presented as
an ordinary grantable runtime prompt.

Notifications opens readb's notification settings. App permissions opens readb's
App info, then the user taps Permissions. Stock Android protects the deeper
permissions activity with a signature permission; the app does not bypass it. Allow readb VPN requests readb's own embedded VPN approval,
without requiring a saved profile or starting the tunnel. Both the checklist and
Setup warn that approval may replace the active Android VPN. Android VPN list is
a separate management action; users do not need a separate WireGuard app.

Launcher uses the exact bracket/diagonal header mark as a native adaptive vector,
with its own background and monochrome layer. Both icon and roundIcon reference
that resource. Resource compilation/XML checks and JS no-loop/command smokes pass;
new native permission-flow and visual acceptance still require the packaged app.


## Pixel access acceptance October19

Development APK installed with the retained signing key. Actual first access
checklist, Connection/Setup/Settings/bottom captures passed system-bar bounds,
44px targets and horizontal overflow. Visual captures are private ignored review
artifacts. Notifications opened readb's AppNotificationSettingsActivity; App
permissions opened readb's App info with Permissions visible. Native adaptive
header icon appeared on both Android pages. No privileged permission bypass.

A real cold launch exposed a blank WebView despite the earlier instrumented
capture passing. Early onStart status evaluation raced initial page navigation.
Status evaluation now waits for the local page's onPageFinished callback; two
ordinary cold launches rendered, and dismissal stayed dismissed after relaunch.
Review remains available from Settings. Host permission sequencing checks cover
grant/deny/skip/no-loop paths; independent source review found no important issue.

Profile-free Allow opened Android's readb VPN Connection request. The test chose
Cancel: no VPN approval, peer, tunnel or existing VPN was changed. All runtime
permission groups are discovered from the actual installed dangerous-permission
set; the review revision changes with that set or target SDK. System prompts are
sequential and user-triggered, never a single fictional grant-all dialog.

The Pixel is still unenrolled. Real generated-profile delivery, handshake/report,
paired identity, restart recovery and Quest acceptance remain separate gates.
