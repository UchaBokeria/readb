# Host onboarding JSON fixture

The optional native-client host test compiles unmodified AOSP-derived Android JSON
sources from com.vaadin.external.google:android-json:0.0.20131108.vaadin1.
Primary Maven source: https://repo.maven.apache.org/maven2/com/vaadin/external/google/android-json/0.0.20131108.vaadin1/android-json-0.0.20131108.vaadin1-sources.jar
SHA256: 54c781eea645c450cbbc4a5a1b5a474745465452cec1354cb567b781ea6622c3.
The Maven POM identifies extracted Android SDK org.json sources under Apache2.0;
the sources retain Copyright2010 The Android Open Source Project and their own
license headers. See android-json-LICENSE.txt. This fixture is not included in
Android APKs or production Rust dependencies. It is an older Android-compatible
host parser, not proof of current Android parser/device acceptance.

Run scripts/test-android-onboarding-client.sh. It downloads only this hash-pinned
source jar into a temporary directory, compiles Java --release11 and executes an
explicit ignored Rust test. Real Rust envelopes, Java codec/journal and verified
local TLS exercise client ordering, exact retries, invalid replies and cancel.
Only Android Context/Keystore storage is replaced by a test-only facade around
the real journal with synthetic material and injected persistence failures.
No production TLS override, public test API or device operation is added.

October19 evidence: the explicit fixture passes164 protocol assertions plus19
codec rejection checks. Fractional schema1.5 acceptance and malformed JSON/Base64
diagnostic failures were reproduced before their narrow client fixes. Full
production Java compiles source/target11 against SDK36; fixture Java compiles
--release11. The new Rust test passes scoped Clippy with warnings denied and
rustfmt. The test remains ignored in the ordinary offline workspace suite: the
explicit script supplies its pinned host source fixture. No Android install,
Keystore acceptance or live Blackwall onboarding is proved by this check.
