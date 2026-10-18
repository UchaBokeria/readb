#!/bin/sh
# Local TLS fixture only. No device, production trust store or server changes.
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/readb-http.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
javac --release 11 -d "$test_dir" \
 android/src/dev/readb/companion/OnboardingHttp.java \
 android/tests/host/dev/readb/companion/OnboardingHttpTest.java
keytool -genkeypair -alias local-test -keyalg RSA -keysize 2048 -validity 1 \
 -dname CN=localhost -ext SAN=dns:localhost -storetype PKCS12 \
 -keystore "$test_dir/local.p12" -storepass test-only -keypass test-only \
 -noprompt >"$test_dir/keytool.log" 2>&1
java -cp "$test_dir" dev.readb.companion.OnboardingHttpTest "$test_dir/local.p12"
