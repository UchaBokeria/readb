#!/bin/sh
# Host-only fixture: no device, installed app data or production TLS changes.
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/readb-client-json.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
export READB_HOST_JSON_SOURCES="$test_dir"
python3 - <<'PYTHON'
import hashlib, io, os, pathlib, urllib.request, zipfile
url='https://repo.maven.apache.org/maven2/com/vaadin/external/google/android-json/0.0.20131108.vaadin1/android-json-0.0.20131108.vaadin1-sources.jar'
data=urllib.request.urlopen(url,timeout=30).read(30000)
if hashlib.sha256(data).hexdigest()!='54c781eea645c450cbbc4a5a1b5a474745465452cec1354cb567b781ea6622c3':
 raise SystemExit('host JSON source hash mismatch')
archive=zipfile.ZipFile(io.BytesIO(data));root=pathlib.Path(os.environ['READB_HOST_JSON_SOURCES'])
for name in ['JSONObject','JSONArray','JSONTokener','JSONStringer','JSONException','JSON']:
 path=root/'org/json'/f'{name}.java';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(archive.read(f'org/json/{name}.java'))
PYTHON
: "${CARGO_TARGET_DIR:=$PWD/build/cargo}"
export CARGO_TARGET_DIR
cargo test --locked --test onboarding_client -- --ignored --nocapture
