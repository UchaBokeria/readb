#!/usr/bin/env python3
"""Build a development companion APK. No device changes or release signing."""
import argparse
from native_check import validate as validate_native
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--handover-checks', action='store_true', help='Include synthetic encrypted migration instrumentation; never for release')
p.add_argument('--handover-trust', type=Path, help='Explicit public package=SHA256 certificate pins; enables client migration only')
p.add_argument('--storage-checks', action='store_true', help='Include isolated development instrumentation; never for release')
p.add_argument('--ui-checks', action='store_true', help='Include own-window development capture; never for release')
p.add_argument('--sdk', type=Path, required=True)
p.add_argument('--native-lib', type=Path, required=True, help='arm64 libreadb_android_core.so')
p.add_argument('--build-dir', type=Path, default=REPO / 'build/android')
a = p.parse_args()
os.umask(0o077)
out = a.build_dir.resolve()
out.mkdir(parents=True, exist_ok=True)
tools = a.sdk.resolve() / 'build-tools/36.0.0'
jar = a.sdk.resolve() / 'platforms/android-36/android.jar'
if not jar.is_file() or not a.native_lib.is_file():
    p.error('SDK36 platform or native arm64 library missing')
validate_native(a.native_lib.read_bytes())
DEPENDENCIES = {
 'tunnel.aar': ('https://repo.maven.apache.org/maven2/com/wireguard/android/tunnel/1.0.20260102/tunnel-1.0.20260102.aar', '2b9c16db026496123e4db695d26d03d1958a201096c7c4c89b21077dc70f3119'),
 'collection.jar': ('https://dl.google.com/dl/android/maven2/androidx/collection/collection-jvm/1.5.0/collection-jvm-1.5.0.jar', '70b35924e4babcdffa37d0e575ee039c56a2d97123342624c48b603233704341'),
 'annotation.jar': ('https://dl.google.com/dl/android/maven2/androidx/annotation/annotation-jvm/1.9.1/annotation-jvm-1.9.1.jar', '1e343917ebf27ba96fe4dc52b1cad7fd32b738fbc6355bb6cd5b3b305d7212d0'),
 'kotlin.jar': ('https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.9.24/kotlin-stdlib-1.9.24.jar', '858b902696da9cf585ab9d98ffc1c2712269828354dfe9107e3711b084a36468'),
 'jetbrains.jar': ('https://repo.maven.apache.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.jar', 'ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478'),
}
def run(*args):
    subprocess.run([str(x) for x in args], check=True)
deps = out / 'dependencies'
deps.mkdir(exist_ok=True)
for name, (url, digest) in DEPENDENCIES.items():
    target = deps / name
    if not target.exists():
        data = urllib.request.urlopen(url, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit('Dependency checksum mismatch: ' + name)
        target.write_bytes(data)
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise SystemExit('Cached dependency checksum mismatch: ' + name)
with zipfile.ZipFile(deps / 'tunnel.aar') as z:
    (deps / 'tunnel.jar').write_bytes(z.read('classes.jar'))
    (deps / 'libwg-go.so').write_bytes(z.read('jni/arm64-v8a/libwg-go.so'))
validate_native((deps / 'libwg-go.so').read_bytes())
run(tools / 'aapt2', 'compile', '--dir', ROOT / 'res', '-o', out / 'resources.zip')
manifest = ROOT / 'AndroidManifest.xml'
if a.storage_checks or a.ui_checks or a.handover_checks:
    ns = 'http://schemas.android.com/apk/res/android'
    ET.register_namespace('android', ns)
    tree = ET.parse(manifest)
    for enabled, name in [(a.storage_checks, '.StorageChecks'), (a.ui_checks, '.UiChecks'), (a.handover_checks, '.HandoverChecks')]:
        if enabled:
            ET.SubElement(tree.getroot(), 'instrumentation', {f'{{{ns}}}name': name, f'{{{ns}}}targetPackage': 'dev.readb.companion'})
    manifest = out / 'test-manifest.xml'
    tree.write(manifest, encoding='utf-8', xml_declaration=True)
run(tools / 'aapt2', 'link', '-o', out / 'base.apk', '-I', jar, '--manifest', manifest, out / 'resources.zip')
classes = out / 'classes'
classes.mkdir(exist_ok=True)
for stale in classes.rglob('*.class'):
    stale.unlink()
jars = [deps / 'tunnel.jar', *[deps / name for name in DEPENDENCIES if name.endswith('.jar')]]
sources = sorted((ROOT / 'src').rglob('*.java'))
for enabled, name in [(a.storage_checks, 'StorageChecks'), (a.ui_checks, 'UiChecks'), (a.handover_checks, 'HandoverChecks')]:
    if enabled:
        sources.append(ROOT / ('tests/dev/readb/companion/' + name + '.java'))
run('javac', '-source', '11', '-target', '11', '-classpath', os.pathsep.join(str(x) for x in [jar, *jars]), '-d', classes, *sources)
run(tools / 'd8', '--lib', jar, '--min-api', '33', '--output', out, *sorted(classes.rglob('*.class')), *jars)
with zipfile.ZipFile(out / 'base.apk', 'a') as z:
    z.write(out / 'classes.dex', 'classes.dex')
    z.write(a.native_lib, 'lib/arm64-v8a/libreadb_android_core.so', compress_type=zipfile.ZIP_STORED)
    z.write(deps / 'libwg-go.so', 'lib/arm64-v8a/libwg-go.so', compress_type=zipfile.ZIP_STORED)
    for asset in sorted((ROOT / 'assets').rglob('*')):
        if asset.is_file():
            if asset.name == 'style.css':
                z.writestr('assets/companion/style.css', (REPO / 'web/style.css').read_text() + '\n' + asset.read_text())
            else:
                z.write(asset, 'assets/' + str(asset.relative_to(ROOT / 'assets')))
    if a.handover_trust:
        pins = a.handover_trust.read_bytes()
        if len(pins) > 4096:
            p.error('handover trust file too large')
        z.writestr('assets/handover-trust.properties', pins)
    z.write(REPO / 'LICENSE', 'assets/licenses/readb-LICENSE')
    z.write(REPO / 'THIRD-PARTY.md', 'assets/licenses/THIRD-PARTY.md')
    for notice in sorted((REPO / 'licenses').rglob('*')):
        if notice.is_file():
            z.write(notice, 'assets/licenses/' + str(notice.relative_to(REPO / 'licenses')))
run(tools / 'zipalign', '-P', '16', '-f', '4', out / 'base.apk', out / 'aligned.apk')
password = out / 'development-password'
key = out / 'development.keystore'
if not key.exists():
    password.write_text(secrets.token_urlsafe(32) + '\n')
    password.chmod(0o600)
    run('keytool', '-genkeypair', '-keystore', key, '-alias', 'readb-development', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '3650', '-storepass:file', password, '-keypass:file', password, '-dname', 'CN=readb development')
run(tools / 'apksigner', 'sign', '--ks', key, '--ks-pass', 'file:' + str(password), '--out', out / 'readb-companion-dev.apk', out / 'aligned.apk')
run(tools / 'apksigner', 'verify', out / 'readb-companion-dev.apk')
run(tools / 'zipalign', '-c', '-P', '16', '4', out / 'readb-companion-dev.apk')
print(out / 'readb-companion-dev.apk')
